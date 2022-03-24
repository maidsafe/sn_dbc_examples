// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use log::debug;
use miette::{miette, IntoDiagnostic, Result};
// use serde::{Deserialize, Serialize};
use bls_dkg::PublicKeySet;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use serde::{Deserialize, Serialize};
use sn_dbc_examples::wire;
use std::fmt;
use std::path::{Path, PathBuf};
use xor_name::XorName;

use sn_dbc::{
    blsttc::{serde_impl::SerdeSecret, PublicKey, SecretKey, SecretKeySet},
    rng, Amount, AmountSecrets, Dbc, GenesisMaterial, KeyImage, KeyManager, Owner, OwnerOnce,
    RingCtTransaction, SimpleKeyManager, SimpleSigner, SpentProofShare, TransactionBuilder,
};

use qp2p::{self, Config, Endpoint};
use structopt::StructOpt;

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};

#[cfg(unix)]
use std::os::unix::{io::AsRawFd, prelude::RawFd};

#[cfg(unix)]
use termios::{tcsetattr, Termios, ICANON, TCSADRAIN};

/// Configuration for the program
#[derive(StructOpt)]
pub struct WalletNodeConfig {
    /// address:port of spentbook node used to query spentbook peers upon startup
    #[structopt(default_value = "127.0.0.1:1111")]
    join_spentbook: SocketAddr,

    #[structopt(long, parse(from_os_str), default_value = ".wallet.dat")]
    wallet_file: PathBuf,

    #[structopt(flatten)]
    wallet_qp2p_opts: Config,
}

enum Ownership {
    Mine,
    NotMine,
    Bearer,
}
impl fmt::Display for Ownership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Mine => "mine",
            Self::NotMine => "not mine",
            Self::Bearer => "bearer",
        };
        write!(f, "{}", label)
    }
}

type KeyRing = BTreeMap<PublicKey, SerdeSecret<SecretKey>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DbcInfo {
    dbc: Dbc,

    #[serde(with = "chrono::serde::ts_seconds")]
    received: chrono::DateTime<chrono::Utc>,

    #[serde(with = "chrono::serde::ts_seconds_option")]
    spent: Option<chrono::DateTime<chrono::Utc>>,
    notes: String,
}

impl DbcInfo {
    fn ownership(&self, keyset: &KeyRing) -> Ownership {
        if self.dbc.is_bearer() {
            return Ownership::Bearer;
        } else if keyset.contains_key(&self.dbc.owner_base().public_key()) {
            return Ownership::Mine;
        }
        Ownership::NotMine
    }
}

// axes:
//  spent/unspent
//  received/sent        (sent to self would be both sent+received)
//  bearer/owned
//  reissued_by_me/reissued_by_other

//Unspent:
// 1. owned dbcs for which owner matches one of my keys.            (received)
// 2. owned dbcs for which owner does not match one of my keys.     (sent)
// 3. bearer dbcs                                                   (received)

//Spent:
// 1. owned dbcs for which owner matches one of my keys.
// 2. owned dbcs for which owner does not match one of my keys.
// 3. bearer dbcs

#[derive(Default, Serialize, Deserialize)]
struct Wallet {
    dbcs: HashMap<[u8; 32], DbcInfo>,
    keys: BTreeMap<PublicKey, SerdeSecret<SecretKey>>,
}

impl Wallet {
    fn unspent(&self) -> BTreeMap<&[u8; 32], &DbcInfo> {
        self.dbcs
            .iter()
            .filter(|(_, d)| d.spent.is_none())
            .collect()
    }

    fn addkey(&mut self, sk: SecretKey) {
        self.keys.insert(sk.public_key(), SerdeSecret(sk));
    }

    // fn spent(&self) -> BTreeMap<&[u8; 32], &DbcInfo> {
    //     self.dbcs
    //         .iter()
    //         .filter(|(_, d)| d.spent.is_some())
    //         .collect()
    // }

    fn mark_spent(&mut self, dbc_hash: &[u8; 32]) {
        self.dbcs.get_mut(dbc_hash).unwrap().spent = Some(chrono::Utc::now());
    }

    fn add_dbc(&mut self, dbc: Dbc, notes: Option<String>, sent: bool) -> Result<DbcInfo> {
        if dbc.is_bearer() {
            self.addkey(dbc.owner_base().secret_key().into_diagnostic()?);
        }

        let dbc_hash = dbc.hash();
        let dbc_info = DbcInfo {
            dbc,
            received: chrono::Utc::now(),
            spent: if sent { Some(chrono::Utc::now()) } else { None },
            notes: notes.unwrap_or_else(|| "".to_string()),
        };
        self.dbcs.insert(dbc_hash, dbc_info.clone());

        Ok(dbc_info)
    }

    async fn save(&mut self, path: &Path) -> Result<()> {
        use std::io::Write;
        let bytes = bincode::serialize(&self).into_diagnostic()?;

        let mut file = std::fs::File::create(&path).into_diagnostic()?;
        file.write(&bytes).into_diagnostic()?;

        Ok(())
    }

    async fn load(path: &Path) -> Result<Self> {
        use std::io::Read;

        let mut file = std::fs::File::open(&path).into_diagnostic()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).into_diagnostic()?;

        Ok(bincode::deserialize(&bytes).into_diagnostic()?)
    }
}

struct WalletNodeClient {
    config: WalletNodeConfig,

    wallet: Wallet,

    spentbook_nodes: BTreeMap<XorName, SocketAddr>,
    spentbook_pks: Option<PublicKeySet>,

    /// for communicating with others
    wallet_endpoint: Endpoint,
}

#[tokio::main]
async fn main() -> Result<()> {
    let result = do_main().await;
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("{}", e);
            Err(e)
        }
    }
}

async fn do_main() -> Result<()> {
    // Disable TTY ICANON.  So readline() can read more than 4096 bytes.
    // termios_old has the previous settings so we can restore before exit.
    #[cfg(unix)]
    let (tty_fd, termios_old) = unset_tty_icanon()?;

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("qp2p=warn,quinn=warn"),
    )
    //    .format(|buf, record| writeln!(buf, "{}\n", record.args()))
    .init();

    let config = WalletNodeConfig::from_args();

    let wallet_endpoint = Endpoint::new_client(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        config.wallet_qp2p_opts.clone(),
    )
    .into_diagnostic()?;

    let my_node = WalletNodeClient {
        wallet: Wallet::load(&config.wallet_file).await.unwrap_or_default(),
        config,
        spentbook_nodes: Default::default(),
        spentbook_pks: None,
        wallet_endpoint,
    };

    my_node.run().await?;

    // restore original TTY settings.
    #[cfg(unix)]
    tcsetattr(tty_fd, TCSADRAIN, &termios_old).into_diagnostic()?;

    Ok(())
}

impl WalletNodeClient {
    async fn run(mut self) -> Result<()> {
        print_logo();

        self.process_config().await?;

        println!("Type 'help' to get started.\n");

        let mut rl = Editor::<()>::new();
        rl.set_auto_add_history(true);
        loop {
            match rl.readline(">> ") {
                Ok(line) => {
                    let mut args = line.trim().split_whitespace();
                    let cmd = if let Some(cmd) = args.next() {
                        cmd
                    } else {
                        continue;
                    };
                    let result = match cmd {
                        "balance" => self.cli_balance(),
                        "deposit" => self.cli_deposit(),
                        "issue_genesis" => self.cli_issue_genesis().await,
                        "keys" => self.cli_keys(),
                        "reissue" => self.cli_reissue().await,
                        "unspent" => self.cli_unspent(),
                        // "reissue_auto" => self.cli_reissue_auto(),
                        // "validate" => self.cli_validate(),
                        "newkey" => self.cli_newkey(),
                        // "newkeys" => self.cli_newkeys(),
                        // "decode" => self.cli_decode(),
                        "join" => self.cli_join().await,
                        "save" => self.cli_save().await,
                        "quit" | "exit" => break,
                        "help" => {
                            println!(
                                "\nCommands:
  Network: [join]
  Wallet:  [balance, deposit, issue_genesis, keys, newkey, reissue, unspent]
  Other:   [save, exit, help]
  future:  [spent, reissue_manual, reissue_autogen, decode, validate]"
                            );
                            Ok(())
                        }
                        _ => Err(miette!("Unknown command")),
                    };
                    if let Err(msg) = result {
                        println!("\nError: {:?}\n", msg);
                    }
                }
                Err(ReadlineError::Eof) | Err(ReadlineError::Interrupted) => break,
                Err(e) => {
                    println!("Error reading line: {}", e);
                }
            }
            println!();
        }
        self.wallet.save(&self.config.wallet_file).await
    }

    async fn cli_save(&mut self) -> Result<()> {
        self.wallet.save(&self.config.wallet_file).await
    }

    async fn process_config(&mut self) -> Result<()> {
        self.join_spentbook_section(self.config.join_spentbook)
            .await?;
        Ok(())
    }

    fn cli_newkey(&mut self) -> Result<()> {
        let secret_key = crate::SecretKey::random();

        println!(
            "Receive PublicKey: {}",
            encode(&secret_key.public_key().to_bytes())
        );

        self.wallet.addkey(secret_key);
        Ok(())
    }

    fn cli_deposit(&mut self) -> Result<()> {
        let dbc: Dbc = from_le_hex(&readline_prompt_nl("Paste Dbc: ")?)?;
        let notes = readline_prompt("Notes (optional): ")?;
        let n = if notes.is_empty() { None } else { Some(notes) };
        let dinfo = self.wallet.add_dbc(dbc, n, false)?;

        let ownership = dinfo.ownership(&self.wallet.keys);
        match ownership {
            Ownership::Mine => {
                let sk = self
                    .wallet
                    .keys
                    .get(&dinfo.dbc.owner_base().public_key())
                    .unwrap()
                    .inner()
                    .clone();
                let secrets = dinfo.dbc.amount_secrets(&sk).into_diagnostic()?;
                println!("Deposited {}", secrets.amount());
            }
            Ownership::Bearer => {
                let secrets = dinfo.dbc.amount_secrets_bearer().into_diagnostic()?;
                println!("Deposited {}.\n\n  Important!  Anyone can spend this bearer Dbc.\n  It should be reissued to an owned Dbc immediately.", secrets.amount());
            }
            Ownership::NotMine => {
                println!("Added unknown Dbc.  This Dbc is owned by a third party.")
            }
        };
        Ok(())
    }

    fn cli_balance(&mut self) -> Result<()> {
        let balance = self.balance()?;
        println!("Available balance: {}", balance);
        Ok(())
    }

    async fn cli_reissue(&mut self) -> Result<()> {
        let balance = self.balance()?;
        if balance == 0 {
            println!("No funds available for reissue.");
            return Ok(());
        }

        println!("Available balance: {}", balance);

        let spend_amount = loop {
            let amount: Amount = readline_prompt("Amount to spend: ")?
                .parse()
                .into_diagnostic()?;
            if amount <= balance {
                break amount;
            }
            println!(
                "  entered amount exceeds available balance of {}.\n",
                balance
            );
        };

        let owner_base = {
            loop {
                match readline_prompt("[b]earer or [o]wned: ")?.as_str() {
                    "b" => {
                        let secret_key = crate::SecretKey::random();
                        self.wallet.addkey(secret_key.clone());
                        break Owner::from(secret_key);
                    }
                    "o" => {
                        let input = readline_prompt("Recipient's public key: ")?;
                        let mut bytes = [0u8; 48];
                        let d = decode(&input)?;
                        bytes.copy_from_slice(&d);
                        let public_key: PublicKey =
                            PublicKey::from_bytes(bytes).into_diagnostic()?;
                        break Owner::from(public_key);
                    }
                    _ => println!("Invalid selection\n"),
                }
            }
        };
        let mut rng = rng::thread_rng();
        let recip_owner_once = OwnerOnce::from_owner_base(owner_base, &mut rng);

        let unspent = self.unspent()?;
        let mut tx_builder = TransactionBuilder::default();

        let mut inputs_hash: BTreeMap<KeyImage, [u8; 32]> = Default::default();

        for (dinfo, secret_key, _amount_secrets, _id, _ownership) in unspent.iter() {
            inputs_hash.insert(
                dinfo.dbc.key_image(secret_key).into_diagnostic()?,
                dinfo.dbc.hash(),
            );
            tx_builder = tx_builder
                .add_input_dbc(&dinfo.dbc, secret_key, vec![], &mut rng)
                .into_diagnostic()?;

            if tx_builder.inputs_amount_sum() >= spend_amount {
                break;
            }
        }
        tx_builder = tx_builder.add_output_by_amount(spend_amount, recip_owner_once.clone());

        if tx_builder.inputs_amount_sum() > tx_builder.outputs_amount_sum() {
            let change = tx_builder.inputs_amount_sum() - tx_builder.outputs_amount_sum();
            let secret_key = SecretKey::random();
            self.wallet.addkey(secret_key.clone());
            let change_owner_once =
                OwnerOnce::from_owner_base(Owner::from(secret_key.public_key()), &mut rng);

            tx_builder = tx_builder.add_output_by_amount(change, change_owner_once);
        };
        let mut dbc_builder = tx_builder.build(&mut rng).into_diagnostic()?;

        for (key_image, tx) in dbc_builder.inputs() {
            let spent_proof_shares = self.broadcast_log_spent(key_image, tx).await?;
            let dbc_hash = inputs_hash.get(&key_image).unwrap();
            self.wallet.mark_spent(dbc_hash);
            dbc_builder = dbc_builder.add_spent_proof_shares(spent_proof_shares);
        }

        let dbcs = dbc_builder
            .build(&self.gen_key_manager())
            .into_diagnostic()?;

        let mut iter = dbcs.into_iter();
        let (recip_dbc, _owner_once, _amount_secrets) = iter.next().unwrap();
        let recip_dbc_hex = encode(&bincode::serialize(&recip_dbc).into_diagnostic()?);
        let recip_dbc_is_bearer = recip_dbc.is_bearer();
        self.wallet.add_dbc(recip_dbc, None, false)?;

        let (change_dbc, _owner_once, _amount_secrets) = iter.next().unwrap();
        self.wallet
            .add_dbc(change_dbc, Some("change".to_string()), false)?;

        println!("\n-- Begin DBC --\n{}\n-- End Dbc--\n", recip_dbc_hex);

        if recip_dbc_is_bearer {
            println!("note: this DBC is bearer and has been deposited to our wallet");
        } else if self
            .wallet
            .keys
            .contains_key(&recip_owner_once.owner_base.public_key())
        {
            println!("note: this DBC is 'mine' and has been deposited to our wallet");
        } else {
            println!("note: this DBC is owned by a third party");
        }

        println!("note: change DBC deposited to our wallet.");

        Ok(())
    }

    fn gen_key_manager(&self) -> SimpleKeyManager {
        let sks = SecretKeySet::random(0, &mut rng::thread_rng());
        let mut key_manager = SimpleKeyManager::from(SimpleSigner::new(
            sks.public_keys(),
            (0, sks.secret_key_share(0)),
        ));
        let _ignored = key_manager.add_known_key(self.spentbook_pks.as_ref().unwrap().public_key());
        key_manager
    }

    /*
        fn cli_reissue_manual(&mut self) -> Result<()> {

            let balance = self.balance()?;
            if balance == 0 {
                println!("No funds available for reissue.");
                return Ok(());
            }

            println!("Available balance: {}", balance);

            loop {
                let amount = readline_prompt("Amount to spend: ");
                if amount <= balance {
                    break;
                }
                println!("  entered amount exceeds available balance of {}.\n", balance);
            }

            println!("  -- Unspent Dbcs -- ");
            let unspent = self.unspent()?;
            for ((idx, (dinfo, amount, id, ownership)) in unspent.iter().enumerate() {
                println!("{}. {} --> amount: {} ({})", idx, id, amount, ownership);
            }

            println!("\nchoose input ");
        }
    */

    // todo: move into Wallet
    fn balance(&self) -> Result<Amount> {
        Ok(self
            .unspent()?
            .iter()
            .map(|(_, _, amount_secrets, ..)| amount_secrets.amount())
            .sum())
    }

    async fn cli_issue_genesis(&mut self) -> Result<()> {
        println!("Attempting to issue the Genesis Dbc...");

        // note: rng is necessary for RingCtMaterial::sign().
        let mut rng = rng::thread_rng();

        let genesis_material = GenesisMaterial::default();
        let mut dbc_builder = TransactionBuilder::default()
            .add_input(genesis_material.ringct_material.inputs[0].clone())
            .add_output(
                genesis_material.ringct_material.outputs[0].clone(),
                genesis_material.owner_once.clone(),
            )
            .build(&mut rng)
            .into_diagnostic()?;

        for (key_image, tx) in dbc_builder.inputs() {
            let spent_proof_shares = self.broadcast_log_spent(key_image, tx).await?;
            // let dbc_hash = inputs_hash.get(&key_image).unwrap();
            // self.wallet.mark_spent(dbc_hash);
            dbc_builder = dbc_builder.add_spent_proof_shares(spent_proof_shares);
        }

        let (genesis_dbc, _owner_once, _amount_secrets) = dbc_builder
            .build(&self.gen_key_manager())
            .into_diagnostic()?
            .into_iter()
            .next()
            .unwrap();

        self.wallet
            .add_dbc(genesis_dbc, Some("Genesis Dbc".to_string()), false)?;

        Ok(())
    }

    fn cli_keys(&self) -> Result<()> {
        println!("  -- Wallet Keys -- ");
        for (pk, _sk) in self.wallet.keys.iter() {
            println!("  {}", encode(&pk.to_bytes()));
        }
        Ok(())
    }

    fn cli_unspent(&self) -> Result<()> {
        println!("  -- Unspent Dbcs -- ");
        for (dinfo, _secret_key, amount_secrets, id, ownership) in self.unspent()?.iter() {
            println!(
                "{}, rcvd: {}, amount: {} ({})",
                id,
                dinfo.received.to_rfc3339(),
                amount_secrets.amount(),
                ownership
            );
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn unspent(&self) -> Result<Vec<(&DbcInfo, SecretKey, AmountSecrets, String, Ownership)>> {
        let mut unspents: Vec<(&DbcInfo, SecretKey, AmountSecrets, String, Ownership)> =
            Default::default();

        for (_key_image, dinfo) in self.wallet.unspent().into_iter() {
            let ownership = dinfo.ownership(&self.wallet.keys);
            let (secret_key, amount_secrets) = match ownership {
                Ownership::Mine => {
                    let sk = self
                        .wallet
                        .keys
                        .get(&dinfo.dbc.owner_base().public_key())
                        .unwrap()
                        .inner()
                        .clone();
                    let secrets = dinfo.dbc.amount_secrets(&sk).into_diagnostic()?;
                    (sk, secrets)
                }
                Ownership::NotMine => continue,
                Ownership::Bearer => (
                    dinfo.dbc.owner_base().secret_key().into_diagnostic()?,
                    dinfo.dbc.amount_secrets_bearer().into_diagnostic()?,
                ),
            };
            let id = encode(dinfo.dbc.hash());
            unspents.push((dinfo, secret_key, amount_secrets, id, ownership));
        }
        Ok(unspents)
    }

    async fn cli_join(&mut self) -> Result<()> {
        let addr: SocketAddr = readline_prompt("Spentbook peer [ip:port]: ")?
            .parse()
            .into_diagnostic()?;

        self.join_spentbook_section(addr).await
    }

    async fn join_spentbook_section(&mut self, addr: SocketAddr) -> Result<()> {
        let msg = wire::spentbook::wallet::request::Msg::Discover;
        let reply_msg = self.send_spentbook_network_msg(msg, &addr).await?;

        match reply_msg {
            wire::spentbook::wallet::reply::Msg::Discover(spentbook_pks, spentbook_nodes) => {
                self.spentbook_pks = Some(spentbook_pks);
                self.spentbook_nodes = spentbook_nodes;
                println!("got spentbook peers: {:#?}", self.spentbook_nodes);
            }
            _ => panic!("unexpected reply"),
        }
        Ok(())
    }

    async fn broadcast_log_spent(
        &self,
        key_image: KeyImage,
        transaction: RingCtTransaction,
    ) -> Result<Vec<SpentProofShare>> {
        let msg = wire::spentbook::wallet::request::Msg::LogSpent(key_image, transaction);

        let mut shares: Vec<SpentProofShare> = Default::default();

        for (_xorname, addr) in self.spentbook_nodes.iter() {
            let reply_msg = self.send_spentbook_network_msg(msg.clone(), addr).await?;
            let share = match reply_msg {
                wire::spentbook::wallet::reply::Msg::LogSpent(share_result) => {
                    share_result.into_diagnostic()?
                }
                _ => return Err(miette!("got unexpected reply from spentbook node")),
            };
            shares.push(share);
        }
        Ok(shares)
    }

    async fn send_spentbook_network_msg(
        &self,
        msg: wire::spentbook::wallet::request::Msg,
        dest_addr: &SocketAddr,
    ) -> Result<wire::spentbook::wallet::reply::Msg> {
        debug!("Sending message to {:?} --> {:#?}", dest_addr, msg);

        let m = wire::spentbook::Msg::Wallet(wire::spentbook::wallet::Msg::Request(msg));

        // fixme: unwrap
        let msg_bytes = bincode::serialize(&m).unwrap();

        let (connection, mut recv) = self
            .wallet_endpoint
            .connect_to(dest_addr)
            .await
            .into_diagnostic()?;

        connection.send(msg_bytes.into()).await.into_diagnostic()?;
        let recv_bytes = recv.next().await.into_diagnostic()?.unwrap();
        let net_msg: wire::spentbook::Msg = bincode::deserialize(&recv_bytes).into_diagnostic()?;

        match net_msg {
            wire::spentbook::Msg::Wallet(wire::spentbook::wallet::Msg::Reply(m)) => Ok(m),
            _ => Err(miette!("received unexpected msg from spentbook")),
        }
    }
}

/// displays a welcome logo/banner for the app.
// generated by: https://patorjk.com/software/taag/
// "Wallet" font-name:  ANSI Shadow
fn print_logo() {
    println!(
        r#"
    __     _
    (_  _._|__  |\ | __|_     _ ._|
    __)(_| |(/_ | \|(/_|_\/\/(_)| |<

    ██╗    ██╗ █████╗ ██╗     ██╗     ███████╗████████╗
    ██║    ██║██╔══██╗██║     ██║     ██╔════╝╚══██╔══╝
    ██║ █╗ ██║███████║██║     ██║     █████╗     ██║   
    ██║███╗██║██╔══██║██║     ██║     ██╔══╝     ██║   
    ╚███╔███╔╝██║  ██║███████╗███████╗███████╗   ██║   
    ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝

"#
    );
}

/// Prompts for input and reads the input.
/// Re-prompts in a loop if input is empty.
fn readline_prompt(prompt: &str) -> Result<String> {
    use std::io::Write;
    loop {
        print!("{}", prompt);
        std::io::stdout().flush().into_diagnostic()?;
        let line = readline()?;
        if !line.is_empty() {
            return Ok(line);
        }
    }
}

// Prompts for input and reads the input.
// Re-prompts in a loop if input is empty.
fn readline_prompt_nl(prompt: &str) -> Result<String> {
    loop {
        println!("{}", prompt);
        let line = readline()?;
        if !line.is_empty() {
            return Ok(line);
        }
    }
}

// fn readline_prompt_nl_default(prompt: &str, default: &str) -> Result<String> {
//     println!("{}", prompt);
//     let line = readline()?;
//     match line.is_empty() {
//         true => Ok(default.to_string()),
//         false => Ok(line),
//     }
// }

/// Reads stdin to end of line, and strips newline
fn readline() -> Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).into_diagnostic()?; // including '\n'
    Ok(line.trim().to_string())
}

/// Hex encode bytes
fn encode<T: AsRef<[u8]>>(data: T) -> String {
    hex::encode(data)
}

/// Hex decode to bytes
fn decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>> {
    hex::decode(data).into_diagnostic()
}

fn from_le_hex<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T> {
    bincode::deserialize(&decode(s)?).into_diagnostic()
}

// /// Deserialize anything deserializable from big endian bytes
// fn from_be_bytes<T: for<'de> Deserialize<'de>>(b: &[u8]) -> Result<T> {
//     let bb = big_endian_bytes_to_bincode_bytes(b.to_vec());
//     bincode::deserialize(&bb).into_diagnostic()
// }

// /// Deserialize anything deserializable from big endian bytes, hex encoded.
// fn from_be_hex<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T> {
//     from_be_bytes(&decode(s)?)
// }

// /// Serialize anything serializable as big endian bytes
// fn to_be_bytes<T: Serialize>(sk: &T) -> Result<Vec<u8>> {
//     bincode::serialize(&sk)
//         .map(bincode_bytes_to_big_endian_bytes).into_diagnostic()
// }

// /// Serialize anything serializable as big endian bytes, hex encoded.
// fn to_be_hex<T: Serialize>(sk: &T) -> Result<String> {
//     Ok(encode(to_be_bytes(sk)?))
// }

// borrowed from: https://github.com/iancoleman/threshold_crypto_ui/blob/master/src/lib.rs
//
// bincode is little endian encoding, see
// https://docs.rs/bincode/1.3.2/bincode/config/trait.Options.html#options
// but SecretKey.reveal() gives big endian hex
// and all other bls implementations specify bigendian.
// Also see
// https://safenetforum.org/t/simple-web-based-tool-for-bls-keys/32339/37
// so to deserialize a big endian bytes using bincode
// we must convert to little endian bytes
// fn big_endian_bytes_to_bincode_bytes(mut beb: Vec<u8>) -> Vec<u8> {
//     beb.reverse();
//     beb
// }

/// converts from bincode serialized bytes to big endian bytes.
// fn bincode_bytes_to_big_endian_bytes(mut bb: Vec<u8>) -> Vec<u8> {
//     bb.reverse();
//     bb
// }

/// Unsets TTY ICANON.  So readline() can read more than 4096 bytes.
///
/// returns FD of our input TTY and the previous settings
#[cfg(unix)]
fn unset_tty_icanon() -> Result<(RawFd, Termios)> {
    let tty_fd = std::io::stdin().as_raw_fd();
    let termios_old = Termios::from_fd(tty_fd).unwrap();
    let mut termios_new = termios_old;
    termios_new.c_lflag &= !ICANON;
    tcsetattr(tty_fd, TCSADRAIN, &termios_new).into_diagnostic()?;
    Ok((tty_fd, termios_old))
}
