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
use blsttc::{PublicKey, SecretKey};
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use sn_dbc_examples::wire;
use std::fmt;
use xor_name::XorName;

use blst_ringct::ringct::RingCtTransaction;
use sn_dbc::{
    Dbc, DbcBuilder, GenesisMaterial, KeyImage, ReissueRequest, ReissueRequestBuilder,
    ReissueShare, SpentProofShare, TransactionBuilder,
};

use qp2p::{self, Config, Endpoint};
use structopt::StructOpt;

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};

/// Configuration for the program
#[derive(StructOpt, Default)]
pub struct WalletNodeConfig {
    /// address:port of spentbook node used to query spentbook peers upon startup
    #[structopt(long)]
    join_spentbook: Option<SocketAddr>,

    /// address:port of mint node used to query mint peers upon startup
    #[structopt(long)]
    join_mint: Option<SocketAddr>,

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

type KeyRing = BTreeMap<PublicKey, SecretKey>;

struct DbcInfo {
    dbc: Dbc,
    received: chrono::DateTime<chrono::Utc>,
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

#[derive(Default)]
struct Wallet {
    dbcs: HashMap<[u8; 32], DbcInfo>,
    keys: BTreeMap<PublicKey, SecretKey>,
}

impl Wallet {
    fn unspent(&self) -> BTreeMap<&[u8; 32], &DbcInfo> {
        self.dbcs
            .iter()
            .filter(|(_, d)| d.spent.is_none())
            .collect()
    }

    fn spent(&self) -> BTreeMap<&[u8; 32], &DbcInfo> {
        self.dbcs
            .iter()
            .filter(|(_, d)| d.spent.is_some())
            .collect()
    }

    fn receive(&mut self, dbc: Dbc, notes: Option<String>) -> Result<()> {
        if dbc.is_bearer() {
            self.keys.insert(
                dbc.owner_base().public_key(),
                dbc.owner_base().secret_key().into_diagnostic()?,
            );
        }

        let dbc_hash = dbc.hash();
        let dbc_info = DbcInfo {
            dbc,
            received: chrono::Utc::now(),
            spent: None, // for now we just assume it is unspent.
            notes: notes.unwrap_or("".to_string()),
        };
        self.dbcs.insert(dbc_hash, dbc_info);

        Ok(())
    }
}

struct WalletNodeClient {
    config: WalletNodeConfig,

    wallet: Wallet,

    spentbook_nodes: BTreeMap<XorName, SocketAddr>,
    spentbook_pks: Option<PublicKeySet>,

    mint_nodes: BTreeMap<XorName, SocketAddr>,
    mint_pks: Option<PublicKeySet>,

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
        config,
        wallet: Default::default(),
        spentbook_nodes: Default::default(),
        spentbook_pks: None,
        mint_nodes: Default::default(),
        mint_pks: None,
        wallet_endpoint,
    };

    my_node.run().await?;

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
                        "keys" => self.cli_keys(),
                        "unspent" => self.cli_unspent(),
                        "issue_genesis" => self.cli_issue_genesis().await,
                        // "reissue" => self.cli_reissue(),
                        // "reissue_auto" => self.cli_reissue_auto(),
                        // "validate" => self.cli_validate(),
                        // "newkey" => self.cli_newkey(),
                        // "newkeys" => self.cli_newkeys(),
                        // "decode" => self.cli_decode(),
                        "join" => self.cli_join().await,
                        "quit" | "exit" => break Ok(()),
                        "help" => {
                            println!(
                                "\nCommands:\n  Network: [join]\n  Wallet:  [keys, unspent]\n  Other:   [exit, help]\n  future:  [newkey, newkeys, reissue, reissue_auto, decode, validate]\n"
                            );
                            Ok(())
                        }
                        _ => Err(miette!("Unknown command")),
                    };
                    if let Err(msg) = result {
                        println!("\nError: {:?}\n", msg);
                    }
                }
                Err(ReadlineError::Eof) | Err(ReadlineError::Interrupted) => break Ok(()),
                Err(e) => {
                    println!("Error reading line: {}", e);
                }
            }
        }
    }

    async fn process_config(&mut self) -> Result<()> {
        if let Some(addr) = self.config.join_spentbook {
            self.join_spentbook_section(addr).await?;
        }
        if let Some(addr) = self.config.join_mint {
            self.join_mint_section(addr).await?;
        }

        Ok(())
    }

    async fn cli_issue_genesis(&mut self) -> Result<()> {
        println!("Attempting to issue the Genesis Dbc...");

        // note: rng is necessary for RingCtMaterial::sign().
        let mut rng8 = rand8::thread_rng();

        let genesis_material = GenesisMaterial::default();
        let (genesis_tx, revealed_commitments, _ringct_material, output_owner_map) =
            TransactionBuilder::default()
                .add_input(genesis_material.ringct_material.inputs[0].clone())
                .add_output(
                    genesis_material.ringct_material.outputs[0].clone(),
                    genesis_material.owner_once.clone(),
                )
                .build(&mut rng8)
                .into_diagnostic()?;

        let spent_proof_shares: Vec<SpentProofShare> = self
            .broadcast_log_spent(genesis_material.input_key_image.clone(), genesis_tx.clone())
            .await?;

        let mut rr_builder = ReissueRequestBuilder::new(genesis_tx.clone());
        for share in spent_proof_shares.into_iter() {
            rr_builder = rr_builder.add_spent_proof_share(share);
        }
        let reissue_request = rr_builder.build().into_diagnostic()?;

        // let reissue_request = ReissueRequestBuilder::new(genesis_tx.clone())
        //     .add_spent_proof_shares(spent_proof_shares)
        //     .build().into_diagnostic()?;

        let reissue_shares: Vec<ReissueShare> = self.broadcast_reissue(reissue_request).await?;

        let (genesis_dbc, _owner_once, _amount_secrets) =
            DbcBuilder::new(revealed_commitments, output_owner_map)
                .add_reissue_shares(reissue_shares)
                .build()
                .into_diagnostic()?
                .into_iter()
                .next()
                .unwrap();

        self.wallet
            .receive(genesis_dbc, Some("Genesis Dbc".to_string()))?;

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
        for (_key_image, dinfo) in self.wallet.unspent() {
            let ownership = dinfo.ownership(&self.wallet.keys);
            let amount = match ownership {
                Ownership::Mine => {
                    let sk = self
                        .wallet
                        .keys
                        .get(&dinfo.dbc.owner_base().public_key())
                        .unwrap();
                    let secrets = dinfo.dbc.amount_secrets(&sk).into_diagnostic()?;
                    secrets.amount().to_string()
                }
                Ownership::NotMine => "???".to_string(),
                Ownership::Bearer => dinfo
                    .dbc
                    .amount_secrets_bearer()
                    .into_diagnostic()?
                    .amount()
                    .to_string(),
            };
            let id = encode(dinfo.dbc.hash());
            println!("{} --> amount: {} ({})", id, amount, ownership);
        }
        Ok(())
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
            let reply_msg = self.send_spentbook_network_msg(msg.clone(), &addr).await?;
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

    async fn broadcast_reissue(
        &self,
        reissue_request: ReissueRequest,
    ) -> Result<Vec<ReissueShare>> {
        let msg = wire::mint::wallet::request::Msg::Reissue(reissue_request);

        let mut shares: Vec<ReissueShare> = Default::default();

        for (_xorname, addr) in self.mint_nodes.iter() {
            let reply_msg = self.send_mint_network_msg(msg.clone(), &addr).await?;
            let share = match reply_msg {
                wire::mint::wallet::reply::Msg::Reissue(share_result) => {
                    share_result.into_diagnostic()?
                }
                _ => return Err(miette!("got unexpected reply from mint node")),
            };
            shares.push(share);
        }
        Ok(shares)
    }

    async fn join_mint_section(&mut self, addr: SocketAddr) -> Result<()> {
        let msg = wire::mint::wallet::request::Msg::Discover;
        let reply_msg = self.send_mint_network_msg(msg, &addr).await?;

        match reply_msg {
            wire::mint::wallet::reply::Msg::Discover(mint_pks, mint_nodes) => {
                self.mint_pks = Some(mint_pks);
                self.mint_nodes = mint_nodes;
                println!("got mint peers: {:#?}", self.mint_nodes);
            }
            _ => panic!("unexpected reply"),
        }
        Ok(())
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

        match bincode::deserialize::<wire::spentbook::Msg>(&msg_bytes) {
            Ok(_) => {}
            Err(e) => panic!("failed deserializing our own msg"),
        }

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

    async fn send_mint_network_msg(
        &self,
        msg: wire::mint::wallet::request::Msg,
        dest_addr: &SocketAddr,
    ) -> Result<wire::mint::wallet::reply::Msg> {
        debug!("Sending message to {:?} --> {:#?}", dest_addr, msg);

        let m = wire::mint::Msg::Wallet(wire::mint::wallet::Msg::Request(msg));

        // fixme: unwrap
        let msg_bytes = bincode::serialize(&m).unwrap();

        match bincode::deserialize::<wire::mint::Msg>(&msg_bytes) {
            Ok(_) => {}
            Err(e) => panic!("failed deserializing our own msg"),
        }

        let (connection, mut recv) = self
            .wallet_endpoint
            .connect_to(dest_addr)
            .await
            .into_diagnostic()?;

        connection.send(msg_bytes.into()).await.into_diagnostic()?;
        let recv_bytes = recv.next().await.into_diagnostic()?.unwrap();
        let net_msg: wire::mint::Msg = bincode::deserialize(&recv_bytes).into_diagnostic()?;

        match net_msg {
            wire::mint::Msg::Wallet(wire::mint::wallet::Msg::Reply(m)) => Ok(m),
            _ => Err(miette!("received unexpected msg from mint")),
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

/// Prompts for input and reads the input.
/// Re-prompts in a loop if input is empty.
// fn readline_prompt_nl(prompt: &str) -> Result<String> {
//     loop {
//         println!("{}", prompt);
//         let line = readline()?;
//         if !line.is_empty() {
//             return Ok(line);
//         }
//     }
// }

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

// Hex decode to bytes
// fn decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>> {
//     hex::decode(data).map_err(|e| anyhow!(e))
// }
