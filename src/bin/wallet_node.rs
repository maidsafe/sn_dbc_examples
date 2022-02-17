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
use sn_dbc_examples::wire;
use std::sync::Arc;
use tokio::sync::Mutex;
use xor_name::XorName;

// use sn_dbc::{
//     ReissueRequest, ReissueShare,
//     TransactionBuilder, ReissueRequestBuilder, DbcBuilder,
//     KeyImage, SpentProofShare};
// use blst_ringct::ringct::RingCtTransaction;

use qp2p::{self, Config, Endpoint};
use structopt::StructOpt;

use std::collections::BTreeMap;
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

struct WalletNodeData {
    config: WalletNodeConfig,

    spentbook_nodes: BTreeMap<XorName, SocketAddr>,
    spentbook_pks: Option<PublicKeySet>,

    mint_nodes: BTreeMap<XorName, SocketAddr>,
    mint_pks: Option<PublicKeySet>,

    /// for communicating with others
    wallet_endpoint: Endpoint,
}

struct WalletNodeClient {
    data: Arc<Mutex<WalletNodeData>>,
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

    let my_node_data = WalletNodeData {
        config,
        spentbook_nodes: Default::default(),
        spentbook_pks: None,
        mint_nodes: Default::default(),
        mint_pks: None,
        wallet_endpoint,
    };

    let my_node = WalletNodeClient {
        data: Arc::new(Mutex::new(my_node_data)),
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
                        // "walletinfo" => self.cli_walletinfo(),
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
                                "\nCommands:\n  [join, exit, help]\n  future: [newkey, newkeys, reissue, reissue_auto, decode, validate]\n"
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
        let mut myself = self.data.lock().await;

        if let Some(addr) = myself.config.join_spentbook {
            myself.join_spentbook_section(addr).await?;
        }
        if let Some(addr) = myself.config.join_mint {
            myself.join_mint_section(addr).await?;
        }

        Ok(())
    }

    async fn cli_join(&mut self) -> Result<()> {
        let mut myself = self.data.lock().await;

        let addr: SocketAddr = readline_prompt("Spentbook peer [ip:port]: ")?
            .parse()
            .into_diagnostic()?;

        myself.join_spentbook_section(addr).await
    }
}

impl WalletNodeData {
    async fn join_spentbook_section(&mut self, addr: SocketAddr) -> Result<()> {
        let msg = wire::SpentbookWalletNetworkMsg::Discover;
        let reply_msg = self.send_spentbook_network_msg(&msg, &addr).await?;

        match reply_msg {
            wire::SpentbookWalletNetworkMsgReply::DiscoverReply(spentbook_pks, spentbook_nodes) => {
                self.spentbook_pks = Some(spentbook_pks);
                self.spentbook_nodes = spentbook_nodes;
                println!("got spentbook peers: {:#?}", self.spentbook_nodes);
            }
            _ => panic!("unexpected reply"),
        }
        Ok(())
    }

    async fn join_mint_section(&mut self, addr: SocketAddr) -> Result<()> {
        let msg = wire::MintWalletNetworkMsg::Discover;
        let reply_msg = self.send_mint_network_msg(&msg, &addr).await?;

        match reply_msg {
            wire::MintWalletNetworkMsgReply::DiscoverReply(mint_pks, mint_nodes) => {
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
        msg: &wire::SpentbookWalletNetworkMsg,
        dest_addr: &SocketAddr,
    ) -> Result<wire::SpentbookWalletNetworkMsgReply> {
        debug!("Sending message to {:?} --> {:?}", dest_addr, msg);

        // fixme: unwrap
        let msg = bincode::serialize(msg).unwrap();

        let (connection, mut recv) = self
            .wallet_endpoint
            .connect_to(dest_addr)
            .await
            .into_diagnostic()?;

        connection.send(msg.into()).await.into_diagnostic()?;
        let bytes = recv.next().await.into_diagnostic()?.unwrap();
        let net_msg: wire::SpentbookWalletNetworkMsgReply =
            bincode::deserialize(&bytes).into_diagnostic()?;

        Ok(net_msg)
    }

    async fn send_mint_network_msg(
        &self,
        msg: &wire::MintWalletNetworkMsg,
        dest_addr: &SocketAddr,
    ) -> Result<wire::MintWalletNetworkMsgReply> {
        debug!("Sending message to {:?} --> {:?}", dest_addr, msg);

        // fixme: unwrap
        let msg = bincode::serialize(msg).unwrap();

        let (connection, mut recv) = self
            .wallet_endpoint
            .connect_to(dest_addr)
            .await
            .into_diagnostic()?;

        connection.send(msg.into()).await.into_diagnostic()?;
        let bytes = recv.next().await.into_diagnostic()?.unwrap();
        let net_msg: wire::MintWalletNetworkMsgReply =
            bincode::deserialize(&bytes).into_diagnostic()?;

        Ok(net_msg)
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
