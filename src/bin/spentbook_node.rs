// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use bytes::Bytes;
use log::{debug, info, trace};
use miette::{IntoDiagnostic, Result};

use blst_ringct::ringct::RingCtTransaction;
use sn_dbc::{
    KeyImage, KeyManager, SimpleKeyManager, SimpleSigner, SpentBookNodeMock, SpentProofShare,
};
use sn_dbc_examples::wire;

use xor_name::XorName;

use qp2p::{self, Config, Endpoint, IncomingConnections};
use structopt::StructOpt;

use bls_dkg::KeyGen;
use rand_core::RngCore;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};

/// Configuration for the program
#[derive(StructOpt)]
pub struct SpentbookNodeConfig {
    /// Peer addresses (other SpentbookNodes)
    peers: Vec<SocketAddr>,

    /// number of SpentbookNode peers that make up a Spentbook
    #[structopt(long, default_value = "3")]
    quorum_size: usize,

    #[structopt(flatten)]
    p2p_qp2p_opts: Config,
}

struct ServerEndpoint {
    endpoint: Endpoint,
    incoming_connections: IncomingConnections,
}

struct SpentbookNodeServer {
    xor_name: XorName,

    config: SpentbookNodeConfig,

    peers: BTreeMap<XorName, SocketAddr>,

    spentbook_node: Option<SpentBookNodeMock>,

    /// for communicating with other mintnodes
    server_endpoint: ServerEndpoint,

    keygen: Option<bls_dkg::KeyGen>,
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

    let config = SpentbookNodeConfig::from_args();

    let (endpoint, incoming_connections, _contact) = Endpoint::new_peer(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &[],
        config.p2p_qp2p_opts.clone(),
    )
    .await
    .into_diagnostic()?;
    let server_endpoint = ServerEndpoint {
        endpoint,
        incoming_connections,
    };

    let my_xor_name = XorName::random();

    println!(
        "Spentbook [{}] listening for messages at: {}",
        my_xor_name,
        server_endpoint.endpoint.public_addr()
    );

    let my_node = SpentbookNodeServer {
        config,
        xor_name: my_xor_name,
        peers: BTreeMap::from_iter([(my_xor_name, server_endpoint.endpoint.public_addr())]),
        spentbook_node: None,
        server_endpoint,
        keygen: None,
    };

    my_node.run().await?;

    Ok(())
}

impl SpentbookNodeServer {
    async fn run(mut self) -> Result<()> {
        {
            for peer in self.config.peers.clone().iter() {
                let msg = wire::spentbook::p2p::Msg::Peer(
                    self.xor_name,
                    self.server_endpoint.endpoint.public_addr(),
                );
                self.send_p2p_network_msg(msg, peer).await?;
            }
        }

        Ok(self.listen_for_network_msgs().await?)
    }

    async fn listen_for_network_msgs(&mut self) -> Result<()> {

        let local_addr = self.server_endpoint.endpoint.local_addr();
        let external_addr = self.server_endpoint.endpoint.public_addr();
        info!(
            "[P2P] listening on local  {:?}, external: {:?}",
            local_addr, external_addr
        );

        while let Some((connection, mut incoming_messages)) =
            self.server_endpoint.incoming_connections.next().await
        {
            let socket_addr = connection.remote_address();

            while let Some(bytes) = incoming_messages.next().await.into_diagnostic()? {
                debug!("[Net] got network message from {}", socket_addr);

                let net_msg: wire::spentbook::Msg =
                    bincode::deserialize(&bytes).into_diagnostic()?;

                debug!("[Net] received from {:?} --> {:?}", socket_addr, net_msg);
                let mut rng = rand::thread_rng();

                match net_msg {
                    wire::spentbook::Msg::P2p(p2p_msg) => {
                        match p2p_msg {
                            wire::spentbook::p2p::Msg::Peer(actor, addr) => {
                                self.handle_peer_msg(actor, addr).await?
                            },
                            wire::spentbook::p2p::Msg::Dkg(msg) => {
                                self.handle_p2p_message(msg, &mut rng).await?
                            },
                        }
                    },
                    wire::spentbook::Msg::Wallet(wallet_msg) => {
                        match wallet_msg {
                            wire::spentbook::wallet::Msg::Request(request_msg) => {
                                let reply_msg = match request_msg {
                                    wire::spentbook::wallet::request::Msg::LogSpent(k, t) => {
                                        wire::spentbook::wallet::reply::Msg::LogSpent(
                                            self.handle_log_spent_request(k, t).await,
                                        )
                                    }
                                    wire::spentbook::wallet::request::Msg::Discover => {
                                        wire::spentbook::wallet::reply::Msg::Discover(
                                            self
                                                .spentbook_node
                                                .as_ref()
                                                .unwrap()
                                                .key_manager
                                                .public_key_set()
                                                .unwrap()
                                                .clone(),
                                            self.peers.clone(),
                                        )
                                    }
                                };

                                let m = wire::spentbook::Msg::Wallet(wire::spentbook::wallet::Msg::Reply(reply_msg));
                                let reply_msg_bytes = Bytes::from(bincode::serialize(&m).unwrap());
                                connection.send(reply_msg_bytes).await.into_diagnostic()?;               
                            },
                            _ => {},   // ignore non-requests.
                        }                        
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_log_spent_request(
        &mut self,
        key_image: KeyImage,
        tx: RingCtTransaction,
    ) -> sn_dbc::Result<SpentProofShare> {
        self.spentbook_node
            .as_mut()
            .unwrap()
            .log_spent(key_image, tx)
    }

    async fn send_p2p_network_msg(
        &self,
        msg: wire::spentbook::p2p::Msg,
        dest_addr: &SocketAddr,
    ) -> Result<()> {
        self.send_network_msg(wire::spentbook::Msg::P2p(msg), dest_addr).await
    }

    async fn send_network_msg(
        &self,
        msg: wire::spentbook::Msg,
        dest_addr: &SocketAddr,
    ) -> Result<()> {
        // if delivering to self, use local addr rather than external to avoid
        // potential hairpinning problems.
        let addr = if *dest_addr == self.server_endpoint.endpoint.public_addr() {
            self.server_endpoint.endpoint.local_addr()
        } else {
            *dest_addr
        };

        debug!("[P2P] Sending message to {:?} --> {:?}", addr, msg);

        // fixme: unwrap
        let msg = bincode::serialize(&msg).unwrap();

        let (connection, _) = self
            .server_endpoint
            .endpoint
            .connect_to(&addr)
            .await
            .into_diagnostic()?;
        // {
        //     error!("[P2P] Failed to connect to {}. {:?}", addr, e);
        //     return;
        // }

        // debug!(
        //     "[P2P] Sending message to {:?} --> {:?}",
        //     addr, msg
        // );

        connection.send(msg.into()).await.into_diagnostic()
        // {
        //     Ok(()) => trace!("[P2P] Sent network msg successfully."),
        //     Err(e) => error!("[P2P] Failed to send network msg: {:?}", e),
        // }
    }

    async fn handle_peer_msg(&mut self, actor: XorName, addr: SocketAddr) -> Result<()> {
        if self.peers.contains_key(&actor) {
            trace!(
                "We already know about peer [{:?}]@{:?}. ignoring.",
                actor,
                addr
            )
        } else {
            // Here we send our peer list back to the new peer.
            for (peer_actor, peer_addr) in self.peers.clone().into_iter() {
                self.send_p2p_network_msg(
                    wire::spentbook::p2p::Msg::Peer(peer_actor, peer_addr),
                    &addr,
                )
                .await?;
            }
            self.peers.insert(actor, addr);

            trace!("Added peer [{:?}]@{:?}", actor, addr);

            if self.peers.len() == self.config.quorum_size {
                info!("initiating dkg with {} nodes", self.peers.len());
                self.initiate_dkg().await?;
            }
        }
        Ok(())
    }

    async fn initiate_dkg(&mut self) -> Result<()> {
        let names: BTreeSet<XorName> = self.peers.keys().cloned().collect();
        let threshold = names.len() - 1;
        println!("dkg threshold: {}", threshold);
        let (keygen, message_and_target) =
            KeyGen::initialize(self.xor_name, threshold, names).unwrap();
        self.broadcast_p2p_messages(message_and_target).await?;

        self.keygen = Some(keygen);

        Ok(())
    }

    async fn handle_p2p_message(
        &mut self,
        message: bls_dkg::message::Message,
        rng: &mut impl RngCore,
    ) -> Result<()> {
        match &mut self.keygen {
            Some(keygen) => {
                if keygen.is_finalized() {
                    debug!("ignoring dkg message because already finalized");
                    return Ok(());
                }
                match keygen.handle_message(rng, message) {
                    Ok(message_and_targets) => {
                        self.broadcast_p2p_messages(message_and_targets).await?
                    }
                    Err(e) => return Err(e).into_diagnostic(),
                }
            }
            None => debug!("received dkg message before initiating dkg"),
        }

        match &mut self.keygen {
            Some(keygen) => {
                if keygen.is_finalized() {
                    let (_, outcome) = keygen.generate_keys().unwrap();
                    println!("outcome threshold: {}", outcome.public_key_set.threshold());
                    self.spentbook_node = Some(SpentBookNodeMock::from(SimpleKeyManager::from(
                        SimpleSigner::from(outcome),
                    )));
                    info!("DKG finalized!");
                    info!("SpentbookNode created!");
                }
                Ok(())
            }
            None => Ok(()), // already logged it above
        }
    }

    async fn broadcast_p2p_messages(
        &self,
        message_and_target: Vec<bls_dkg::key_gen::MessageAndTarget>,
    ) -> Result<()> {
        for (target, message) in message_and_target.into_iter() {
            let target_addr = self.peers.get(&target).unwrap();
            let msg = wire::spentbook::p2p::Msg::Dkg(message);
            self.send_p2p_network_msg(msg, target_addr).await?;
        }
        Ok(())
    }
}

/*
/// Displays mint information in human readable form
fn print_mintinfo_human(mintinfo: &SpentbookInfo) -> Result<()> {
    println!();

    println!("Number of Spentbook Nodes: {}\n", mintinfo.mintnodes.len());

    println!("-- Spentbook Keys --\n");
    println!("SecretKeySet (Poly): {}\n", to_be_hex(&mintinfo.poly)?);

    println!(
        "PublicKeySet: {}\n",
        to_be_hex(&mintinfo.secret_key_set.public_keys())?
    );

    println!(
        "PublicKey: {}\n",
        to_be_hex(&mintinfo.secret_key_set.public_keys().public_key())?
    );

    println!("\n   -- SecretKeyShares --");
    for i in 0..mintinfo.secret_key_set.threshold() + 2 {
        println!(
            "    {}. {}",
            i,
            encode(&sks_to_bytes(&mintinfo.secret_key_set.secret_key_share(i))?)
        );
    }

    let mut secret_key_shares: BTreeMap<usize, SecretKeyShare> = Default::default();

    println!("\n   -- PublicKeyShares --");
    for i in 0..mintinfo.secret_key_set.threshold() + 2 {
        // the 2nd line matches ian coleman's bls tool output.  but why not the first?
        //        println!("  {}. {}", i, to_be_hex::<PublicKeyShare>(&sks.public_keys().public_key_share(i))?);
        println!(
            "    {}. {}",
            i,
            encode(
                &mintinfo
                    .secret_key_set
                    .public_keys()
                    .public_key_share(i)
                    .to_bytes()
            )
        );
        secret_key_shares.insert(i, mintinfo.secret_key_set.secret_key_share(i));
    }

    println!(
        "\n   Required Signers: {}   (Threshold = {})",
        mintinfo.secret_key_set.threshold() + 1,
        mintinfo.secret_key_set.threshold()
    );

    println!("\n-- Genesis DBC --\n");
    print_dbc_human(&mintinfo.genesis, true, None)?;

    for (i, spentbook) in mintinfo.spentbook_nodes.iter().enumerate() {
        println!("\n-- SpentBook Node {} --\n", i);
        for (key_image, _tx) in spentbook.iter() {
            println!("  {}", encode(&key_image.to_bytes()));
        }
    }

    println!();

    Ok(())
}

/// displays a welcome logo/banner for the app.
fn print_logo() {
    println!(
        r#"
 __     _
(_  _._|__  |\ | __|_     _ ._|
__)(_| |(/_ | \|(/_|_\/\/(_)| |<
 ____  ____   ____   __  __ _       _
|  _ \| __ ) / ___| |  \/  (_)_ __ | |_
| | | |  _ \| |     | |\/| | | '_ \| __|
| |_| | |_) | |___  | |  | | | | | | |_
|____/|____/ \____| |_|  |_|_|_| |_|\__|
  "#
    );
}
*/
