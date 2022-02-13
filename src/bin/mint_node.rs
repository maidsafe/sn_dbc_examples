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
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use sn_dbc::{MintNode, ReissueRequest, ReissueShare, SimpleKeyManager, SimpleSigner};

use xor_name::XorName;

use qp2p::{self, Config, Endpoint, IncomingConnections};
use structopt::StructOpt;

use bls_dkg::KeyGen;
use rand_core::RngCore;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};

/// Configuration for the program
#[derive(StructOpt)]
pub struct MintNodeConfig {
    /// Peer addresses (other MintNodes)
    peers: Vec<SocketAddr>,

    /// number of MintNode peers that make up a Mint
    #[structopt(long, default_value = "3")]
    quorum_size: usize,

    #[structopt(flatten)]
    mint_qp2p_opts: Config,
    // we would like to do the following, but not (yet?) supported.
    // filed this: https://github.com/clap-rs/clap/issues/3443
    // #[structopt(flatten, prefix="wallet")]
    // wallet_qp2p_opts: Config,

    // #[structopt(flatten, prefix="mint")]
    // mint_qp2p_opts: Config,
}

struct ServerEndpoint {
    endpoint: Endpoint,
    incoming_connections: IncomingConnections,
}

struct MintNodeServerData {
    xor_name: XorName,

    config: MintNodeConfig,

    peers: BTreeMap<XorName, SocketAddr>,

    mint_node: Option<MintNode<SimpleKeyManager>>,

    /// for communicating with other mintnodes
    mint_endpoint: ServerEndpoint,

    /// for communicating with wallet users
    wallet_endpoint: ServerEndpoint,

    keygen: Option<bls_dkg::KeyGen>,
}

struct MintNodeServer {
    data: Arc<Mutex<MintNodeServerData>>,
}

#[derive(Debug, Serialize, Deserialize)]
enum MintNetworkMsg {
    Peer(XorName, SocketAddr),
    Dkg(bls_dkg::message::Message),
}

#[derive(Debug, Serialize, Deserialize)]
enum WalletNetworkMsg {
    Reissue(ReissueRequest),
}

#[derive(Debug, Serialize, Deserialize)]
enum WalletNetworkMsgReply {
    ReissueReply(sn_dbc::Result<ReissueShare>),
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

    let config = MintNodeConfig::from_args();

    let (endpoint, incoming_connections, _contact) = Endpoint::new_peer(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &[],
        config.mint_qp2p_opts.clone(),
    )
    .await
    .into_diagnostic()?;
    let mint_endpoint = ServerEndpoint {
        endpoint,
        incoming_connections,
    };

    let mut wallet_qp2p_opts = config.mint_qp2p_opts.clone();
    wallet_qp2p_opts.external_port = config.mint_qp2p_opts.external_port.map(|p| p + 1);

    let (endpoint, incoming_connections, _contact) = Endpoint::new_peer(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &[],
        wallet_qp2p_opts,
    )
    .await
    .into_diagnostic()?;
    let wallet_endpoint = ServerEndpoint {
        endpoint,
        incoming_connections,
    };

    let my_xor_name = XorName::random();

    println!(
        "Mint [{}] listening for messages at: {}",
        my_xor_name,
        mint_endpoint.endpoint.public_addr()
    );

    let my_node_data = MintNodeServerData {
        config,
        xor_name: my_xor_name,
        peers: BTreeMap::from_iter([(my_xor_name, mint_endpoint.endpoint.public_addr())]),
        mint_node: None,
        mint_endpoint,
        wallet_endpoint,
        keygen: None,
    };

    let my_node = MintNodeServer {
        data: Arc::new(Mutex::new(my_node_data)),
    };

    my_node.run().await?;

    Ok(())
}

impl MintNodeServer {
    async fn run(self) -> Result<()> {
        {
            let myself = self.data.lock().await;

            for peer in myself.config.peers.clone().iter() {
                let msg = MintNetworkMsg::Peer(
                    myself.xor_name,
                    myself.mint_endpoint.endpoint.public_addr(),
                );
                myself.send_mint_network_msg(&msg, peer).await?;
            }
        }

        tokio::try_join!(
            self.listen_for_mint_network_msgs(),
            self.listen_for_wallet_network_msgs()
        )
        .map(|_| ())
    }

    async fn listen_for_mint_network_msgs(&self) -> Result<()> {
        {
            let myself = self.data.lock().await;

            let local_addr = myself.mint_endpoint.endpoint.local_addr();
            let external_addr = myself.mint_endpoint.endpoint.public_addr();
            info!(
                "[P2P] listening on local  {:?}, external: {:?}",
                local_addr, external_addr
            );
        }

        loop {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let mut myself = self.data.lock().await;

            if let Ok((connection, mut incoming_messages)) =
                myself.mint_endpoint.incoming_connections.try_recv()
            {
                let socket_addr = connection.remote_address();

                while let Some(bytes) = incoming_messages.next().await.into_diagnostic()? {
                    let net_msg: MintNetworkMsg = bincode::deserialize(&bytes).into_diagnostic()?;

                    debug!("[P2P] received from {:?} --> {:?}", socket_addr, net_msg);
                    let mut rng = rand::thread_rng();

                    match net_msg {
                        MintNetworkMsg::Peer(actor, addr) => {
                            myself.handle_peer_msg(actor, addr).await?
                        }
                        MintNetworkMsg::Dkg(msg) => {
                            myself.handle_dkg_message(msg, &mut rng).await?
                        }
                    }
                }
            }
        }
    }

    async fn listen_for_wallet_network_msgs(&self) -> Result<()> {
        {
            let myself = self.data.lock().await;

            let local_addr = myself.wallet_endpoint.endpoint.local_addr();
            let external_addr = myself.wallet_endpoint.endpoint.public_addr();
            info!(
                "[Wallet] listening on local  {:?}, external: {:?}",
                local_addr, external_addr
            );
        }

        loop {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let mut myself = self.data.lock().await;

            if let Ok((connection, mut incoming_messages)) =
                myself.wallet_endpoint.incoming_connections.try_recv()
            {
                let socket_addr = connection.remote_address();

                while let Some(bytes) = incoming_messages.next().await.into_diagnostic()? {
                    let net_msg: WalletNetworkMsg =
                        bincode::deserialize(&bytes).into_diagnostic()?;

                    debug!("[P2P] received from {:?} --> {:?}", socket_addr, net_msg);

                    let reply_msg = match net_msg {
                        WalletNetworkMsg::Reissue(rr) => WalletNetworkMsgReply::ReissueReply(
                            myself.handle_reissue_request(rr).await,
                        ),
                    };

                    let reply_msg_bytes = Bytes::from(bincode::serialize(&reply_msg).unwrap());
                    connection.send(reply_msg_bytes).await.into_diagnostic()?;
                }
            }
        }
    }
}

impl MintNodeServerData {
    async fn handle_reissue_request(&self, rr: ReissueRequest) -> sn_dbc::Result<ReissueShare> {
        self.mint_node.as_ref().unwrap().reissue(rr)
    }

    async fn send_mint_network_msg(
        &self,
        msg: &MintNetworkMsg,
        dest_addr: &SocketAddr,
    ) -> Result<()> {
        // if delivering to self, use local addr rather than external to avoid
        // potential hairpinning problems.
        let addr = if *dest_addr == self.mint_endpoint.endpoint.public_addr() {
            self.mint_endpoint.endpoint.local_addr()
        } else {
            *dest_addr
        };

        debug!("[P2P] Sending message to {:?} --> {:?}", addr, msg);

        // fixme: unwrap
        let msg = bincode::serialize(msg).unwrap();

        let (connection, _) = self
            .mint_endpoint
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
                self.send_mint_network_msg(&MintNetworkMsg::Peer(peer_actor, peer_addr), &addr)
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
        let (keygen, message_and_target) =
            KeyGen::initialize(self.xor_name, names.len() - 1, names).unwrap();
        self.broadcast_dkg_messages(message_and_target).await?;

        self.keygen = Some(keygen);

        Ok(())
    }

    async fn handle_dkg_message(
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
                        self.broadcast_dkg_messages(message_and_targets).await?
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
                    self.mint_node = Some(MintNode::new(SimpleKeyManager::from(
                        SimpleSigner::from(outcome),
                    )));
                    info!("DKG finalized!");
                    info!("MintNode created!");
                }
                Ok(())
            }
            None => Ok(()), // already logged it above
        }
    }

    async fn broadcast_dkg_messages(
        &self,
        message_and_target: Vec<bls_dkg::key_gen::MessageAndTarget>,
    ) -> Result<()> {
        for (target, message) in message_and_target.into_iter() {
            let target_addr = self.peers.get(&target).unwrap();
            let msg = MintNetworkMsg::Dkg(message);
            self.send_mint_network_msg(&msg, target_addr).await?;
        }
        Ok(())
    }
}

/*
/// Displays mint information in human readable form
fn print_mintinfo_human(mintinfo: &MintInfo) -> Result<()> {
    println!();

    println!("Number of Mint Nodes: {}\n", mintinfo.mintnodes.len());

    println!("-- Mint Keys --\n");
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
