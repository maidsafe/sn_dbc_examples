// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub mod spentbook {

    pub mod p2p {

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub enum Msg {
            Peer(xor_name::XorName, std::net::SocketAddr),
            Dkg(bls_dkg::message::Message),
        }
    }

    pub mod wallet {

        use thiserror::Error;

        pub type Result<T, E = Error> = std::result::Result<T, E>;

        #[derive(serde::Serialize, serde::Deserialize, Error, Debug, Clone)]
        pub enum Error {
            #[error("Spentbook not ready")]
            NotReady,

            #[error("Internal error")]
            Internal,

            #[error("Dbc error: {0}")]
            Dbc(#[from] sn_dbc::Error),
        }

        pub mod request {
            #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
            pub enum Msg {
                Discover,
                LogSpent(sn_dbc::KeyImage, sn_dbc::RingCtTransaction),
            }
        }

        pub mod reply {
            #[allow(clippy::large_enum_variant)]
            #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
            pub enum Msg {
                Discover(
                    Option<bls_dkg::PublicKeySet>,
                    std::collections::BTreeMap<xor_name::XorName, std::net::SocketAddr>,
                ),
                LogSpent(super::Result<sn_dbc::SpentProofShare>),
            }
        }

        #[allow(clippy::large_enum_variant)]
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub enum Msg {
            Request(request::Msg),
            Reply(reply::Msg),
        }
    }

    #[allow(clippy::large_enum_variant)]
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum Msg {
        Wallet(wallet::Msg),
        P2p(p2p::Msg),
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Msg {
    Spentbook(spentbook::Msg),
}
