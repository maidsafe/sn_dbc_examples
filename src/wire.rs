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

        pub mod request {
            #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
            pub enum Msg {
                Discover,
                LogSpent(sn_dbc::KeyImage, blst_ringct::ringct::RingCtTransaction),
            }
        }

        pub mod reply {
            #[allow(clippy::large_enum_variant)]
            #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
            pub enum Msg {
                Discover(bls_dkg::PublicKeySet, std::collections::BTreeMap<xor_name::XorName, std::net::SocketAddr>),
                LogSpent(sn_dbc::Result<sn_dbc::SpentProofShare>),
            }
        }

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub enum Msg {
            Request(request::Msg),
            Reply(reply::Msg),
        }
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum Msg {
        Wallet(wallet::Msg),
        P2p(p2p::Msg)
    }
}

pub mod mint {

    pub mod p2p {

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub enum Msg {
            Peer(xor_name::XorName, std::net::SocketAddr),
            Dkg(bls_dkg::message::Message),
        }
        
    }

    pub mod wallet {

        pub mod request {
            #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
            pub enum Msg {
                Discover,
                Reissue(sn_dbc::ReissueRequest),
            }
        }

        pub mod reply {
            #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
            pub enum Msg {
                Discover(bls_dkg::PublicKeySet, std::collections::BTreeMap<xor_name::XorName, std::net::SocketAddr>),
                Reissue(sn_dbc::Result<sn_dbc::ReissueShare>),
            }
        }

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub enum Msg {
            Request(request::Msg),
            Reply(reply::Msg)
        }        
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum Msg {
        Wallet(wallet::Msg),
        P2p(p2p::Msg)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Msg {
    Spentbook(spentbook::Msg),
    Mint(spentbook::Msg),
}
