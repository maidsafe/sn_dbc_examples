// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use bls_dkg::PublicKeySet;
use serde::{Deserialize, Serialize};
use xor_name::XorName;

use blst_ringct::ringct::RingCtTransaction;
use sn_dbc::{KeyImage, ReissueRequest, ReissueShare, SpentProofShare};

use std::collections::BTreeMap;
use std::net::SocketAddr;

#[derive(Debug, Serialize, Deserialize)]
pub enum SpentbookP2pNetworkMsg {
    Peer(XorName, SocketAddr),
    Dkg(bls_dkg::message::Message),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SpentbookWalletNetworkMsg {
    Discover,
    LogSpent(KeyImage, RingCtTransaction),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum SpentbookWalletNetworkMsgReply {
    DiscoverReply(PublicKeySet, BTreeMap<XorName, SocketAddr>),
    LogSpentReply(sn_dbc::Result<SpentProofShare>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MintP2pNetworkMsg {
    Peer(XorName, SocketAddr),
    Dkg(bls_dkg::message::Message),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MintWalletNetworkMsg {
    Discover,
    Reissue(ReissueRequest),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MintWalletNetworkMsgReply {
    DiscoverReply(PublicKeySet, BTreeMap<XorName, SocketAddr>),
    ReissueReply(sn_dbc::Result<ReissueShare>),
}
