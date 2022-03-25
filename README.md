# sn_dbc_examples
Safe Network DBCs

|Crate|Documentation|CI|Safe Rust|
|:-:|:-:|:-:|:-:|
|[![](http://meritbadge.herokuapp.com/sn_dbc)](https://crates.io/crates/sn_dbc)|[![Documentation](https://docs.rs/sn_dbc/badge.svg)](https://docs.rs/sn_dbc)|![](https://github.com/maidsafe/sn_dbc/workflows/Master/badge.svg)|[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-error.svg)](https://github.com/rust-secure-code/safety-dance/)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:-:|:-:|:-:|

# About

This crate provides an example spentbook node and an example wallet.  Both are CLI only (no GUI).

The spentbook_node and the wallet are each implemented in a single source file to demonstrate how
simple it is and make it easier to understand.  See the src/bin directory.

With these examples, one can run a distributed Spentbook and use the
included wallet client to:
* issue a Genesis DBC
* reissue any number of other DBCs, either bearer or owned.
* generate new receiving public key(s)
* deposit a DBC into a wallet
* check wallet balance
* list unspent DBCs in wallet

These examples use the sn_dbc and qp2p crates directly.  They do not use or
rely on the Safe Network node or API.  The Safe Network is building a distributed
Spentbook/mint that should implement approximately the same public API as 
sn_dbc::SpentbookNodeMock, but will be very different in implementation details.


Key components are:

- [sn_dbc](https://github.com/maidsafe/sn_dbc/) - Safe Network DBCs
- [blst_ringct](https://github.com/maidsafe/blst_ringct/) - RingCt using bls curve
- [blsttc](https://github.com/maidsafe/blsttc/) - BLS keys
- [qp2p](https://github.com/maidsafe/qp2p/) - Quic protocol P2P library


# Building

## sn_dbc_examples

```
$ git clone https://github.com/maidsafe/sn_dbc_examples.git
$ cd sn_dbc_examples
$ cargo build
```

## ultraman

ultraman makes it easy to start/stop multiple spentbook nodes.

note: ultraman is a rust port of `foreman` from the ruby ecosystem.
It should be possible to use it also, but that is untested

```
$ git clone https://github.com/dan-da/ultraman.git
$ cd ultraman
$ cargo build
$ cargo install --path .
```

# Running

## start the spentbook nodes

This will start 3 spentbook nodes.

```
$ cd sn_dbc_examples
$ RUST_LOG=info ultraman start
```

To stop the nodes, just ctrl-c the ultraman proc.

## start wallet 1

In another shell:

```
$ cd sn_dbc_examples
$ cargo run --bin wallet
```

## start wallet 2,3,4... (optional)

In another shell:

```
$ cd sn_dbc_examples
$ cargo run --bin wallet -- --wallet-file .wallet2.dat
```

(be sure to use a different wallet filename for each instance)

## reset spentbook and wallet data

The spentbook and wallet data are persisted to disk (by default in the directory in which they are run).  To reset the data, end all wallet and spentbook processes and
then:

```
$ cd sn_dbc_examples
$ ./wipe_wallet_and_spendbook_data.sh
```

# Example session

## Start distributed spentbook with 3 nodes.

```
$ ultraman start
20:35:57 system   | peer3.1  start at pid: 14351
20:35:57 system   | peer2.1  start at pid: 14352
20:35:57 system   | peer1.1  start at pid: 14353
20:35:57 peer2.1  | Spentbook [c35b8e..] listening for messages at: 127.0.0.1:5099
20:35:57 peer1.1  | Spentbook [2f33dd..] listening for messages at: 127.0.0.1:1111
20:35:57 peer3.1  | Spentbook [007608..] listening for messages at: 127.0.0.1:5199
20:35:59 peer1.1  | SpentbookNode created. ready to process spentbook requests.
20:35:59 peer2.1  | SpentbookNode created. ready to process spentbook requests.
20:35:59 peer3.1  | SpentbookNode created. ready to process spentbook requests.
```

## Run a wallet and check initial balance (Bob's wallet)

in shell 1:

```
$ cargo run --bin wallet
    Finished dev [unoptimized + debuginfo] target(s) in 0.14s
     Running `target/debug/wallet`

    __     _
    (_  _._|__  |\ | __|_     _ ._|
    __)(_| |(/_ | \|(/_|_\/\/(_)| |<

    ██╗    ██╗ █████╗ ██╗     ██╗     ███████╗████████╗
    ██║    ██║██╔══██╗██║     ██║     ██╔════╝╚══██╔══╝
    ██║ █╗ ██║███████║██║     ██║     █████╗     ██║   
    ██║███╗██║██╔══██║██║     ██║     ██╔══╝     ██║   
    ╚███╔███╔╝██║  ██║███████╗███████╗███████╗   ██║   
    ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝


got spentbook peers: {
    007608(00000000)..: 127.0.0.1:5199,
    2f33dd(00101111)..: 127.0.0.1:1111,
    c35b8e(11000011)..: 127.0.0.1:5099,
}
Type 'help' to get started.

>> balance
Available balance: 0
```

## issue genesis DBC and check balance

in shell 1:

```
>> issue_genesis
Attempting to issue the Genesis Dbc...

>> balance
Available balance: 18446744073709551615
```

## run a second wallet and generate a new key (Alice's wallet)

Alice wants to receive a payment from Bob, so she generates a
new receive key/address:

in shell 2:

```
$ cargo run --bin wallet -- --wallet-file .wallet2.dat
...
>> newkey
Receive PublicKey: a5c4a0e24ff643b9a7056af9efe3ed447472cd8b5a6f272cca4d0e2684e80325b4602c01862c9aa6aca7b7dbea1afb19
```

## Bob reissues genesis DBC into a smaller DBC to pay Alice

in shell 1:

```
>> reissue
Available balance: 18446744073709551615
Amount to spend: 100000
[b]earer or [o]wned: o
Recipient's public key: a5c4a0e24ff643b9a7056af9efe3ed447472cd8b5a6f272cca4d0e2684e80325b4602c01862c9aa6aca7b7dbea1afb19

-- Begin DBC --
01000000a5c4a0e24ff643b9a7056af9efe3ed447472cd8b ...
-- End Dbc--

note: this DBC is owned by a third party
note: change DBC deposited to our wallet.
```

## Alice deposits DBC from Bob into her wallet 

in shell 2:

```
>> deposit
Paste Dbc: 
01000000a5c4a0e24ff643b9a7056af9efe3ed447472cd8b ...
Notes (optional): from Bob
Deposited 100000
```

# Alice verifies wallet balance and unspent DBCs

in shell 2:

```
>> balance
Available balance: 100000

>> unspent
  -- Unspent Dbcs -- 
a56e45ddf45f880b588b75f243fa88328d190c928596c5237c2d3bffe993a66c, rcvd: 2022-03-24T04:24:14.208444897+00:00, amount: 100000 (mine)
```



## License

This SAFE Network library is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) https://opensource.org/licenses/MIT) at your option.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
