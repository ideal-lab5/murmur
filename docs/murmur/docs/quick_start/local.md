---
sidebar_position: 2
---

# Murmur CLI

Create and execute a murmur wallet from a terminal.

The murmur-cli is a standalone client that creates and manages Merkle mountain range data for murmur wallets. It can be used to create new murmur wallets and to execute balance transfers from them against the Ideal Network's testnet.

## Installation

The easiest way to install the murmur client is with [cargo](https://doc.rust-lang.org/cargo/) install. By default it will try to connect to a Substrate node running on `localhost:9944`. This can be configured by specifying the environment variable `WS_URL` (e.g. `WS_URL=wss://etf1.idealabs.network:443`).

``` shell
cargo install --git https://github.com/ideal-lab5/murmur
# verify the installation
murmur --help
```

You can use docker to easily run a local IDN validator node (with RPC exposed on localhost:9944) with:

``` shell
docker pull ideallabs/etf@latest
docker run -p 9944:9944 ideallabs/etf --tmp --dev --alice --unsafe-rpc-external
```

## Create a Wallet

murmur wallets are inherently *ephemeral* in nature since we can't generate an infinite Merkle mountain range. The 'validity' period determines the number of future blocks when the wallet will be executable. In the future we will implement an 'update' algorithm to allow exhausted wallets to be extended. 

``` shell
murmur new --name SomeUniqueName --seed 0xAnyString --validity 1000
```

## Execute a Balance Transfer

``` shell
murmur new --name SomeUniqueName --seed 0xAnyString --to SomeRecipientAddress --amount aNumericalAmount
```

## Update a Wallet
Coming Soon