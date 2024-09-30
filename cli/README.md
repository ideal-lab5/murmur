# Murmur-CLI

An implementation of the Murmur protocol as a CLI.

It allows for the creation and exeuction of ephemeral 'murmur' wallets on the Ideal Network.

## Setup

Install the cli with

``` shell
cargo install murmur
# verify it works
murmur --help
```

To setup a dev environment:
- run a local [IDN solochain node](https://github.com/ideal-lab5/etf)
- [generate metadata](#generating-metadata-for-the-chain)

### Build

`cargo build`

### Usage

##### Create a wallet

``` shell
# generate a wallet valid for the next 1000 blocks
./target/debug/murmur-cli new --name test --seed my_secret_key --validity 1000
```

##### Execute a balance transfer

``` shell
# send a balance transfer now
./target/debug/murmur-cli execute --name test --seed my_secret_key --amount 100
```

## Test

`cargo test`

## Generating metadata for the chain

``` shell
# clone and build the node
git clone git@github.com:ideal-lab5/etf.git
cd etf
cargo +stable build
# run a local node
./target/debug/node --dev
# use subxt to prepare metadata
cd /path/to/murmur/
mkdir artifacts
cargo install subxt-cli
# Download and save all of the metadata:
subxt metadata > ./artifacts/metadata.scale
```

