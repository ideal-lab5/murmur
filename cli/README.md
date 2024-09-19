# Murmur-CLI

An implementation of the Murmur protocol as a CLI.

It allows for the creation and exeuction of ephemeral 'murmur' wallets for use on the Ideal Network.

## Setup

To setup a dev environment:
- run an IDN node
- 

### Build

`cargo build`

### Usage

``` shell
# generate a wallet valid for the next 1000 blocks
./target/debug/murmur-cli new --name test --seed my_secret_key --valid-for 1000
# send a balance transfer now
./target/debug/murmur-cli execute --name test --seed my_secret_key --amount 100
# schedule a balance transfer
./target/debug/murmur-cli schedule-execute --name test --seed my_secret_key --when 100 --amount 100
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
./target/debug/node --tmp --dev --alice --unsafe-rpc-external --rpc-cors all
# use subxt to prepare metadata
cd /path/to/otp-wallet/
mkdir artifacts
cargo install subxt-cli
# Download and save all of the metadata:
subxt metadata > ./artifacts/metadata.scale
```

