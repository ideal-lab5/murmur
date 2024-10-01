# Murmur-CLI

An implementation of the Murmur protocol as a CLI.

It allows for the creation and exeuction of ephemeral 'murmur' wallets on the Ideal Network.

## Setup

Install the cli with

``` shell
cargo install murmur-cli
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
./target/debug/murmur-cli new --name test --seed my_secret_key --validity 100
```

##### Execute a balance transfer

``` shell
# send a balance transfer
./target/debug/murmur-cli execute --name test --seed my_secret_key --to CuqfkE3QieYPAWPpwiygDufmyrKecDcVCF7PN1psaLEn8yr --amount 100
```

## Test

`cargo test`
