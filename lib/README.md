# murmur-lib

An implementation of the Murmur protocol and corresponding CLI. This implements the Murmur protocol for usage with the Ideal network's randomness beacon. Specifically, it uses [TinyBLS377](https://docs.rs/w3f-bls/latest/w3f_bls/engine/type.TinyBLS377.html) and constructs basic identities which are deterministic based on block number.

## Setup

To setup a dev environment:
- run a local [IDN solochain node](https://github.com/ideal-lab5/etf)
- [generate chain metadata](#generate-metadata)

### Build

`cargo build`

### CLI Usage

##### Create a wallet

``` shell
# generate a wallet valid for the next 1000 blocks
./target/debug/murmur new --name test --seed my_secret_key --validity 100
```

##### Execute a balance transfer

``` shell
# send a balance transfer
./target/debug/murmur execute --name test --seed my_secret_key --to CuqfkE3QieYPAWPpwiygDufmyrKecDcVCF7PN1psaLEn8yr --amount 100_000_000
```

## Test

`cargo test`


## Generate Metadata

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