# Murmur

Murmur is a framework for building web3 applications. It enables on-chain, time-based event clocks. 

An OTP Wallet Client

This is an experimental keyless crytpo wallet client for OTP proxies on the ETF Network.

This client allows users to authenticate with a pure proxy by using an OTP code. It uses timelock encryption and time-based OTP generation 

## Setup

```
cargo build
```

## Testing

```
cargo test
```

## Usage

``` shell
murmur-cli new --seed [] --name [] --schedule 100 101 209...
```

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

## TODOs

- [ ] pass mmr_store path as a parameter
- [ ] error handling
- [ ] add dry run option (e.g. to check if username is a duplicate) e.g. add the '-x' flag to indicate if the call should be executed: `otp-wallet-client execute ... -x` 