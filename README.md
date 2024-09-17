# Murmur

Murmur is an air-gapped keyless crypto wallet protocol that runs on the Ideal Network. It is based on the [Hours of Horus](https://eprint.iacr.org/2021/715) protocol, where it enables keyless crypto wallets that require knowledge of future OTP codes rather than signatures in order to execute calls.

## Setup

```
cargo build
```

## Testing

```
cargo test
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