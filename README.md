# Murmur

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

## How it works

In order to use the wallet, there must be at least one node running. I recommend running a local node for testing purposes.

Also, the OTP wallet can only be called via proxy, so in order to use this client you must also have an ETF wallet somewhere. This could be through the polkadotjs extension or in the local keystore. 

### Wallet Creation

- first build the project (cargo build) to generate the target/debug folder, where otp-wallet-client exists. Alternately, building in release mode will generate the target/release folder. 

``` bash
otp-wallet-client new <name> <seed> 
```
This writes to a new file called mmr_store in the root directory. This file contains the MMR leaf data. It is **not** secret data and can be freely publicized or broadcast (e.g. it can be stored in IPFS without exposing any secret information).

#### How it works
1. Use the seed to generate a new TOTP generator
2. Based on the current block number and the max block height parameter, generate future OTP codes for each future block in the range
3. Build an MMR 
4. Call the `OTPProxy > create` extrinsic with the MMR root to create the proxy [TODO]

### Wallet Usage
- delay must be >= 2
- assumes mmr_store exists in root 
  
``` bash
otp-wallet-client execute <name> <seed> --delay 2 --to AcctId --amount 100_000_00
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
- [ ] modify cli to allow any call to be submitted, something like `otp-wallet-client execute <username> <seed> --pallet <pallet_name> --extrinsic <extrinsic name> --params [path separated parameter list] --delay X`