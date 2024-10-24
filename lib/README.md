# Murmur Lib

An implementation of the Murmur protocol and corresponding CLI. This implements the Murmur protocol for usage with the Ideal network's randomness beacon. Specifically, it uses [TinyBLS377](https://docs.rs/w3f-bls/latest/w3f_bls/engine/type.TinyBLS377.html) and constructs basic identities which are deterministic based on block number.

## Setup

To setup a dev environment:

1. Run a local [IDN solochain node](https://github.com/ideal-lab5/etf)
2. [Generate chain metadata](#generate-metadata)

### Build

To build the project, use the following command:

```shell
cargo build
```

### CLI Usage

##### Create a wallet

To generate a wallet valid for the next 1000 blocks, use:

```shell
./target/debug/murmur new --name test --seed my_secret_key --validity 100
```

##### Execute a balance transfer

To send a balance transfer, use:

```shell
./target/debug/murmur execute --name test --seed my_secret_key --to CuqfkE3QieYPAWPpwiygDufmyrKecDcVCF7PN1psaLEn8yr --amount 100_000_000
```

## Test

To run the tests, use the following command:

```shell
cargo test
```

## Generate Metadata

To run the tests, use the following command:

1. Clone and build the node:

```shell
git clone git@github.com:ideal-lab5/etf.git
cd etf
cargo +stable build
```

2. Run a local node:

```shell
./target/debug/node --tmp --dev --alice --unsafe-rpc-external --rpc-cors all
```

3. Prepare metadata using `subxt`:

```shel
cd /path/to/otp-wallet/
mkdir artifacts
cargo install subxt-cli
```

4. Download and save all of the metadata:

```shell
subxt metadata > ./artifacts/metadata.scale
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the Apache-2.0. See the [LICENSE](../LICENSE) file for details.

## Contact

For any inquiries, please contact [Ideal Labs](https://idealabs.network).
