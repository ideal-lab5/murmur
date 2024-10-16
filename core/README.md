# Murmur Core

This library contains the core implementation of the murmur protocol. This implementation can support both BLS12-377 and BLS12-381, but is left curve-agnostic, only expecting that the beacon is produced by an ETF-PFG instance.

## Build

To build the library, use the following command:

```shell
cargo build
```

The OTP code generator is gated under the "client" feature. To build with this feature enabled, use:

```shell
cargo build --features "client"
```

## Test

To run the tests, use the following command:

```shell
cargo test
```

The OTP code generator is gated under the "client" feature, so run tests with:

```shell
cargo test --features "client"
```

## Future Work/Notes

- **OTPAuth Feature**: There is an 'otpauth' feature that can be enabled on the totp lib. It allows for the inclusion of an issuer and account_name. We can investigate usage of this in the future. [TOTP Library Reference](https://github.com/constantoine/totp-rs/blob/da78569b0c233adbce126dbe0c35452340fd3929/src/lib.rs#L160)
- **Wallet Update logic**: Each murmur wallet is ephemeral, since any MMR must be limited in size. We can use a zkp to prove knowledge of the seed in order to allow the wallet owner to update the wallet by providing a new MMR root.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the Apache-2.0. See the [LICENSE](../LICENSE) file for details.

## Contact

For any inquiries, please contact [Ideal Labs](https://idealabs.network).