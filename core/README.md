# Murmur Core

This library contains the core implementation of the murmur protocol. This implementation can support both BLS12-377 and BLS12-381, but is left curve-agnostic, only expecting that the beacon is produced by an ETF-PFG instance.

## Build

``` shell
cargo build
```

The OTP code generator is gated under the "client" feature, so build with:
``` shell
cargo build --features "client"
```

## Test

``` shell
cargo test
```

The OTP code generator is gated under the "client" feature, so run tests with:
``` shell
cargo test --features "client"
```

## Future Work/Notes
- There is an 'otpauth' feature that can be enabled on the totp lib. It allows for the inclusion of an issuer and account_name. We can investigate usage of this in the future. https://github.com/constantoine/totp-rs/blob/da78569b0c233adbce126dbe0c35452340fd3929/src/lib.rs#L160
- Wallet Update logic: Each murmur wallet is ephemeral, since any MMR must be limited in size. We can use a zkp to prove knowledge of the seed in order to allow  the wallet owner to update the wallet by providing a new MMR root.