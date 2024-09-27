# Murmur Core

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