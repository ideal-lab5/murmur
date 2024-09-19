# Murmur Core

The core implementation of the murmur protocol. This library enables each step of the Murmur protocol, including implementations of the following:

### Functions

#### Create
$\{(b_i, ct_i)\}_{i \in [n]} \leftarrow Murmur.Create(seed, \{b_0, ..., b_n\}) $

#### PrepareExecute
$h_b \leftarrow PrepareExecute(seed, AUX, b)$

#### Verify
- `verify -> true/false`

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