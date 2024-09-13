# Murmur Core

The core implementation of the murmur protocol. This library enables each step of the Murmur protocol, including implementations of the following:

- `create -> (root, mmr_leaves_to_bn = {(1, Leaf(0x0123...)), (3, Leaf(0x12301...)), ...})`
- `execute -> `
- `verify -> true/false`

## Build
``` shell
cargo build
```

## Test

``` shell
cargo test
```