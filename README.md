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

## TODOs

- [ ] create and add latex doc
- [ ] add zeroize for safety
- [ ] look into using ratatui
- [ ] performance and storage optimizations