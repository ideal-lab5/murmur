# Murmur

Murmur is an air-gapped keyless crypto wallet protocol that runs on the Ideal Network. It is based on the [Hours of Horus](https://eprint.iacr.org/2021/715) protocol, where it enables keyless crypto wallets that require knowledge of future OTP codes rather than signatures in order to execute calls. This repository contains the core implementation of the murmur protocol and a CLI to allow fully non-custodial usage of murmur wallets on the Ideal Network.

## Setup

```
cargo build
```

## Testing

```
cargo test
```
