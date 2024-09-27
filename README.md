# Murmur

Murmur is an air-gapped keyless crypto wallet protocol that runs on the Ideal Network. It is based on the [Hours of Horus](https://eprint.iacr.org/2021/715) protocol, which leverages timelock encryption and a secure OTP code generator to construct a keyless wallet scheme. Our scheme improves on this construction in several ways. 

- We use a Merkle mountain range in place of a Merkle tree, allowing for arbitrary numbers of OTP codes to be generated
- JIT execution: Rather than relying on a commit-reveal scheme in order to use the wallet, our scheme uses a 'just-in-time' approach leveraging the Ideal Network's on-chain randomness, which provides the decryption key (i.e. BLS signature) necessary to verify proofs.

This repository contains the core implementation of the murmur protocol and a CLI to allow fully non-custodial usage of murmur wallets on the Ideal Network.

## Setup

```
cargo build
```

## Testing

```
cargo test
```
