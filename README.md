# Murmur

Murmur is an air-gapped keyless crypto wallet protocol that runs on the [Ideal Network](). This repository contains the core implementation of the murmur protocol and a CLI to allow fully non-custodial usage of murmur wallets.

The murmur protocol enables **keyless account abstraction** capabilities for any chain bridged to the Ideal Network (alternatively, we can do this with drand). wallet is a special pure proxy that can only be executed when presented with proof that the origin knows a correct time-based OTP code. 

It is based on the [Hours of Horus](https://eprint.iacr.org/2021/715) protocol, which leverages timelock encryption and a secure OTP code generator to construct a keyless wallet scheme. Our scheme improves on this construction in several ways. 

- We leverage the Ideal Network to instantiate practical timelock encryption, allowing the HoH scheme to be realized in the first place.
- We use a Merkle mountain range in place of a Merkle tree, allowing for arbitrary numbers of OTP codes to be generated
- JIT execution: Rather than relying on a commit-reveal scheme in order to use the wallet, our scheme uses a 'just-in-time' approach leveraging the Ideal Network's on-chain randomness, which provides the decryption key (i.e. BLS signature) necessary to verify proofs.

## Build

```
cargo build
```

## Testing

```
cargo test
```
