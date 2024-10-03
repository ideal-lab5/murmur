---
sidebar_position: 1
---

# Murmur

Murmur is a keyless crypto wallet protocol for Substrate based chains, specifically the [Ideal Network](https://docs.idealabs.network). It is an implementation of the [hours of horus](https://eprint.iacr.org/2021/715) wallet with several improvements to enhance practicality. Powered by **timelock encryption** and secure **OTP code** generation, **murmur** allows users to create and execute secure crypto wallets with no mnemonic or secret key. Murmur wallets can be accessed seamlessly across web-enabled devices.

- need to provide motivation for the solution
- need to compare to existing solutions. How does it compare to: custodial, non-custodial, MPC wallets, Aptos keyless wallets..

## Getting Started

Start [here](./quick_start/protocol.md) to learn more about the inner workings of the murmur protocol. 

Check out the [api](./quick_start/api.md) docs to learn how to integrate murmur into your applications. 

If you just want to get started, try the [cli](./quick_start/local.md) for a standalone version the wallet client.

## Future Work
This type of wallet requires that murmur wallet user transactions are signed on behalf of an origin with enough funding to cover any resultant transaction fees. While we do not address it in this work, we leave it as an open task to address a potential paymaster scheme. This also allows for KYC or other such mechanisms to easily be established (e.g. if there is a semi-centralized API required to sign transction).

- Performance Improvements
    - batch verification for execution and updates 
        - what if we used a Verkle Mountain range instead? 
        - This could let us represent many murmur wallets with a single data structure
        - also a VMR allows for more efficient 'multiproofs', so I suppose you could efficiently prove a set of murmur wallets, connected within a VMR, can efficiently be proved in a batch verification scenario 
