---
sidebar_position: 1
---

# Murmur

Murmur is a keyless crypto wallet protocol for Substrate based chains, specifically for the [Ideal Network](https://docs.idealabs.network). It is an implementation of the [hours of horus](https://eprint.iacr.org/2021/715) protocol with several improvements to enhance practicality. Powered by **timelock encryption** and secure **OTP code** generation, **murmur** allows users to create and execute secure crypto wallets with no mnemonic or secret key. Murmur wallets can be accessed seamlessly across web-enabled devices, providing a plug-and-play solution for app developers to easily integrate web3 capabilities into applications and services with no additional infrastructure or overhead.

Crypto wallet solutions and abstractions come in a myriad of flavors, which we can generally categorize into custodial, non-custodial, and MPC. Murmur is an MPC-based solution, but it doesn't work as a traditional MPC wallet. Normally, MPC wallets require that a set of workers produce threshold signatures *per-request* and on-demand, producing signatures as requested by wallet owners. This presents several issues though. Firstly, more users means more requests, meaning more work must be done by the network workers in order to produce threshold signatures, which could cause problems in terms of scalability if there are a large number of users. If tokenomics are not well constructed, this could lead to large fees being required in order to access a wallet. In addition, an MPC wallet can add a paywall to security, as you may have to pay a higher fee if you want more workers to participate in the threshold signing phase. Murmur, on the other hand, doesn't suffer from these issues. Murmur functions against the Ideal Network's randomness beacon, allowing for any number of murmur wallets to be executed simulataneously without requring additional costs or computations from the network's workers, making the solution is far more scalable and cost efficient.

## Getting Started

- Murmur.js is a javascript library that lets developers easily integrate keyless crypto wallets into their applications. Check out the [browser integration guide](./quick_start/browser.md) to learn how to integrate murmur into your applications. 

- You can also run the murmur wallet using a standalone client. Try the [cli](./quick_start/local.md) for a terminal based client that allows you to create a wallet and execute basic balance transfers.

- Start [here](./quick_start/protocol.md) to learn more about the inner workings of the murmur protocol, or just jump into the code on [github](https://github.com/ideal-lab5/murmur).


<!-- ## Future Work
This type of wallet requires that murmur wallet user transactions are signed on behalf of an origin with enough funding to cover any resultant transaction fees. While we do not address it in this work, we leave it as an open task to address a potential paymaster scheme. This also allows for KYC or other such mechanisms to easily be established (e.g. if there is a semi-centralized API required to sign transction).

- Performance Improvements
    - batch verification for execution and updates 
        - what if we used a Verkle Mountain range instead? 
        - This could let us represent many murmur wallets with a single data structure
        - also a VMR allows for more efficient 'multiproofs', so I suppose you could efficiently prove a set of murmur wallets, connected within a VMR, can efficiently be proved in a batch verification scenario  -->
