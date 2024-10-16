---
sidebar_position: 1
---

# Murmur (At a Glance)

This is a comprehensive overview of the Murmur protocol and architecture. Murmur is inspired by [hours of horus](https://eprint.iacr.org/2021/715), though with several improvements to enhance practicality. Our implementation relies on the [Ideal Network](https://docs.idealabs.network) (IDN), a Substrate-based verifiable randomness beacon we developed in conjunction with the [Web3 Foundation](https://web3.foundation/). Beyond outputting verifiable randomness, the IDN also enables efficient [timelock encryption](https://docs.idealabs.network/docs/learn/crypto/timelock_encryption), a cryptographic primitive where messages can be encrypted *for a future block* in such a way that the beacon randomness produced in that block acts as a decryption key for the data. 

## How it Works

A murmur wallet is a modified [pure proxy](https://wiki.polkadot.network/docs/learn-proxies-pure) set to have **no delegate** - meaning any origin can attempt to use the proxy. This type of proxy, which we call a **murmur proxy**, is the key to enabling seamless cross-platform account abstraction. Murmur proxies are created with a given unique name and self-reported root and size of a [Merkle mountain range](https://docs.grin.mw/wiki/chain-state/merkle-mountain-range/) whose leaves are timelock encrypted OTP codes. Instead of relying on signature verification to determine if a call can be proxied, a murmur wallet requires: successful timelock decryption, a valid merkle proof, and a commitment to the OTP code and the call to be proxied. The idea is that valid OTP codes must be supplied on a *just in time* basis, where a prover (the caller) attempts to convince a verifier (the runtime) that they had knowledge of the OTP code before it could have been decrypted and without revealing it. It is important to note that end users **do not** observe and input generated OTP codes into an application as in standard OTP-based authentication, the handling of OTP codes is "invisible" to the end user.

**Ideal Network**

The Ideal Network is a Substrate-based blockchain that enables a randomness beacon based on an [aggregatable BLS Signature Scheme](https://eprint.iacr.org/2022/1611). It produces fresh verifiable randomness each time the Ideal Network finalizes a block. Quite different than solutions like [drand](https://drand.love), this beacon uses DLEQ proofs to verify beacon output, enabling for more efficient onchain verification (as opposed to checking pairings). Beacon outputs are encoded in the runtime via the [randomness beacon pallet](https://github.com/ideal-lab5/pallets/tree/main/pallets/randomness-beacon). You can learn more about the Ideal Network by visiting the docs [here](https://docs.idealabs.network).

<div style={{ textAlign: 'center' }}>
![idn_stack](../../assets/idn_stack.drawio.png)
</div>

**Creating a Wallet**

The diagram below depicts the creation of a Murmur wallet, where:
- $\mathcal{G}$ is a *secure time-based OTP code generator*
- $ct \leftarrow TLE(OTP, ID(j))$ represents timelock encryption 
- the OTP code $OTP$ is encrypted "for" block number $j$. 

The general idea is that OTP codes are generated for future blocks and lock them with timelock encryption for each respective block. They are then organized into a Merkle mountain range which can be publicly stored. The user then submits an extrinsic to create a new wallet, specifying a *unique* name, root, and MMR size. The call can be sent from *any* origin (e.g. an ephemeral keypair built with a light client such as Substrate-connect). For formal proofs, we invite the reader to investigate the Hours of Horus paper mentioned above.

<div style={{ textAlign: 'center' }}>
![create](../../assets/murmur_create.drawio.png)
</div>

**Using a Wallet**

Execution of calls from a Murmur wallet requires that a user constructs a valid Merkle proof and commitment and provides the data to the chain 'just in time'. The IDN, which acquires fresh randomness with each finalized block, will attempt to use the latest known signature to decrypt the provided ciphertext. If it cannot be decrypted, then the protocol is aborted. Otherwise, the plaintext is used to verify the commitment, which should be the hash of the OTP code concatenated with the call to be proxied. If the Merkle proof is also valid, then the runtime is convinced that the caller knew the OTP code before it could have been decrypted and that it is a leaf within the MMR. When convinced of the validity, the runtime allows the proxy to execute the call.

<div style={{ textAlign: 'center' }}>
![execute](../../assets/murmur_execute.drawio.png)
</div>

**Updating a Wallet**

You may have noticed that since OTP codes are only generated for a limited block schedule the wallet is inaccessible after block $k$ is finalized. This is indeed the case, that each Murmur wallet can be considered as ephemeral. We have not yet implemented the update logic, but it will be coming soon. Once implemented, Murmur wallets can be considered as 'session-based', operating in limited authorized sessions defined by the user.

## Components and Architecture

The Murmur protocol is intended to be flexible and can be implemented in a variety of ways to fit the context. In this section we detail the various components and discuss how they connect to one another.

<div style={{ textAlign: 'center' }}>
![murmur_components](../../assets/murmur_stack.drawio.png)
</div>

**Rust Compatibility**

The `murmur-core` library, and it's corresponding `murmur-lib` implementation (using BLS377 with type III pairings), allow for the solution to easily be used in **rust**. The release build of this library is able to handle the generation and encryption of 1000 OTPs in under 4 seconds.

**Javascript Compatibility**

The `murmur.js` library allows for Murmur to be used in **javascript**. Presently, this functions as an HTTP connector to the `murmur-api`, though in the future we will investigate javascript binding rather than relying on the API.

The visualization below depicts dependencies and flow of data of each component of Murmur's architecture. 

<div style={{ textAlign: 'center' }}>
![connections](../../assets/murmur_connections.drawio(1).png)
</div>

**[murmur-core](https://github.com/ideal-lab5/murmur/tree/main/core)**

The basis of the murmur "stack" is the `murmur-core` crate, which encapsulates the logic for constructing and proving things about the MMR data required for murmur wallets.

**[murmur-lib](https://github.com/ideal-lab5/murmur/tree/main/lib)**

This is an *implementation* of the murmur protocol over BLS377 using type III pairings.

**[murmur-api](https://github.com/ideal-lab5/murmur-api)**

The `murmur-api` is a Rust-based web service designed to facilitate the use of `murmur-lib`. It is an HTTP API with an open-read database, allowing users to export MMR data and maintain full control over their Murmur wallets. This API primarily serves as a convenience to externalize OTP code generation and ensure adequate entropy when constructing seeds for OTP codes. In the future, we aim to deprecate this component.

**[murmur.js](https://github.com/ideal-lab5/murmur.js)**

This is an HTTP connector to the `murmur-api`. It encapsulates communication with the API as a javascript-based wrapper, facilitating creation, inspection, and execution of Murmur wallets. It relies on `axios` and `polkadot.js` to communicate the the `murmur-api` and the IDN, respectively.

**Examples** 
- The [murmur-cli](https://github.com/ideal-lab5/murmur/tree/main/lib/src/bin/murmur) is a terminal-based way to use murmur. 
- The murmur.js library can be used in various javascript based contexts. For example, the [murmur-dapp](https://github.com/ideal-lab5/murmur-dapp/) is a next.js application that demonstrates usage the library in a browser-based context, while the [murmur-discord-bot](https://github.com/ideal-lab5/murmur-discord-bot) functions in a node.js environment, allowing for murmur wallets to be used within Discord.


### Pallets

> IMPORTANT: Pertaining to participation in [Polkadot 2024 Hackathon | Bangkok](https://dorahacks.io/hackathon/polkadot-2024-bangkok/detail), the core consensus modules of the Ideal Network and the Randomness Beacon pallet should not be considered for evaluation, as it was developed outside the scope of this hackathon.

The [Murmur pallet](https://github.com/ideal-lab5/pallets/tree/main/pallets/murmur) is the core pallet that enables Murmur wallets. Specifically, it takes the role of a 'prover' in the [Murmur protocol](../learn/protocol.md), where it is responsible for registering uniquely named Murmur proxies and acting as an extension to the proxy pallet, where it verifies execution parameters prior to dispatching them. Specifically, this works with our modified [Proxy pallet](https://github.com/ideal-lab5/pallets/tree/main/pallets/proxy), which allows virtually uncallable proxies to be defined with *no delegate*. This proxy type can only be used via the Murmur pallet's proxy extrinsic, which requires valid proof of future OTP codes.


<div style={{ textAlign: 'center' }}>
![idn_pallets](../../assets/murmur_pallets.drawio.png)
</div>

Explore the [pallets repo](https://github.com/ideal-lab5/pallets/tree/main) to learn more about the core runtime modules that power Murmur and the Ideal Network.

## Vulnerabilities, Limitations, Assumption

- Murmur wallets are inherently ephemeral. We currently have not implemented any update functionality, meaning that in its current state all Murmur wallets expire at some point. We will address this in the future.
- Murmur wallets are not recoverable currently. If the user loses their username/seed then they have effectively lost access to their wallet. 
- There has been no formal security audit of the IDN or Murmur.
- Murmur wallets **only** work on the IDN solochain for the time being. In the near future we will deploy the network as a parachain and explore ways to make Murmur wallets easily usable in a cross-chain capacity.


