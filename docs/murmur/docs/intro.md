---
sidebar_position: 1
---

# Murmur

---
Noun. *a low indistinct but often continuous sound*
> The *murmur* of the waves along the shore
> A *murmur* of voice

---

Murmur is a **keyless crypto wallet protocol** powered by the [Ideal Network](https://docs.idealabs.network) (IDN). Using **timelock encryption** and secure time-based [one-time password](https://www.techtarget.com/searchsecurity/definition/one-time-password-OTP) (OTP) generation, **murmur** allows users to create and execute secure crypto wallets with no mnemonic or secret key. Murmur allows users to access crypto wallets without needing a secret key or mnemonic - it is a truly keyless wallet solution.

Murmur wallets can be accessed seamlessly across web-enabled devices, providing a plug-and-play solution for app developers to easily integrate web3 capabilities into applications and services with no additional infrastructure or overhead. Murmur wallets can be used by installing a standalone wallet client or by using our GDPR-compliant "MMR-as-a-Service" API, which allows you to easily create in-app wallets with seamless cross-browser interoperability. 

## Why Murmur?

Crypto wallets and account abstraction come in a myriad of flavors, custodial, non-custodial, MPC, and various other "wallet-as-a-service" solutions. 

Murmur offers a distinct alternative to tradition MPC wallets. Normally, MPC wallets require *wallet providers* to issue threshold signatures on command. This can present several challenges, such as:

- **Scalability issues**: More users means more requests for signatures and more load on the network
- **Increased Costs**: Users can encounter significant fees for higher security, essentially placing wallet security behind a paywall

Murmur sidesteps these disadvantages by relying on the Ideal Network's [randomness beacon](https://docs.idealabs.network/docs/learn/etf-pfg) to produce decryption keys for future OTP codes. Rather than producing threshold signatures on-demand, threshold signatures are produced with each block finalized by the IDN. This results in a highly scalable, cost-efficient, and decentralized wallet solution.

**Key Features**
- **Truly Keyless Wallet**: No mnemonic or key management required.
- **No Wallet Provider**: No reliance on a third-party provider for wallet access.
- **Infinitely Scalable**: The Murmur protocol is designed to scale without increased computational or financial overhead, limited only by the underlying blockchain.
- **Non-Custodial**: While Murmur offers API-based access for convenience, users maintain full control of their wallets at all times.
- **Secure Against Key Extraction Attacks**: Unlike some threshold ECDSA approaches, Murmur uses threshold BLS signatures and is resistant to key extraction vulnerabilities (e.g. [research by zengo-x](https://eprint.iacr.org/2021/1621.pdf)).

<!-- 
| Attribute | Non-Custodial | Custodial | WaaS (e.g. [magic.link](magic.link)) | MPC | Murmur |
|-------------------|--|--|--|--|--|
| Scalability       | a|b|c|d|e|
| Permissibility    | a| b|c|d|e| -->

## Getting Started

The murmur protocol is very flexible and can be used in various contexts, each with different trust models. Start [here](./quick_start/protocol.md) to learn more about the inner workings of the murmur protocol, or just jump into the code on [github](https://github.com/ideal-lab5/murmur).

**From a Browser**
Murmur can be used from the browser by relying on the murmur.js library to communicate with an API, allowing for the creation and execution of in-app wallets. The [murmur-api](https://github.com/ideal-lab5/murmur-api) is a stateless API that simply outsources the computation required to compute and encrypt OTP codes and merkle proofs. [Murmur.js](https://github.com/ideal-lab5/murmur.js) is a javascript library that lets developers easily integrate keyless crypto wallets into their applications. In conjunction with [polkadot.js](https://polkadot.js.org/docs/api), it allows developers to easily add a 'wallet-as-a-service' mechanism to their applications. 

Check out the [browser integration guide](./quick_start/browser.md) to learn how to integrate murmur into your applications by communicating with the api. See out the library in action by exploring the [murmur-dapp](https://github.com/ideal-lab5/murmur-dapp/) and [murmur discord bot](https://github.com/ideal-lab5/murmur-api).

**Standalone Client**
You can also run the murmur wallet using a standalone client. Try the [cli](./quick_start/local.md) for a terminal based client that allows you to create a wallet and execute basic balance transfers.

<!-- ## Future Work
This type of wallet requires that murmur wallet user transactions are signed on behalf of an origin with enough funding to cover any resultant transaction fees. While we do not address it in this work, we leave it as an open task to address a potential paymaster scheme. This also allows for KYC or other such mechanisms to easily be established (e.g. if there is a semi-centralized API required to sign transction).

- Performance Improvements
    - batch verification for execution and updates 
        - what if we used a Verkle Mountain range instead? 
        - This could let us represent many murmur wallets with a single data structure
        - also a VMR allows for more efficient 'multiproofs', so I suppose you could efficiently prove a set of murmur wallets, connected within a VMR, can efficiently be proved in a batch verification scenario  -->
