---
sidebar_position: 1
---

# Murmur

---
Noun. *a low indistinct but often continuous sound*
> The *murmur* of the waves along the shore
> A *murmur* of voice

---

Murmur is a **keyless crypto wallet protocol** powered by the [Ideal Network](https://docs.idealabs.network) (IDN). Using **timelock encryption** and secure time-based [one-time password](https://www.techtarget.com/searchsecurity/definition/one-time-password-OTP) (OTP) generation, **murmur** allows users to create and execute secure crypto wallets with no mnemonic or secret key - it is a truly keyless wallet solution. The protocol is designed to be versatile and can be used in a myriad of ways, from [a terminal](./quick_start/local.md) to [twitch chats](./quick_start/twitch.md).

Murmur wallets can be accessed seamlessly across web-enabled devices, providing a frictionless plug-and-play solution for app developers to integrate web3 capabilities into applications and services without any additional infrastructure or overhead. Murmur wallets can be used by installing a **standalone wallet client** or by using our **HTTP API**, which allows you to easily create in-app wallets with seamless interoperability across browsers and other HTTP clients. 

## Why Murmur?

Crypto wallets and account abstraction come in a myriad of flavors, custodial, non-custodial, MPC, and various other "wallet-as-a-service" solutions. 

Murmur offers a distinct alternative to tradition MPC wallets. Normally, MPC wallets require *wallet providers* to issue threshold signatures on command. This can present several challenges, such as:

- **Scalability issues**: More users means more requests for signatures and more load on the network
- **Increased Costs**: Users can encounter significant fees for higher security, essentially placing wallet security behind a paywall

Murmur sidesteps these disadvantages by relying on the Ideal Network's [randomness beacon](https://docs.idealabs.network/docs/learn/etf-pfg) to produce decryption keys for future OTP codes. Rather than producing threshold signatures on-demand, threshold signatures are produced with each block finalized by the IDN. This results in a highly scalable, cost-efficient, and decentralized wallet solution, where more users does not correlate with added computational overhead.

**Key Features**
- **Truly Keyless Wallet**: No mnemonic or key management required.
- **No Wallet Provider**: No reliance on a third-party provider for wallet access.
- **Infinitely Scalable**: The Murmur protocol is designed to scale without increased computational or financial overhead, limited only by the underlying blockchain.
- **Non-Custodial**: Users retain complete control of their wallets at all times. Even when opting for the convenience of HTTP-API-based access, only the heavy computational tasks are outsourced, ensuring full ownership remains with the user.
- **Secure Against Key Extraction Attacks**: Unlike some threshold ECDSA approaches, Murmur uses threshold BLS signatures and is resistant to key extraction vulnerabilities (e.g. [research by zengo-x](https://eprint.iacr.org/2021/1621.pdf)).

<!-- 
| Attribute | Non-Custodial | Custodial | WaaS (e.g. [magic.link](magic.link)) | MPC | Murmur |
|-------------------|--|--|--|--|--|
| Scalability       | a|b|c|d|e|
| Permissibility    | a| b|c|d|e| -->

## Getting Started

The murmur protocol is very flexible and can be used in various contexts, each with different trust models. Start [here](./learn/protocol.md) to learn more about the inner workings of the murmur protocol, or just jump into the code on [github](https://github.com/ideal-lab5/murmur).

**From a Browser or JS app**
Murmur can be used from any web-enabled javascript context by relying on the **murmur.js** library to communicate with the **murmur-api**, allowing for the creation and execution of in-app wallets. The [murmur-api](https://github.com/ideal-lab5/murmur-api) is a permissionless HTTP API that simply outsources the computation required to compute and encrypt OTP codes and merkle proofs. [Murmur.js](https://github.com/ideal-lab5/murmur.js) is a javascript library that lets developers easily integrate keyless crypto wallets into their applications. In conjunction with [polkadot.js](https://polkadot.js.org/docs/api), it developers can add a 'wallet-as-a-service' mechanism to their applications with minimal effort. 

Check out the [browser integration guide](./quick_start/browser.md) to learn how to integrate murmur into your applications by communicating with the api. See out the library in action by exploring the [murmur-dapp](https://github.com/ideal-lab5/murmur-dapp/) and [murmur-bots](https://github.com/ideal-lab5/murmur-bots/) repo. which includes both Discord and Twitch bots.

**Standalone Client**
You can also run the murmur wallet using a standalone client. Try the [cli](./quick_start/local.md) for a terminal based client that allows you to create a wallet and execute basic balance transfers.

## Question?

If you have questions about Murmur or the Ideal network, get in touch by [joining our discord channel](https://discord.gg/phZvQkzU2a).
