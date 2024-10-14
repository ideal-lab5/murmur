---
sidebar_position: 3
---

# Browser Integration

Murmur can be easily integrated into web applications with [murmur.js](https://github.com/ideal-lab5/murmur.js), a javascript wrapper that allows you to communicate with the `murmur-api`.

1. [Integrate Murmur](#integrate-murmur)
2. [Sequence Diagram](#sequence-diagram)

## Murmur Integration Guide

To get started, create a new javascript-based project (e.g. `npx init`). Then install the following dependencies

```shell
npm i @ideallabs/murmur.js axios @polkadot/api
```

``` js
import { MurmurStore } from "@ideallabs/murmur.js";
// setup axios and polkadotjs
let { axios, api } = await setup()
// instantiate an instance of a murmur store 
let murmur = new MurmurStore(axios, api)
// get a session cookie
murmur.authenticate({
    username,
    password
})
```

## Create a Murmur Wallet

The validity period specifies the duration (from creation) for which the wallet is valid. 

``` js
let validity = 500
murmur.new(validity).then(() => {
    // handle result
})
```

## Update a Wallet 

Coming soon, will be something like this:
``` js
let validity = 500
murmur.update(validity).then(result => {
    // do stuff
})
```

## Execute a Murmur Wallet

``` js
// use polkadotjs to construct some call
let call = prepareCall(api)
murmur.execute(call).then(result => {

})
```

## Query Murmur wallets

Use the polkadotjs api to query the chain state:
``` js
let name = 'some_name';
murmur.inspect(name).then(result => {
    console.log(result)
})
```

## Sequence Diagram

![sequence_diagram](../../assets/murmur_seq_diagram.drawio.png)
