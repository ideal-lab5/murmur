---
sidebar_position: 3
---

# Browser Integration

Murmur can be easily integrate into web applications with **murmur.js**, a javascript wrapper that allows you to communicate with the `murmur-api` (TODO link to the api?).

## Integrate Murmur

``` js
import { MurmurStore } from "murmur.js";
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
murmur.new(validity)
```

## Update a Wallet 

Coming soon, will be something like this:
``` js
let validity = 500
murmur.update(validity)
```

## Execute a Murmur Wallet

``` js
// use polkadotjs to construct some call
let call = prepareCall(api)
murmur.execute(call)
```

## Query Murmur wallets

Use the polkadotjs api to query the chain state:
``` js
let name = 'some_name';
let maybeWallet = await api.query.murmur.registry(name);
```