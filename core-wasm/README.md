# Murmur Core Wasm

The core implementation of the murmur protocol as a wasm pack. This library enables each step of the Murmur protocol, including implementations of the following:

- `create`
- `execute`
- `verify -> true/false`

## Tests

Run the wasm tests with wasm-pack: `wasm-pack test --node`

## Deploy

run the `wasm-build.sh` script to generate the wasm-build (in pkg directory)
