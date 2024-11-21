# Murmur Core

This library contains the core implementation of the murmur protocol. This implementation can support both BLS12-377 and BLS12-381, but is left curve-agnostic. This crate can support the randomness beacon produced by the [Ideal Network](https://idealabs.network) as well as [Drand](https://drand.love)'s Quicknet. In general, this library is intended to work with a blockchain whose runtime includes the corresponding [Murmur Pallet](https://github.com/ideal-lab5/idn-sdk/tree/main/pallets/murmur). More specifcially, it is intended to run against the [Ideal Network](https://idealabs.network). For examples of usage against a real network, refer to the [CLI](../lib/src/bin/murmur/main.rs).

## Usage

### Creation and Execution

#### Create a Murmur Store

``` rust
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;
use w3f_bls::{DoublePublicKeyScheme, KeypairVT, TinyBLS377};

// This simulates the production of a randomness beacon public key
// In practice, this would be fetched from the beacon (e.g. as a hex string) and must be deseraialized
let keypair = KeypairVT::<TinyBLS377>::generate(&mut rng);
let double_public: DoublePublicKey<TinyBLS377> =
    DoublePublicKey(keypair.into_public_key_in_signature_group().0, keypair.public.0);

// The 'lifetime' of the Murmur wallet for the given session
let block_schedule: &[BlockNumber] =
    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

// This is your 'secret' seed, a short password used while constructing OTP codes
let seed = vec![1, 2, 3];

// The nonce functions similarly to nonce's for standard accounts, except instead of updating on a 
// "per transaction" basis, it only updates on a "per session" basis
// 
let nonce = 0;

let murmur_store = MurmurStore::<EngineTinyBLS377>::new::<
    DummyIdBuilder,
    OsRng,
    ChaCha20Rng,
>(seed.clone(), block_schedule.to_vec(), nonce, double_public, &mut rng)
.unwrap();
```
#### Update a Murmur Store

Updating a Murmur store is done by calling the same new function as above and using the 'next' nonce in the 

``` rust
// update the nonce
let nonce = 1;

let murmur_store = MurmurStore::<EngineTinyBLS377>::new::<
    DummyIdBuilder,
    OsRng,
    ChaCha20Rng,
>(seed.clone(), block_schedule.to_vec(), nonce, double_public, &mut rng)
.unwrap();
```

#### Prepare Execution Parameters

``` rust
```

### Verification

#### Verify Updates

``` rust
```

#### Verify Execution Parameters

``` rust
```

## Build

To build the library, use the following command:

```shell
cargo build
```

The OTP code generator is gated under the "client" feature. To build with this feature enabled, use:

```shell
cargo build --features "client"
```

## Test

To run the tests, use the following command:

```shell
cargo test
```

The OTP code generator is gated under the "client" feature, so run tests with:

```shell
cargo test --features "client"
```

## Future Work/Notes

- **OTPAuth Feature**: There is an 'otpauth' feature that can be enabled on the totp lib. It allows for the inclusion of an issuer and account_name. We can investigate usage of this in the future. [TOTP Library Reference](https://github.com/constantoine/totp-rs/blob/da78569b0c233adbce126dbe0c35452340fd3929/src/lib.rs#L160)
## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the Apache-2.0. See the [LICENSE](../LICENSE) file for details.

## Contact

For any inquiries, please contact [Ideal Labs](https://idealabs.network).