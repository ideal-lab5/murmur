# Murmur Core

This library contains the core implementation of the Murmur protocol. This implementation can support both BLS12-377 and BLS12-381, but is left curve-agnostic. This crate can support the randomness beacon produced by the [Ideal Network](https://idealabs.network) as well as [Drand](https://drand.love)'s Quicknet. In general, this library is intended to work with a blockchain whose runtime includes the corresponding [Murmur Pallet](https://github.com/ideal-lab5/idn-sdk/tree/main/pallets/murmur). More specifcially, it is intended to run against the [Ideal Network](https://idealabs.network). For examples of usage against the Ideal Network, refer to the [CLI](../lib/src/bin/murmur/main.rs).

## Usage

### Create, Update, Execute

To create and update murmur wallets, you must define an `IdentityBuilder`. The [BasicIdentityBuilder](../lib/src/lib.rs) struct implements allows for the construction of valid identities on the Ideal Network. In the future, we will add support for Drand's Quicknet as well.

#### Create a Murmur Store

``` rust
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;
use murmur_core::{
	murmur::{EngineTinyBLS377, Error, MurmurStore},
};
use w3f_bls::{DoublePublicKeyScheme, KeypairVT, TinyBLS377};

// This simulates the production of a randomness beacon public key
// In practice, this would be fetched from the beacon (e.g. as a hex string) and must be deseraialized
let keypair = KeypairVT::<TinyBLS377>::generate(&mut rng);
let double_public: DoublePublicKey<TinyBLS377> =
    DoublePublicKey(keypair.into_public_key_in_signature_group().0, keypair.public.0);

// The 'lifetime' of the Murmur wallet for the given session
// This corresponds to future rounds of the randomness beacon
// for which timelocked commitments can be made
let schedule = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

// This is your 'secret' seed, a short password used while constructing OTP codes
let seed = vec![1, 2, 3];

// The nonce functions similarly to nonce's for standard accounts, except instead of updating on a 
// "per transaction" basis, it only updates on a "per session" basis
// 
let nonce = 0;

let murmur_store = MurmurStore::<EngineTinyBLS377>::new::<
    BasicIdentityBuilder,
    OsRng,
    ChaCha20Rng,
>(seed.clone(), schedule.to_vec(), nonce, double_public, &mut rng)
.unwrap();
```
#### Update a Murmur Store

Updating a Murmur store is done by calling the same new function as above and incrementing the previous nonce by 1. The data any single MMR can contain is finite, so when a Murmur wallet is created it can only be functional for a finite number of blocks (the block schedule). In this sense, Murmur is a "session-based" wallet. To ensure wallet lifetimes can be extended, Murmur wallets can be updated by generated a new Murmur store and submitting the result to a system that implements a verifier (see below). More specifically, when a Murmur store is created a DLEQ proof is generated (Discrete Log Equivalence Proof - a type of zkp) and attached to the store. This proof allows the Murmur store creator to convince a verifier that it knows the secret input (seed) without exposing it.

``` rust
// Compute the next nonce
let nonce = 1;
// Construct a new murmur store
let murmur_store = MurmurStore::<EngineTinyBLS377>::new::<
    BasicIdentityBuilder,
    OsRng,
    ChaCha20Rng,
>(seed.clone(), block_schedule.to_vec(), nonce, double_public, &mut rng)
.unwrap();
```

#### Prepare Execution Parameters

This library allows for arbitary payloads to be strictly associated with the reveal of a future OTP code. That is, given an OTP created for a future round r, it allows for the creation of a commitment to that data that cannot be verified until the future round `r` happens and the beacon outputs a signature allowing for decryption of the OTP code. We can consider this a form of `timelocked` commitments.

``` rust
// The round when the commitment will be verifiable
let when = 156921;
// Generates a Merkle proof, the hash Sha256(OTP || aux_data),
// the timelocked OTP code ciphertext and its position in the MMR.
// This data is used later on by the verifier to verify the commitment.
let (proof, commitment, ciphertext, pos) =
			murmur_store.execute(seed.clone(), when, aux_data.clone()).unwrap();
```

### Verification

The verifier module provides functionality to verify Murmur store data and timelocked commitments. In general, this would be executed by whichever actor in the system implementing Murmur has agency to directly manipulate the system or otherwise proxy user input to meaningful actions. This is intended to be run in trustless systems, specifically in the context of a blockchain runtime.

#### Verify Updates

When a Murmur store is updated, a DLEQ proof is generated and attached to the store. This is intended to allow the creator of the Murmur store to prove that they know the secret inputs without revealing them, allowing them to update the Murmur store whenever they need to. The `verify_update` function verifies the DLEQ proof. If it is true, then the prover (Murmur store creator) has convinced the verifier (e.g. Blockchain Runtime) that it was generated with the same seed. 

``` rust
verifier::verify_update::<TinyBLS377>(proof, public_key, nonce).unwrap()
```

#### Verify Execution Parameters

This function allows for "tmelocked" commitments to be verified. The OTP input should be the timelock decrypted ciphertext. More specifically, it:
1) Verified a Merkle proof to prove that the ciphertext is indeed at the given position in the MMR defined by the given root.
2) reconstructs the commitment and compares it against the given one

``` rust
verifier::verify_execute(
    root, proof, commitment, ciphertext, OTP, &aux_data, pos,
);
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