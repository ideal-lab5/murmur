/*
 * Copyright 2024 by Ideal Labs, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![no_std]

//! various utilities helpful for testing

use alloc::vec::Vec;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, Rng};
use rand_core::OsRng;
use ark_ec::CurveGroup;
use w3f_bls::{DoublePublicKey, DoublePublicKeyScheme, EngineBLS, TinyBLS377};
use dleq_vrf::SecretKey;

extern crate alloc;

pub use murmur_core::otp::BOTPGenerator;

pub use murmur_core::murmur::MurmurStore;

pub use murmur_core::murmur::generate_witness;

pub fn otp<E: EngineBLS, R: Rng + CryptoRng + Sized>(
	seed: Vec<u8>, 
	when: u64, 
	rng: &mut R
) -> Vec<u8> {
	let witness = generate_witness(seed.clone(), rng);
	let secret_key = 
		SecretKey::<<E::SignatureGroup as CurveGroup>::Affine>::from_seed(&witness);
	let pubkey = secret_key.as_publickey();
	let mut pubkey_bytes = Vec::new();
	pubkey.serialize_compressed(&mut pubkey_bytes).unwrap();
	let totp = BOTPGenerator::new(witness.to_vec()).unwrap();
	totp.generate(when).as_bytes().to_vec()
}

pub fn get_dummy_beacon_pubkey() -> Vec<u8> {
	let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
	let double_public: DoublePublicKey<TinyBLS377> =
		DoublePublicKey(keypair.into_public_key_in_signature_group().0, keypair.public.0);
	let mut bytes = Vec::new();
	double_public.serialize_compressed(&mut bytes).unwrap();
	bytes
}
