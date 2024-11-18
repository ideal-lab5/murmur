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

use beefy::{known_payloads, Commitment, Payload};
use murmur_core::types::{Identity, IdentityBuilder};
use rand_core::OsRng;
use serde::Serialize;
use w3f_bls::{DoublePublicKey, SerializableToBytes, TinyBLS377};
use zeroize::Zeroize;

pub use etf::runtime_types::{
	bounded_collections::bounded_vec::BoundedVec, node_template_runtime::RuntimeCall,
};
pub use murmur_core::{
	murmur::{EngineTinyBLS377, Error, MurmurStore},
	types::BlockNumber,
};
use rand_chacha::ChaCha20Rng;
use subxt::ext::codec::Encode;

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "artifacts/metadata.scale")]
pub mod etf {}

/// The BasicIdBuilder builds identities for the default IDN beacon
#[derive(Debug)]
pub struct BasicIdBuilder;
impl IdentityBuilder<BlockNumber> for BasicIdBuilder {
	fn build_identity(when: BlockNumber) -> Identity {
		let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
		let commitment = Commitment {
			payload,
			block_number: when,
			// Note: Currently the validator set id is always set to 0 by the IDN runtime.
			// We have a backlog item to properly update this, which will require
			// that we properly estimate future validator set ids here
			// see: https://github.com/ideal-lab5/pallets/issues/29
			validator_set_id: 0,
		};
		Identity::new(b"", vec![commitment.encode()])
	}
}

#[derive(Serialize)]
/// Data needed to build a valid call for a proxied execution.
pub struct ProxyData {
	pub position: u64,
	/// The hash of the commitment
	pub hash: Vec<u8>,
	/// The timelocked ciphertext
	pub ciphertext: Vec<u8>,
	/// The Merkle proof items
	pub proof_items: Vec<Vec<u8>>,
	/// The size of the Merkle proof
	pub size: u64,
}

/// Create a new MMR and return the data needed to build a valid call for creating a murmur wallet.
///
/// * `seed`: The seed used to generate otp codes
/// * `block_schedule`: A list of block numbers when the wallet will be executable
/// * `round_pubkey_bytes`: The Ideal Network randomness beacon public key
pub fn create(
	mut seed: Vec<u8>,
	nonce: u64,
	block_schedule: Vec<BlockNumber>,
	round_pubkey_bytes: Vec<u8>,
) -> Result<MurmurStore<EngineTinyBLS377>, Error> {
	let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes)
		.map_err(|_| Error::InvalidPubkey)?;

	let mmr_store = MurmurStore::<EngineTinyBLS377>::new::<BasicIdBuilder, OsRng, ChaCha20Rng>(
		seed.clone(),
		block_schedule.clone(),
		nonce,
		round_pubkey,
		&mut OsRng,
	)?;
	seed.zeroize();
	Ok(mmr_store)
}

/// Return the data needed for the immediate execution of the proxied call.
/// * `seed`: The seed used to generate otp codes
/// * `when`: The block number when OTP codeds should be generated
/// * `store`: A murmur store
/// * `call`: Proxied call. Any valid runtime call
pub fn prepare_execute(
	mut seed: Vec<u8>,
	when: BlockNumber,
	store: MurmurStore<EngineTinyBLS377>,
	call: &RuntimeCall,
) -> Result<ProxyData, Error> {
	let (proof, commitment, ciphertext, pos) = store.execute(seed.clone(), when, call.encode())?;
	seed.zeroize();
	let size = proof.mmr_size();
	let proof_items: Vec<Vec<u8>> =
		proof.proof_items().iter().map(|leaf| leaf.0.clone()).collect::<Vec<_>>();

	Ok(ProxyData { position: pos, hash: commitment, ciphertext, proof_items, size })
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_core::{OsRng, SeedableRng};

	#[test]
	pub fn it_can_create_an_mmr_store_and_call_data() {
		let seed = b"seed".to_vec();
		let block_schedule = vec![1, 2, 3, 4, 5, 6, 7];
		let double_public_bytes = murmur_test_utils::get_dummy_beacon_pubkey();
		let mut rng = ChaCha20Rng::from_rng(&mut OsRng).unwrap();
		let mmr_store =
			create(seed.clone(), 0, block_schedule.clone(), double_public_bytes.clone(), &mut rng)
				.unwrap();

		assert_eq!(mmr_store.root.0.len(), 32);
		assert_eq!(mmr_store.metadata.keys().len(), 7);
	}

	#[test]
	pub fn it_can_prepare_valid_execution_call_data() {
		let seed = b"seed".to_vec();
		let block_schedule = vec![1, 2, 3, 4, 5, 6, 7];
		let double_public_bytes = murmur_test_utils::get_dummy_beacon_pubkey();
		let mut rng = ChaCha20Rng::from_rng(&mut OsRng).unwrap();
		let mmr_store =
			create(seed.clone(), 0, block_schedule, double_public_bytes, &mut rng).unwrap();

		let bob = subxt_signer::sr25519::dev::bob().public_key();
		let balance_transfer_call =
			etf::runtime_types::node_template_runtime::RuntimeCall::Balances(
				etf::balances::Call::transfer_allow_death {
					dest: subxt::utils::MultiAddress::<_, u32>::from(bob),
					value: 1,
				},
			);

		let when = 1;

		let proxy_data =
			prepare_execute(seed.clone(), when, mmr_store.clone(), &balance_transfer_call).unwrap();

		assert_eq!(proxy_data.position, 0);
		assert_eq!(proxy_data.hash.len(), 32);
		assert_eq!(proxy_data.ciphertext.len(), 266);
	}
}
