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
use serde::Serialize;
use w3f_bls::{DoublePublicKey, SerializableToBytes, TinyBLS377};
use zeroize::Zeroize;

pub use etf::runtime_types::{
	bounded_collections::bounded_vec::BoundedVec, node_template_runtime::RuntimeCall,
};
pub use murmur_core::{
	murmur::{Error, MurmurStore},
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
			validator_set_id: 0, /* TODO: how to ensure correct validator set ID is used? could
			                      * just always set to 1 for now, else set input param. */
		};
		Identity::new(&commitment.encode())
	}
}

#[derive(Serialize)]
/// Data needed to build a valid call for creating a murmur wallet.
pub struct CreateData {
	/// The root of the MMR
	pub root: Vec<u8>,
	/// The size of the MMR
	pub size: u64,
    /// The murmur store (map of block nubmer to ciphertext)
	pub mmr_store: MurmurStore,
    /// The serialized VRF public key
    pub public_key_bytes: Vec<u8>,
    /// The serialized Schnorr signature
    pub proof_bytes: Vec<u8>,
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
	rng: &mut ChaCha20Rng,
) -> Result<MurmurStore, Error> {
	let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes)
		.map_err(|_| Error::InvalidPubkey)?;

	let mmr_store = MurmurStore::new::<TinyBLS377, BasicIdBuilder, ChaCha20Rng>(
		seed.clone(),
		block_schedule.clone(),
		nonce,
		round_pubkey,
		rng,
	)?;
	seed.zeroize();
	Ok(mmr_store)
}

/// Return the data needed for the immediate execution of the proxied call.
/// * `seed`: The seed used to generate otp codes
/// * `when`: The block number when OTP codeds should be generated
/// * `store`: A murmur store
/// * `call`: Proxied call. Any valid runtime call
// Note to self: in the future, we can consider ways to prune the murmurstore as OTP codes are
// consumed     for example, we can take the next values from the map, reducing storage to 0 over
// time     However, to do this we need to think of a way to prove it with a merkle proof
//     my thought is that we would have a subtree, so first we prove that the subtree is indeed in
// the parent MMR     then we prove that the specific leaf is in the subtree.
//  We could potentially use that idea as a way to optimize the execute function in general. Rather
// than  loading the entire MMR into memory, we really only need to load a  minimal subtree
// containing the leaf we want to consume -> add this to the 'future work' section later
pub fn prepare_execute(
	mut seed: Vec<u8>,
	when: BlockNumber,
	store: MurmurStore,
	call: &RuntimeCall,
	rng: &mut ChaCha20Rng,
) -> Result<ProxyData, Error> {
	let (proof, commitment, ciphertext, pos) =
		store.execute(seed.clone(), when, call.encode(), rng)?;
	seed.zeroize();
	let size = proof.mmr_size();
	let proof_items: Vec<Vec<u8>> =
		proof.proof_items().iter().map(|leaf| leaf.0.clone()).collect::<Vec<_>>();

	Ok(ProxyData { position: pos, hash: commitment, ciphertext, proof_items, size })
}

#[cfg(test)]
mod tests {
	use super::*;

	use super::*;
	use rand_core::{OsRng, SeedableRng};

	#[test]
	pub fn it_can_create_an_mmr_store_and_call_data() {
		let name = b"name".to_vec();
		let seed = b"seed".to_vec();
		let block_schedule = vec![1, 2, 3, 4, 5, 6, 7];
		let double_public_bytes = murmur_test_utils::get_dummy_beacon_pubkey();
		let mut rng = ChaCha20Rng::from_rng(&mut OsRng).unwrap();
		let mmr_store =
			create(seed.clone(), 0, block_schedule.clone(), double_public_bytes.clone(), &mut rng)
            .unwrap();

		// let mmr_store = MurmurStore::new::<TinyBLS377, BasicIdBuilder, ChaCha20Rng>(
		// 	seed,
		// 	block_schedule,
		// 	0,
		// 	DoublePublicKey::<TinyBLS377>::from_bytes(&double_public_bytes).unwrap(),
        //     &mut rng,
		// ).unwrap();

		assert_eq!(mmr_store.root.0.len(), 32);
		assert_eq!(mmr_store.size, 7);
	}

	#[test]
	pub fn it_can_prepare_valid_execution_call_data() {
		let name = b"name".to_vec();
		let seed = b"seed".to_vec();
		let block_schedule = vec![1, 2, 3, 4, 5, 6, 7];
		let double_public_bytes = murmur_test_utils::get_dummy_beacon_pubkey();
		let mut rng = ChaCha20Rng::from_rng(&mut OsRng).unwrap();
		let mmr_store = create(
            seed.clone(), 
            0, 
            block_schedule, 
            double_public_bytes, 
            &mut rng
        ).unwrap();

		// let size = proof.mmr_size();
		// let proof_items: Vec<Vec<u8>> =
		// 	proof.proof_items().iter().map(|leaf| leaf.0.clone()).collect::<Vec<_>>();

        let bob = subxt_signer::sr25519::dev::bob().public_key();
		let balance_transfer_call =
			etf::runtime_types::node_template_runtime::RuntimeCall::Balances(
				etf::balances::Call::transfer_allow_death {
					dest: subxt::utils::MultiAddress::<_, u32>::from(bob),
					value: 1,
				},
			);

        let bob2 = subxt_signer::sr25519::dev::bob().public_key();
        let balance_transfer_call_2 =
            etf::runtime_types::node_template_runtime::RuntimeCall::Balances(
                etf::balances::Call::transfer_allow_death {
                    dest: subxt::utils::MultiAddress::<_, u32>::from(bob2),
                    value: 1,
                },
            );

		let when = 1;

		let proxy_data = prepare_execute(
			seed.clone(),
			when,
			mmr_store.clone(),
			&balance_transfer_call,
			&mut rng,
		)
		.unwrap();

		// let (proof, commitment, ciphertext, _pos) = create_data.mmr_store
		// 	.execute(seed.clone(), when, balance_transfer_call_2.encode(), &mut rng)
		// 	.unwrap();
        // let expected_commitment = [71, 71, 72, 200, 197, 44, 120, 151, 127, 6, 162, 244, 138, 122, 196, 183, 30, 47, 111, 239, 225, 32, 57, 141, 186, 229, 164, 113, 113, 44, 131, 168];
        // let expected_ciphertext = [76, 42, 82, 184, 114, 58, 31, 205, 146, 16, 41, 191, 126, 213, 18, 65, 42, 149, 78, 140, 243, 164, 39, 54, 13, 96, 159, 93, 200, 83, 227, 179];
		// let size = proof.mmr_size();
		// let proof_items: Vec<Vec<u8>> =
		// 	proof.proof_items().iter().map(|leaf| leaf.0.clone()).collect::<Vec<_>>();
		assert_eq!(proxy_data.position, 0);
		assert_eq!(proxy_data.hash.len(), 32);
		assert_eq!(proxy_data.ciphertext.len(), 266);
		// assert_eq!(proxy_data.proof_items, proof_items);
		// assert_eq!(proxy_data.size, size);
	}
}
