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

//! The murmur protocol implementation
//!

use alloc::{string::String, vec, vec::Vec};

#[cfg(feature = "client")]
use crate::otp::BOTPGenerator;

#[cfg(feature = "client")]
use rand_core::OsRng;

use crate::types::*;
use etf_crypto_primitives::{
    ibe::fullident::Identity,
    encryption::tlock::*
};
use w3f_bls::{DoublePublicKey, EngineBLS};
use ckb_merkle_mountain_range::{
    MerkleProof,
    util::{
        MemMMR,
        MemStore
    },
};
use ark_serialize::CanonicalSerialize;
use codec::Encode;
use sha3::Digest;

#[derive(Debug)]
pub enum Error {
    ExecuteError
}

/// creates the leaves needed to generate an MMR
/// This function generates otp codes for the given block schedule
/// then it encrypts the resulting codes and constructs leaves 
/// the leaves can be used to generate an MMR
///
#[cfg(feature = "client")]
pub fn create<E: EngineBLS, I: IdentityBuilder<BlockNumber>>(
    seed: Vec<u8>,
    block_schedule: Vec<BlockNumber>,
    ephemeral_msk: [u8;32],
    pk: DoublePublicKey<E>,
) -> Vec<(BlockNumber, Leaf)> {
    let totp = build_generator(&seed.clone());

    let mut leaves = Vec::new();

    for i in &block_schedule {
        let otp_code = totp.generate(*i);
        let identity = I::build_identity(*i);
        let ct_bytes = timelock_encrypt::<E>(
            identity,
            pk.1,
            ephemeral_msk,
            otp_code.as_bytes(),
        );
        let leaf = Leaf::from(ct_bytes);
        leaves.push((*i, leaf));
    }
    
    leaves
}

/// computes parameters needed to execute a transaction at the specified block number
/// outputs a payload containing: (ciphertext, hash, merkle proof, position/index)
#[cfg(feature = "client")]
pub fn execute<E: EngineBLS>(
    seed: Vec<u8>,
    when: BlockNumber,
    aux_data: Vec<u8>,
    leaves: Vec<(BlockNumber, Leaf)>,
) -> Result<ExecutionPayload, Error> {
    // rebuild the MMR and search for the position of the leaf for the given block number
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);

    let mut target_pos: u64 = 0;
    let mut target_leaf: Leaf = Leaf::default();

    leaves.into_iter().for_each(|leaf_data| {
        let leaf = leaf_data.1;
        let block_num = leaf_data.0;
        let pos = mmr.push(leaf.clone()).unwrap();
        if block_num == when  {
            target_pos = pos;
            target_leaf = leaf;
        }
    });

    // prepare merkle proof
    let root = mmr.get_root()
        .expect("The MMR root should be calculable");
    let proof = mmr.gen_proof(vec![target_pos])
        .expect("should be ok");

    // hash(otp || AUX_DATA)
    let botp = build_generator(&seed.clone());
    let otp_code = botp.generate(when);
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(otp_code.as_bytes());
    hasher.update(&aux_data);
    let hash = hasher.finalize().to_vec();

    let payload = ExecutionPayload {
        root,
        proof,
        target: target_leaf,
        pos: target_pos,
        hash,
    };
    Ok(payload)
}

/// verify the correctness of a proof 
/// e.g. would be called by the pallet/runtime
pub fn verify(
    root: Leaf, 
    otp: Vec<u8>, 
    aux_data: Vec<u8>, 
    payload: ExecutionPayload
) -> bool {
    // verify the merkle proof
    let proof = payload.proof;
    let pos = payload.pos;
    let target = payload.target;

    let mut validity = proof.verify(root, vec![(pos, target)])
        .unwrap_or(false);

    if validity {
        // verify the hash
        let mut hasher = sha3::Sha3_256::default();
        hasher.update(otp);
        hasher.update(aux_data);
        let hash = hasher.finalize();

        validity = validity 
            && hash.to_vec() == payload.hash;
    }

    validity
}

#[cfg(feature = "client")]
/// timelock encryption function
pub fn timelock_encrypt<E: EngineBLS>(
    identity: Identity,
    pk: E::PublicKeyGroup,
    ephemeral_msk: [u8;32],
    message: &[u8],
) -> Vec<u8> {
    let ciphertext = tle::<E, OsRng>(
        pk.clone(), 
        ephemeral_msk.clone(),
        message,
        identity,
        OsRng, // TODO
    ).unwrap(); // TODO: Error Handling
    let mut ct_bytes = Vec::new();
    ciphertext.serialize_compressed(&mut ct_bytes).unwrap();
    ct_bytes
}

/// build a block-otp generator from the seed
#[cfg(feature = "client")]
fn build_generator(seed: &[u8]) -> BOTPGenerator {
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(seed);
    let hash = hasher.finalize();
    BOTPGenerator::new(hash.to_vec())
}

mod tests {
    
    use super::*;
    use w3f_bls::{DoublePublicKey, DoublePublicKeyScheme, TinyBLS377};

    pub struct DummyIdBuilder;
    impl IdentityBuilder<BlockNumber> for DummyIdBuilder {
        fn build_identity(at: BlockNumber) -> Identity {
            Identity::new(&[at as u8])
        }
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_can_generate_leaves() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
	    // let msk = keypair.secret.0; // can destroy this
	    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let ephem_msk = [1;32];
        let seed = vec![1,2,3];
        let schedule = vec![1,2,3];

        let leaves = create::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule,
            ephem_msk,
            double_public,
        );

        assert!(leaves.len() == 3);
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_can_generate_valid_output_and_verify_it() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
	    // let msk = keypair.secret.0; // can destroy this
	    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let double_public_again: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let ephem_msk = [1;32];
        let seed = vec![1,2,3];
        let schedule = vec![1,2,3];

        let leaves = create::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        );

        // precompute a root here
        // this is the expected root when we attempt to call verify
        let store = MemStore::default();
        let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);
    
        leaves.clone().into_iter().for_each(|leaf_data| {
            mmr.push(leaf_data.1.clone()).unwrap();
        });
    
        // prepare merkle proof
        let expected_root = mmr.get_root().expect("The MMR root should be calculable");
        let aux_data = vec![1,2,3];

        let later = 1;
        // generate execution parameters
        if let Ok(payload) = execute::<TinyBLS377>(
            seed.clone(),
            later,
            aux_data.clone(),
            leaves.clone(),
        ) {
            // we will recalculate the otp code here
            // in practice, the verify function would get the OTP code by using timelock decryption
            // where the ciphertext is provided in the execution payload
            let botp = build_generator(&seed.clone());
            let otp_code = botp.generate(later);

            // lets check if we can serialize/deserialize the proof and still verify it
            let proof_items: Vec<Vec<u8>> = payload.proof.proof_items().iter()
                .map(|leaf| leaf.0.to_vec().clone())
                .collect::<Vec<_>>();
            let proof_leaves: Vec<Leaf> = proof_items.clone().into_iter().map(|p| Leaf(p)).collect::<Vec<_>>();
			// rebuild the proofs
			let merkle_proof = MerkleProof::<Leaf, MergeLeaves>::new(leaves.len() as u64, proof_leaves);

            let execution_payload = ExecutionPayload {
                root: expected_root.clone(),
                proof: merkle_proof,
                target: payload.target.clone(),
                pos: payload.pos.clone(),
                hash: payload.hash.clone(),
            };

            let validity = verify(expected_root.clone(), otp_code.as_bytes().to_vec(), aux_data.clone(), execution_payload);
            assert!(validity);
            assert!(verify(expected_root, otp_code.as_bytes().to_vec(), aux_data, payload));
        } else {
            panic!("The test should pass");
        }
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_fails_on_verify_bad_aux_data() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
	    // let msk = keypair.secret.0; // can destroy this
	    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let double_public_again: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let ephem_msk = [1;32];
        let seed = vec![1,2,3];
        let schedule = vec![1,2,3];

        let leaves = create::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        );

        // precompute a root here
        // this is the expected root when we attempt to call verify
        let store = MemStore::default();
        let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);
    
        leaves.clone().into_iter().for_each(|leaf_data| {
            mmr.push(leaf_data.1.clone()).unwrap();
        });
    
        // prepare merkle proof
        let expected_root = mmr.get_root().expect("The MMR root should be calculable");
        let aux_data = vec![1,2,3];

        let later = 1;
        // generate execution parameters
        if let Ok(payload) =  execute::<TinyBLS377>(
            seed.clone(),
            later,
            aux_data.clone(),
            leaves,
        ) {
            // we will recalculate the otp code here
            // in practice, the verify function would get the OTP code by using timelock decryption
            // where the ciphertext is provided in the execution payload
            let botp = build_generator(&seed.clone());
            let otp_code = botp.generate(later);
            let bad_aux_data = vec![2,3,4,5,4,3];
            assert!(!verify(expected_root, otp_code.as_bytes().to_vec(), bad_aux_data, payload));
        } else {
            panic!("The test should pass");
        }
    }
}