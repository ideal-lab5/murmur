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
use crate::otp::BOTPGenerator;
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
use rand_core::OsRng;
use sha3::Digest;
use beefy::{known_payloads, Payload, Commitment, VersionedFinalityProof};

#[derive(Debug)]
pub enum Error {
    ExecuteError
}

// TODO: create an 'identity builder' trait and inject into the create function
// then remove the dependency on beefy here
// and implement an identity builder in the cli component

/// creates the leaves needed to generate an MMR
/// This function generates otp codes for the given block schedule
/// then it encrypts the resulting codes and constructs leaves 
/// the leaves can be used to generate an MMR
///
pub fn create<E: EngineBLS>(
    seed: Vec<u8>,
    block_schedule: Vec<BlockNumber>,
    ephemeral_msk: [u8;32],
    pk: DoublePublicKey<E>,
) -> Vec<(BlockNumber, Leaf)>  {
    let totp = build_generator(&seed.clone());

    let mut leaves = Vec::new();

    for i in &block_schedule {
        let otp_code = totp.generate(*i);
        let identity = build_identity(*i);
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
        sk: Vec::new(),
    };
    Ok(payload)
}

/// verify the correctness of a proof 
/// e.g. would be called by the pallet/runtime
pub fn verify(
    root: Leaf, 
    otp: String, 
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
        hasher.update(otp.as_bytes().to_vec());
        hasher.update(aux_data);
        let hash = hasher.finalize();

        validity = validity 
            && hash.to_vec() == payload.hash;
    }

    validity
}

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


/// build an identity based on the block number
/// in the future we can consider abstracting this functionality to work with identities constructed in different ways
/// e.g. if we want to support multiple beacons
pub fn build_identity(when: BlockNumber) -> Identity {
    let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
    let commitment = Commitment {
        payload, 
        block_number: when, 
        validator_set_id: 0, // TODO: how to ensure correct validator set ID is used? could just always set to 1 for now, else set input param.
    };
    Identity::new(&commitment.encode())
}

/// build a block-otp generator from the seed
fn build_generator(seed: &[u8]) -> BOTPGenerator {
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(seed);
    let hash = hasher.finalize();
    BOTPGenerator::new(hash.to_vec())
}

mod tests {
    
    use super::*;
    use w3f_bls::{DoublePublicKey, DoublePublicKeyScheme, TinyBLS377};

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

        let leaves = create::<TinyBLS377>(
            seed.clone(),
            schedule,
            ephem_msk,
            double_public,
        );

        assert!(leaves.len() == 3);
    }

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

        let leaves = create::<TinyBLS377>(
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
            leaves,
        ) {
            // we will recalculate the otp code here
            // in practice, the verify function would get the OTP code by using timelock decryption
            // where the ciphertext is provided in the execution payload
            let botp = build_generator(&seed.clone());
            let otp_code = botp.generate(later);

            assert!(verify(expected_root, otp_code, aux_data, payload));
        } else {
            panic!("The test should pass");
        }
    }

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

        let leaves = create::<TinyBLS377>(
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
            leaves,
        ) {
            // we will recalculate the otp code here
            // in practice, the verify function would get the OTP code by using timelock decryption
            // where the ciphertext is provided in the execution payload
            let botp = build_generator(&seed.clone());
            let otp_code = botp.generate(later);
            let bad_aux_data = vec![2,3,4,5,4,3];
            assert!(!verify(expected_root, otp_code, bad_aux_data, payload));
        } else {
            panic!("The test should pass");
        }
    }
}