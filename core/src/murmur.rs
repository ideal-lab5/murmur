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

use alloc::{vec, vec::Vec};
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
use beefy::{
    known_payloads, 
    Payload, 
    Commitment,
};
use codec::Encode;
use rand_core::OsRng;
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
        let ct_bytes = timelock_encrypt::<E>(
            *i,
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
/// outputs (ciphertext, hash, merkle proof, position/index)
/// TODO: create a new struct to represent return type
pub fn execute<E: EngineBLS>(
    seed: Vec<u8>,
    when: BlockNumber,
    call_data: Vec<u8>,
    leaves: Vec<(BlockNumber, Leaf)>,
) -> Result<(Leaf, Vec<u8>,  MerkleProof<Leaf, MergeLeaves>, Leaf, u64), Error> {
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
    hasher.update(&call_data);
    let hash = hasher.finalize().to_vec();

    Ok((root, hash, proof, target_leaf, target_pos))
}

/// timelock encryption function
pub fn timelock_encrypt<E: EngineBLS>(
    when: BlockNumber,
    pk: E::PublicKeyGroup,
    ephemeral_msk: [u8;32],
    message: &[u8],
) -> Vec<u8> {
    let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
    let commitment = Commitment {
        payload, 
        block_number: when, 
        validator_set_id: 0, // TODO: how to ensure correct validator set ID is used? could just always set to 1 for now, else set input param.
    };
    let ciphertext = tle::<E, OsRng>(
        pk.clone(), 
        ephemeral_msk.clone(),
        message,
        Identity::new(&commitment.encode()),
        OsRng, // TODO
    ).unwrap(); // TODO: Error Handling
    let mut ct_bytes = Vec::new();
    ciphertext.serialize_compressed(&mut ct_bytes).unwrap();
    ct_bytes
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
    pub fn it_can_generate_valid_merkle_proofs_and_hashes() {
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

        let later = 1;
        // generate execution parameters
        if let Ok(result) = execute::<TinyBLS377>(
            seed,
            later,
            vec![1,2,3], // aux data (call data in practice)
            leaves,
        ) {
            let root: Leaf = result.0;
            let hash: Vec<u8> = result.1;
            let original_proof: MerkleProof<Leaf, MergeLeaves> = result.2;
            let target_leaf: Leaf = result.3;
            let pos: u64 = result.4;
            

            // experiment w/ serialization
            let proof_items: Vec<Vec<u8>> = original_proof.proof_items().iter()
                .map(|leaf| leaf.0.to_vec().clone())
                .collect::<Vec<_>>();
            // convert to leaves
            let leaves: Vec<Leaf> = proof_items.clone().into_iter().map(|p| Leaf(p)).collect::<Vec<_>>();
            assert_eq!(leaves, original_proof.proof_items().to_vec());

            let proof = MerkleProof::<Leaf, MergeLeaves>::new(schedule.clone().len() as u64, leaves);
            assert_eq!(proof.proof_items(), original_proof.proof_items());
            // let root = Leaf::from(proxy_details.root);
            let target = vec![(pos, target_leaf.clone())];
            let new_root = proof.calculate_root(target.clone()).unwrap();

            match proof.verify(new_root, target.clone()) {
                Ok(validity) => {
                    assert!(validity);
                },
                Err(e) => {
                    panic!("The test failed with error: {:?}", e);
                }
            }
            // then we verify the hash
        } else {
            panic!("The test should pass");
        }
    }
}