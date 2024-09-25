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
use alloc::{
    vec, 
    vec::Vec,
    collections::BTreeMap,
};

#[cfg(feature = "client")]
use crate::otp::BOTPGenerator;

#[cfg(feature = "client")]
use rand_core::OsRng;

#[cfg(feature = "client")]
use ark_serialize::CanonicalSerialize;

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
        MemStore,
    },
};

use sha3::Digest;

/// Error types for murmur wallet usage
#[derive(Debug)]
pub enum Error {
    ExecuteError,
    MMRError,
}

/// The murmur store contains minimal data required to use a murmur wallet
#[cfg(feature = "client")]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MurmurStore {
    /// A map of block numbers to leaf positions in the mmr
    pub metadata: BTreeMap<BlockNumber, Ciphertext>,
    /// The root of the mmr
    pub root: Leaf,
}

#[cfg(feature = "client")]
impl MurmurStore {

    /// Create a new Murmur store 
    ///
    /// * `seed`: An any-length seed (i.e. password)
    /// * `block_schedule`: The blocks for which OTP codes will be generated
    /// * `ephemeral_msk`: Any 32 bytes
    /// * `round_public_key`: The IDN beacon's public key
    ///
    pub fn new<E: EngineBLS, I: IdentityBuilder<BlockNumber>>(
        seed: Vec<u8>,
        block_schedule: Vec<BlockNumber>,
        ephemeral_msk: [u8;32],
        round_public_key: DoublePublicKey<E>,
    ) -> Self {
        let totp = build_generator(&seed.clone());
        let mut metadata = BTreeMap::new();

        let store = MemStore::default();
        let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);
        
        for i in &block_schedule {
            let otp_code = totp.generate(*i);
            let identity = I::build_identity(*i);
            let ct_bytes = timelock_encrypt::<E>(
                identity,
                round_public_key.1,
                ephemeral_msk,
                otp_code.as_bytes(),
            );
            let leaf = Leaf(ct_bytes.clone());
            let _pos = mmr.push(leaf).expect("todo");//.map_err(|e| {
            metadata.insert(*i, ct_bytes);
        }

       
        MurmurStore {
            metadata,
            root: mmr.get_root().unwrap().clone(),
        }
    }

    /// Build data required (proof and commitment) to execute a valid call from a murmur wallet
    /// note: this rebuilds the entire mmr
    /// we can look into ways to optimize this in the future
    /// the main issue is that he MemStore is not serializable
    /// a possible fix is to externalize mmr logic
    ///
    /// TODO: this should probably be a result, not option
    ///
    /// * `seed`: The seed used to create the mmr
    /// * `when`: The block number when the wallet is being used (or will be)
    /// * `call_data`: The call to be executed with the wallet (at `when`)
    pub fn execute(
        &self, 
        seed: Vec<u8>, 
        when: BlockNumber, 
        call_data: Vec<u8>
    ) -> Option<(MerkleProof::<Leaf, MergeLeaves>, Vec<u8>, Ciphertext, u64)> {
        let mmr = self.to_mmr();
        let commitment = MurmurStore::commit(seed.clone(), when, &call_data.clone());
        // generate the merkle proof here and fetch the ciphertext
        if let Some(ciphertext) = self.metadata.get(&when) {
            let pos = get_key_index(&self.metadata, &when).unwrap() as u64;
            let proof = mmr.gen_proof(vec![pos]).expect("todo: handle error");
            return Some((proof, commitment, ciphertext.clone(), pos));
        }

        None
    }

    /// Generate a commitment (hash) to commit to executing a call at a specific block number
    ///
    /// * `seed`: The seed used to generated the MMR
    /// * `when`: The block number when the commitment is verifiable
    /// * `data`: The data to commit to
    ///
    fn commit(seed: Vec<u8>, when: BlockNumber, data: &[u8]) -> Vec<u8> {
        let botp = build_generator(&seed);
        let otp_code = botp.generate(when);

        let mut hasher = sha3::Sha3_256::default();
        hasher.update(otp_code.as_bytes());
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Builds an mmr from the mmr store
    ///
    /// * `mmr`: a MemMMR instance (to be populated)
    ///
    fn to_mmr(&self) -> MemMMR<Leaf, MergeLeaves> {
        let store = MemStore::default();
        let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);
        for (_block_number, ciphertext) in self.metadata.clone() {
            mmr.push(Leaf(ciphertext)).expect("todo");
        }

        mmr
    }
}

#[cfg(feature = "client")]
/// Timelock encryption helper function
pub fn timelock_encrypt<E: EngineBLS>(
    identity: Identity,
    pk: E::PublicKeyGroup,
    ephemeral_msk: [u8;32],
    message: &[u8],
) -> Vec<u8> {
    let ciphertext = tle::<E, OsRng>(
        pk, 
        ephemeral_msk,
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

// verify the correctness of execution parameters
pub fn verify(
    root: Leaf,
    proof: MerkleProof<Leaf, MergeLeaves>,
    hash: Vec<u8>,
    ciphertext: Vec<u8>,
    otp: Vec<u8>,
    aux_data: Vec<u8>,
    pos: u64,
) -> bool {

    let mut validity = proof.verify(root, vec![(pos, Leaf(ciphertext))])
        .unwrap_or(false);

    if validity {
        // verify the hash
        let mut hasher = sha3::Sha3_256::default();
        hasher.update(otp);
        hasher.update(aux_data);
        let expected_hash = hasher.finalize();

        validity = validity && 
            expected_hash.to_vec() == hash;
    }

    validity
}

/// get the index of a key in a BTreeMap
pub fn get_key_index<K: Ord>(
    b: &BTreeMap<K, impl alloc::fmt::Debug>, 
    key: &K
) -> Option<usize> {
    b.keys().position(|k| k == key)
}

#[cfg(test)]
mod tests {
    
    use super::*;
    use w3f_bls::{DoublePublicKeyScheme, TinyBLS377};

    pub struct DummyIdBuilder;
    impl IdentityBuilder<BlockNumber> for DummyIdBuilder {
        fn build_identity(at: BlockNumber) -> Identity {
            Identity::new(&[at as u8])
        }
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_can_generate_mmr_data_store() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
	    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let ephem_msk = [1;32];
        let seed = vec![1,2,3];
        let schedule = vec![1,2,3];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        );

        assert!(murmur_store.metadata.keys().len() == 3);
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_can_generate_valid_output_and_verify_it() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
	    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let ephem_msk = [1;32];
        let seed = vec![1,2,3];
        let schedule = vec![1,2,3];

        let aux_data = vec![2,3,4,5];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        );

        // the block number when this would execute
        let when = 1;

        let root = murmur_store.root.clone();
        let (proof, commitment, ciphertext, pos) = murmur_store
            .execute(seed.clone(), when, aux_data.clone())
            .unwrap();

        // in practice, the otp code would be timelock decrypted
        // but for testing purposes, we will just calculate the expected one now
        let botp = build_generator(&seed.clone());
        let otp_code = botp.generate(when);

        assert!(verify(
            root,
            proof,
            commitment,
            ciphertext,
            otp_code.as_bytes().to_vec(),
            aux_data,
            pos,
        ));
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_fails_on_verify_bad_aux_data() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
	    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let ephem_msk = [1;32];
        let seed = vec![1,2,3];
        let schedule = vec![1,2,3];

        let aux_data = vec![2,3,4,5];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        );

        // the block number when this would execute
        let when = 1;
        let root = murmur_store.root.clone();
        let (proof, commitment, ciphertext, pos) = murmur_store
            .execute(seed.clone(), when, aux_data.clone())
            .unwrap();


        // in practice, the otp code would be timelock decrypted
        // but for testing purposes, we will just calculate the expected one now
        let botp = build_generator(&seed.clone());
        let otp_code = botp.generate(when);

        let bad_aux = vec![2,3,13,3];
        assert!(!verify(
            root,
            proof,
            commitment,
            ciphertext,
            otp_code.as_bytes().to_vec(),
            bad_aux,
            pos,
        ));
    }
}