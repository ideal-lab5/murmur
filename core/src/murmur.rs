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
    string::String, vec, 
    vec::Vec,
    collections::BTreeMap,
};

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
    ExecuteError,
    MMRError,
}

#[cfg(feature = "client")]
#[derive(Debug)]
pub struct MurmurStore {
    /// the seed used to create the store (should we even keep it here?) probably not...
    seed: Vec<u8>,
    /// a store of block numbers to ciphertexts (encrypted OTP codes)
    /// Q: how large is each ciphertext?
    pub data: BTreeMap<BlockNumber, Ciphertext>,
}

#[cfg(feature = "client")]
impl MurmurStore {

    pub fn from(
        seed: Vec<u8>, 
        data: BTreeMap<BlockNumber, Ciphertext>
    ) -> Self {
        MurmurStore {
            seed,
            data,
        }
    }

    /// creates the leaves needed to generate an MMR
    /// This function generates otp codes for the given block schedule
    /// then it encrypts the resulting codes and constructs leaves 
    /// the leaves can be used to generate an MMR
    ///
    #[cfg(feature = "client")]
    pub fn new<E: EngineBLS, I: IdentityBuilder<BlockNumber>>(
        seed: Vec<u8>,
        block_schedule: Vec<BlockNumber>,
        ephemeral_msk: [u8;32],
        pk: DoublePublicKey<E>,
    ) -> Self {
        let totp = build_generator(&seed.clone());

        let mut mmr_store = BTreeMap::new();

        for i in &block_schedule {
            let otp_code = totp.generate(*i);
            let identity = I::build_identity(*i);
            let ct_bytes = timelock_encrypt::<E>(
                identity,
                pk.1,
                ephemeral_msk,
                otp_code.as_bytes(),
            );
            mmr_store.insert(*i, ct_bytes);
        }
        
        MurmurStore {
            seed,
            data: mmr_store,
        }
    }

    pub fn get(&self, when: BlockNumber) -> Option<Ciphertext> {
        self.data.get(&when).cloned()
    }

    /// use the seed to commit to some data at a specific block number
    /// i.e. this commit cannot be verified until there is a signature
    ///      output from IDN for `when`
    pub fn commit(&self, when: BlockNumber, data: &[u8]) -> Vec<u8> {
        let botp = build_generator(&self.seed);
        let otp_code = botp.generate(when);

        let mut hasher = sha3::Sha3_256::default();
        hasher.update(otp_code.as_bytes());
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    // builds an mmr from the mmr store
    ///
    /// * `mmr`: a MemMMR instance 
    ///
    pub fn to_mmr(&self, mmr: &mut MemMMR::<Leaf, MergeLeaves>) -> Result<(), Error> {
        self.data.iter().for_each(|elem| {
            let leaf = Leaf::from(elem.1.clone());
            mmr.push(leaf).map_err(|e| {
                return Error::MMRError;
            });
        });

        Ok(())
    }
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

// verify the correctness of execution parameters
// e.g. would be called by the pallet/runtime
// this function assumes that the otp is the timelock decryption result
// of decrypting the ciphertext
// I don't know if I like this design, could move decryption
// inside this function maybe? not sure...
pub fn verify(
    root: Leaf,
    proof: MerkleProof<Leaf, MergeLeaves>,
    hash: Vec<u8>,
    ciphertext: Vec<u8>,
    otp: Vec<u8>,
    aux_data: Vec<u8>,
    pos: u64,
) -> bool {

    let mut validity = proof.verify(root, vec![(pos, Leaf::from(ciphertext))])
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

mod tests {
    
    use super::*;
    use w3f_bls::{DoublePublicKey, DoublePublicKeyScheme, TinyBLS377};
    use ckb_merkle_mountain_range::helper::leaf_index_to_pos;

    pub struct DummyIdBuilder;
    impl IdentityBuilder<BlockNumber> for DummyIdBuilder {
        fn build_identity(at: BlockNumber) -> Identity {
            Identity::new(&[at as u8])
        }
    }

    fn get_key_index<K: Ord>(b: &BTreeMap<K, impl alloc::fmt::Debug>, key: &K) -> Option<usize> {
        b.keys().position(|k| k == key)
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_can_generate_mmr_data_store() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
	    // let msk = keypair.secret.0; // can destroy this
	    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let ephem_msk = [1;32];
        let seed = vec![1,2,3];
        let schedule = vec![1,2,3];

        let datastore = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        );

        assert!(datastore.data.len() == 3);
        assert!(datastore.data.get(&schedule.clone()[0]).is_some());
        assert!(datastore.data.get(&schedule.clone()[1]).is_some());
        assert!(datastore.data.get(&schedule.clone()[2]).is_some());
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

        let ephem_msk = [1;32];
        let seed = vec![1,2,3];
        let schedule = vec![1,2,3];
        let aux_data = vec![3,4,3];
        let when = 2;

        let datastore = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        );

        let hash = datastore.commit(when, &aux_data);

        let store = MemStore::default();
        let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);
        datastore.to_mmr(&mut mmr).unwrap();

        let ciphertext = datastore.get(when).unwrap();
        let pos: u64 = get_key_index(&datastore.data, &when).unwrap() as u64;
        // let pos: u64 = leaf_index_to_pos(idx as u64);

        let proof = mmr.gen_proof(vec![pos])
            .expect("todo: handle error");

        let root = mmr.get_root().expect("the root should be able to be calculated");

        // in practice, the otp code would be timelock decrypted
        // but for testing purposes, we will just calculate the expected one now
        let botp = build_generator(&seed.clone());
        let otp_code = botp.generate(when);

        assert!(verify(
            root,
            proof,
            hash,
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
	    // let msk = keypair.secret.0; // can destroy this
	    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
		    keypair.into_public_key_in_signature_group().0,
		    keypair.public.0,
	    );

        let ephem_msk = [1;32];
        let seed = vec![1,2,3];
        let schedule = vec![1,2,3];
        let aux_data = vec![3,4,3];
        let when = 2;

        let datastore = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        );

        let hash = datastore.commit(when, &aux_data);

        let store = MemStore::default();
        let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);
        datastore.to_mmr(&mut mmr).unwrap();

        let ciphertext = datastore.get(when).unwrap();
        let pos: u64 = get_key_index(&datastore.data, &when).unwrap() as u64;
        // let pos: u64 = leaf_index_to_pos(idx as u64);

        let proof = mmr.gen_proof(vec![pos])
            .expect("todo: handle error");

        let root = mmr.get_root().expect("the root should be able to be calculated");

        // in practice, the otp code would be timelock decrypted
        // but for testing purposes, we will just calculate the expected one now
        let botp = build_generator(&seed.clone());
        let otp_code = botp.generate(when);

        let bad_aux = vec![4,4,4,4,4,4];

        assert!(!verify(
            root,
            proof,
            hash,
            ciphertext,
            otp_code.as_bytes().to_vec(),
            bad_aux,
            pos,
        ));
    }
}