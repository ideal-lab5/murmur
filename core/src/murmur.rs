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
use alloc::{collections::BTreeMap, vec, vec::Vec};

#[cfg(feature = "client")]
use crate::otp::BOTPGenerator;

use rand_chacha::ChaCha20Rng;
use ark_std::rand::SeedableRng;
use ark_std::rand::{CryptoRng, Rng};

#[cfg(feature = "client")]
use zeroize::Zeroize;

#[cfg(feature = "client")]
use ark_serialize::CanonicalSerialize;

use crate::types::*;
use ckb_merkle_mountain_range::{
    helper::leaf_index_to_pos,
    util::{MemMMR, MemStore},
    MerkleProof,
};
use etf_crypto_primitives::{encryption::tlock::*, ibe::fullident::Identity};
use sha3::Digest;
use w3f_bls::{DoublePublicKey, EngineBLS};

/// Error types for murmur wallet usage
#[derive(Debug, PartialEq)]
pub enum Error {
    ExecuteError,
    MMRError,
    InconsistentStore,
    /// No leaf could be identified in the MMR at the specified position
    NoLeafFound,
    /// No ciphertext could be identified for the block within the current murmur store
    NoCiphertextFound,
    /// There was an error when executing timelock encryption (is the ciphertext too large?)
    TlockFailed,
    /// The buffer does not have enough space allocated
    InvalidBufferSize,
    /// The seed was invalid 
    InvalidSeed,
    /// The public key was invalid (could not be decoded)
    InvalidPubkey,
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
        mut seed: Vec<u8>,
        block_schedule: Vec<BlockNumber>,
        mut ephemeral_msk: [u8; 32],
        round_public_key: DoublePublicKey<E>,
    ) -> Result<Self, Error> {
        let totp = build_generator(seed.clone())?;
        seed.zeroize();
        let mut metadata = BTreeMap::new();

        let store = MemStore::default();
        let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);

        for i in &block_schedule {
            let otp_code = totp.generate(*i);
            let identity = I::build_identity(*i);

            // we need to seed a new rng here
            let mut hasher = sha3::Sha3_256::default();
            hasher.update(ephemeral_msk.to_vec().clone());
            hasher.update(otp_code.as_bytes().to_vec().clone());
            let hash = hasher.finalize();

            let ephem_rng = ChaCha20Rng::from_seed(hash.into());
            let ct_bytes = timelock_encrypt::<E, ChaCha20Rng>(
                identity,
                round_public_key.1,
                ephemeral_msk,
                otp_code.as_bytes(),
                ephem_rng,
            )?;
            let leaf = Leaf(ct_bytes.clone());
            // Q: How can I test this?
            // https://github.com/nervosnetwork/merkle-mountain-range/blob/9e77d3ef81ddfdd9b7dd9583762582e859849dde/src/mmr.rs#L60
            let _pos = mmr.push(leaf).map_err(|_| Error::InconsistentStore)?;
            metadata.insert(*i, ct_bytes);
        }

        ephemeral_msk.zeroize();
        let root = mmr.get_root().map_err(|_| Error::InconsistentStore)?;

        Ok(MurmurStore { metadata, root })
    }

    /// Build data required (proof and commitment) to execute a valid call from a murmur wallet
    ///
    /// * `seed`: The seed used to create the mmr
    /// * `when`: The block number when the wallet is being used (or will be)
    /// * `call_data`: The call to be executed with the wallet (at `when`)
    ///
    pub fn execute(
        &self,
        mut seed: Vec<u8>,
        when: BlockNumber,
        call_data: Vec<u8>,
    ) -> Result<(MerkleProof<Leaf, MergeLeaves>, Vec<u8>, Ciphertext, u64), Error> {
        if let Some(ciphertext) = self.metadata.get(&when) {
            let commitment = MurmurStore::commit(seed.clone(), when, &call_data.clone())?;
            seed.zeroize();
            let idx = get_key_index(&self.metadata, &when)
                .expect("The key must exist within the metadata.");
            let pos = leaf_index_to_pos(idx as u64);
            let mmr = self.to_mmr()?;
            let proof = mmr
                .gen_proof(vec![pos])
                .map_err(|_| Error::InconsistentStore)?;
            return Ok((proof, commitment, ciphertext.clone(), pos));
        }

        Err(Error::NoCiphertextFound)
    }

    /// Generate a commitment (hash) to commit to executing a call at a specific block number
    ///
    /// * `seed`: The seed used to generated the MMR
    /// * `when`: The block number when the commitment is verifiable
    /// * `data`: The data to commit to
    ///
    fn commit(mut seed: Vec<u8>, when: BlockNumber, data: &[u8]) -> Result<Vec<u8>, Error> {
        let botp = build_generator(seed.clone())?;
        seed.zeroize();
        let otp_code = botp.generate(when);

        let mut hasher = sha3::Sha3_256::default();
        hasher.update(otp_code.as_bytes());
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    /// Builds an mmr from the mmr store
    ///
    /// * `mmr`: a MemMMR instance (to be populated)
    ///
    fn to_mmr(&self) -> Result<MemMMR<Leaf, MergeLeaves>, Error> {
        let store = MemStore::default();
        let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);
        for (_block_number, ciphertext) in self.metadata.clone() {
            mmr.push(Leaf(ciphertext))
                .map_err(|_| Error::InconsistentStore)?;
        }

        Ok(mmr)
    }
}

#[cfg(feature = "client")]
/// Timelock encryption helper function
pub fn timelock_encrypt<E: EngineBLS, R: CryptoRng + Rng + Sized>(
    identity: Identity,
    pk: E::PublicKeyGroup,
    ephemeral_msk: [u8; 32],
    message: &[u8],
    rng: R,
) -> Result<Vec<u8>, Error> {
    let ciphertext = tle::<E, R>(pk, ephemeral_msk, message, identity, rng)
        .map_err(|_| Error::TlockFailed)?;
    let mut ct_bytes = Vec::new();
    ciphertext
        .serialize_compressed(&mut ct_bytes)
        .map_err(|_| Error::InvalidBufferSize)?;
    Ok(ct_bytes)
}

/// Build a block-otp generator from the seed
#[cfg(feature = "client")]
fn build_generator(mut seed: Vec<u8>) -> Result<BOTPGenerator, Error> {
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(&seed);
    seed.zeroize();
    let hash = hasher.finalize();
    BOTPGenerator::new(hash.to_vec())
        .map_err(|_| Error::InvalidSeed)
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
    let mut validity = proof
        .verify(root, vec![(pos, Leaf(ciphertext))])
        .unwrap_or(false);

    if validity {
        let mut hasher = sha3::Sha3_256::default();
        hasher.update(otp);
        hasher.update(aux_data);
        let expected_hash = hasher.finalize();

        validity = validity && expected_hash.to_vec() == hash;
    }

    validity
}

/// get the index of a key in a BTreeMap
pub fn get_key_index<K: Ord>(b: &BTreeMap<K, impl alloc::fmt::Debug>, key: &K) -> Option<usize> {
    b.keys().position(|k| k == key)
}

#[cfg(test)]
mod tests {

    use super::*;
    use w3f_bls::{DoublePublicKeyScheme, TinyBLS377};
    use rand_chacha::ChaCha20Rng;
    use rand_core::OsRng;
    use ark_std::rand::SeedableRng;

    pub struct DummyIdBuilder;
    impl IdentityBuilder<BlockNumber> for DummyIdBuilder {
        fn build_identity(at: BlockNumber) -> Identity {
            Identity::new(&[at as u8])
        }
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_can_generate_mmr_data_store() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let ephem_msk = [1; 32];
        let seed = vec![1, 2, 3];
        let schedule = vec![1, 2, 3];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        )
        .unwrap();

        assert!(murmur_store.metadata.keys().len() == 3);
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_can_generate_valid_output_and_verify_it() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let ephem_msk = [1; 32];
        let seed = vec![1, 2, 3];
        let schedule = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];

        let aux_data = vec![2, 3, 4, 5];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        )
        .unwrap();

        // the block number when this would execute
        let when = 1;

        let root = murmur_store.root.clone();
        let (proof, commitment, ciphertext, pos) = murmur_store
            .execute(seed.clone(), when, aux_data.clone())
            .unwrap();

        // sanity check
        assert!(proof
            .verify(root.clone(), vec![(pos, Leaf(ciphertext.clone()))])
            .unwrap());

        // in practice, the otp code would be timelock decrypted
        // but for testing purposes, we will just calculate the expected one now
        let botp = build_generator(seed.clone()).unwrap();
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
    pub fn it_fails_to_generate_execute_output_when_ciphertext_dne() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let ephem_msk = [1; 32];
        let seed = vec![1, 2, 3];
        let schedule = vec![1, 2, 3, 4, 5];

        let aux_data = vec![2, 3, 4, 5];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        )
        .unwrap();

        // the block number when this would execute
        let when = 1000;

        match murmur_store.execute(seed.clone(), when, aux_data.clone()) {
            Ok(_) => panic!("There should be an error"),
            Err(e) => assert_eq!(e, Error::NoCiphertextFound),
        }
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_fails_on_verify_bad_aux_data() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let ephem_msk = [1; 32];
        let seed = vec![1, 2, 3];
        let schedule = vec![1, 2, 3];

        let aux_data = vec![2, 3, 4, 5];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        )
        .unwrap();

        // the block number when this would execute
        let when = 1;
        let root = murmur_store.root.clone();
        let (proof, commitment, ciphertext, pos) = murmur_store
            .execute(seed.clone(), when, aux_data.clone())
            .unwrap();

        // in practice, the otp code would be timelock decrypted
        // but for testing purposes, we will just calculate the expected one now
        let botp = build_generator(seed.clone()).unwrap();
        let otp_code = botp.generate(when);

        let bad_aux = vec![2, 3, 13, 3];
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

    #[test]
    pub fn it_fails_on_verify_bad_proof() {
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let other_double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let ephem_msk = [1; 32];
        let seed = vec![1, 2, 3];
        let schedule = vec![1, 2, 3];
        let other_schedule = vec![1, 2, 3, 4, 5];

        let aux_data = vec![2, 3, 4, 5];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            schedule.clone(),
            ephem_msk,
            double_public,
        )
        .unwrap();

        let other_murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder>(
            seed.clone(),
            other_schedule.clone(),
            ephem_msk,
            other_double_public,
        )
        .unwrap();

        // the block number when this would execute
        let when = 1;
        let root = murmur_store.root.clone();
        let (proof, commitment, ciphertext, pos) = other_murmur_store
            .execute(seed.clone(), when, aux_data.clone())
            .unwrap();

        // in practice, the otp code would be timelock decrypted
        // but for testing purposes, we will just calculate the expected one now
        let botp = build_generator(seed.clone()).unwrap();
        let otp_code = botp.generate(when);
        assert!(!verify(
            root,
            proof,
            commitment,
            ciphertext,
            otp_code.as_bytes().to_vec(),
            aux_data,
            pos,
        ));
    }
}
