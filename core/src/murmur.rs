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

use ark_std::rand::SeedableRng;
use ark_std::rand::{CryptoRng, Rng};

#[cfg(feature = "client")]
use zeroize::Zeroize;

#[cfg(feature = "client")]
use ark_serialize::CanonicalSerialize;

use crate::types::*;
use ark_ec::CurveGroup;
use ark_transcript::{digest::Update, Transcript};
use ckb_merkle_mountain_range::{
	helper::leaf_index_to_pos,
	util::{MemMMR, MemStore},
	MerkleProof,
};
use dleq_vrf::{EcVrfVerifier, PublicKey, SecretKey};
use etf_crypto_primitives::{
	encryption::tlock::*, 
	ibe::fullident::Identity
};
use sha3::Digest;
use w3f_bls::{DoublePublicKey, EngineBLS};

/// The Murmur protocol label for domain separation in transcripts
pub const MURMUR_PROTO: &[u8] = b"Murmur://";
/// The size of a 32-bit buffer
pub const ALLOCATED_BUFFER_BYTES: usize = 32;

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
	/// The nonce of this murmur store
	pub nonce: u64,
	/// A map of block numbers to leaf positions in the mmr
	pub metadata: BTreeMap<BlockNumber, Ciphertext>,
	/// The root of the mmr
	pub root: Leaf,
	/// A serialized VRF proof
	pub proof: Vec<u8>,
	/// A serialized public key associated with the VRF proof
	pub public_key: Vec<u8>,
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
	pub fn new<E: EngineBLS, I: IdentityBuilder<BlockNumber>, R>(
		mut seed: Vec<u8>,
		block_schedule: Vec<BlockNumber>,
		nonce: u64,
		round_public_key: DoublePublicKey<E>,
		rng: &mut R,
	) -> Result<Self, Error>
	where
		R: Rng + CryptoRng + SeedableRng<Seed = [u8; 32]> + Sized,
	{
		let mut witness = generate_witness(seed.clone(), rng);
		let mut secret_key = SecretKey::<<E::SignatureGroup as CurveGroup>::Affine>::from_seed(&witness);
		let pubkey = secret_key.as_publickey();
		let mut pubkey_bytes = Vec::new();
		pubkey.serialize_compressed(&mut pubkey_bytes).unwrap();

		// generate a transcript s.t. the proof verification requires the nonce
		let mut transcript = Transcript::new_labeled(MURMUR_PROTO);
		transcript.write_bytes(&nonce.to_be_bytes());
		let signature = secret_key.sign_thin_vrf_detached(transcript.clone(), &[]);

		let mut sig_bytes = Vec::new();
		signature.serialize_compressed(&mut sig_bytes).unwrap();

		let totp = BOTPGenerator::new(witness.to_vec()).map_err(|_| Error::InvalidSeed)?;

		seed.zeroize();
		witness.zeroize();
		secret_key.zeroize();

		let mut metadata = BTreeMap::new();
		let store = MemStore::default();
		let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);

		for &i in &block_schedule {
			let otp_code = totp.generate(i);
			let identity = I::build_identity(i);

			let mut ephemeral_msk: [u8; 32] = transcript
				.clone()
				.fork(b"otp-leaf-gen")
				.chain(&i.to_be_bytes())
				.chain(&otp_code.as_bytes())
				.challenge(b"ephemeral_msk")
				.read_byte_array();
			let ephem_rng = R::from_seed(ephemeral_msk);

			let ct_bytes = timelock_encrypt::<E, R>(
				identity,
				round_public_key.1,
				ephemeral_msk,
				otp_code.as_bytes(),
				ephem_rng,
			)?;
			ephemeral_msk.zeroize();
			let leaf = Leaf(ct_bytes.clone());
			// Q: How can I test this line?
			// https://github.com/nervosnetwork/merkle-mountain-range/blob/9e77d3ef81ddfdd9b7dd9583762582e859849dde/src/mmr.rs#L60
			let _pos = mmr.push(leaf).map_err(|_| Error::InconsistentStore)?;
			metadata.insert(i, ct_bytes);
		}

		let root = mmr.get_root().map_err(|_| Error::InconsistentStore)?;

		Ok(MurmurStore { nonce, metadata, root, proof: sig_bytes, public_key: pubkey_bytes })
	}

	/// Build data required (proof and commitment) to execute a valid call from a murmur wallet
	///
	/// * `seed`: The seed used to create the mmr
	/// * `when`: The block number when the wallet is being used (or will be)
	/// * `call_data`: The call to be executed with the wallet (at `when`)
	///
	pub fn execute<R: Rng + CryptoRng + Sized>(
		&self,
		mut seed: Vec<u8>,
		when: BlockNumber,
		call_data: Vec<u8>,
		mut rng: R,
	) -> Result<(MerkleProof<Leaf, MergeLeaves>, Vec<u8>, Ciphertext, u64), Error> {
		if let Some(ciphertext) = self.metadata.get(&when) {
			let commitment = MurmurStore::commit(seed.clone(), when, &call_data.clone(), &mut rng)?;
			seed.zeroize();
			// let idx = get_key_index(&self.metadata, &when)
			// 	.expect("The key must exist within the metadata.");
			let idx = self.metadata.keys().position(|k| k == &when).expect("The leaf should exist");
			let pos = leaf_index_to_pos(idx as u64);
			let mmr = self.to_mmr()?;
			let proof = mmr.gen_proof(vec![pos]).map_err(|_| Error::InconsistentStore)?;
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
	fn commit<R: Rng + CryptoRng + Sized>(
		mut seed: Vec<u8>,
		when: BlockNumber,
		data: &[u8],
		mut rng: R,
	) -> Result<Vec<u8>, Error> {
		let mut witness = generate_witness(seed.clone(), &mut rng);
		let botp = BOTPGenerator::new(witness.to_vec())
            .map_err(|_| Error::InvalidSeed)?;
		seed.zeroize();
		witness.zeroize();

		let otp_code = botp.generate(when);

		let mut hasher = sha3::Sha3_256::default();
		Digest::update(&mut hasher, otp_code.as_bytes());
		Digest::update(&mut hasher, data);
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
			mmr.push(Leaf(ciphertext)).map_err(|_| Error::InconsistentStore)?;
		}

		Ok(mmr)
	}
}

/// construct a 32-byte witness by seeding a transcript with the given 'seed' 
/// using a CSPRNG to generate the witness
///
/// * `seed`: The value written to the transcript
/// * `rng`: A CSPRNG
///
fn generate_witness<R: Rng + CryptoRng + Sized>(mut seed: Vec<u8>, mut rng: R) -> [u8; 32] {
    let mut transcript = Transcript::new_labeled(MURMUR_PROTO);
    transcript.write_bytes(&seed);
    seed.zeroize();
    let witness: [u8; 32] = transcript.clone().witness(&mut rng).read_byte_array();
    witness
}

/// A helper function to perform timelock encryption
///
/// * `identity`: The identity to encrypt for
/// * `pk`: The public key of the randomness beacon
/// * `ephemeral_msk`: A randomly sampled 32-byte secret key
/// * `message`: The message to be timelock encrypted
/// * `rng`: A CSPRNG
///
fn timelock_encrypt<E: EngineBLS, R: CryptoRng + Rng + Sized>(
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

/// Functions for verifying execution and update requests
/// These functions would typically be called by an untrusted verifier (e.g. a blockchain runtime)
pub mod verifier {
	use super::*;
    use ark_serialize::CanonicalDeserialize;
    use dleq_vrf::{ThinVrfProof};

	#[derive(Debug, PartialEq)]
	pub enum VerificationError {
		UnserializableProof,
		UnserializablePubkey,
	}

	/// Verify the correctness of execution parameters by checking that the Merkle proof and hash are valid
	/// The function outputs true if both conditions are true:
	///		proof.verify(root, [(pos, Leaf(ciphertext))])
	///		hash = Sha256(otp || aux_data)	
	////
	/// It outputs false otherwise.
	///
	/// * `root`: The root of the MMR
	/// * `proof`: The Merkle proof to verify
	/// * `hash`: A (potential) commitment to the OTP and aux_data
	/// * `ciphertext`: A timelocked ciphertext 
	/// * `otp`: The OTP
	/// * `aux_data`: The expected aux data used to generate the commitment
	/// * `pos`: The position of the Ciphertext within the MMR
	///
	pub fn verify_execute(
		root: Leaf,
		proof: MerkleProof<Leaf, MergeLeaves>,
		hash: Vec<u8>,
		ciphertext: Vec<u8>,
		otp: &[u8],
		aux_data: &[u8],
		pos: u64,
	) -> bool {
		let mut validity = proof.verify(root, vec![(pos, Leaf(ciphertext))])
			.unwrap_or(false);

		if validity {
			let mut hasher = sha3::Sha3_256::default();
			Digest::update(&mut hasher, otp);
			Digest::update(&mut hasher, aux_data);
			let expected_hash = hasher.finalize().to_vec();

			validity = validity && expected_hash == hash;
		}

		validity
	}

	/// Verifies a Schnorr proof
	/// This is used to ensure that subsequent calls to the 'new' function are called with the same seed
	///
	/// * `serialized_proof`: The serialized proof
	/// * `serialized_pubkey`: The serialized public key
	/// * `nonce`: A nonce value
	///
	pub fn verify_update<E: EngineBLS>(
         serialized_proof: Vec<u8>, 
        serialized_pubkey: Vec<u8>,
        nonce: u64,
    ) -> Result<bool, VerificationError> {
        // build transcript
        let mut transcript = Transcript::new_labeled(MURMUR_PROTO);
        transcript.write_bytes(&nonce.to_be_bytes());
        // deserialize proof and pubkey
        let proof = ThinVrfProof::<<E::SignatureGroup as CurveGroup>::Affine>::
			deserialize_compressed(&mut &serialized_proof[..])
			.map_err(|_| VerificationError::UnserializableProof)?;
        let pk = PublicKey::<<E::SignatureGroup as CurveGroup>::Affine>::
			deserialize_compressed(&mut &serialized_pubkey[..])
			.map_err(|_| VerificationError::UnserializablePubkey)?;
			
		Ok(pk.vrf_verify_detached(transcript, &[], &proof).is_ok())
	}
}

#[cfg(test)]
mod tests {

    use super::*;
    use w3f_bls::{DoublePublicKeyScheme, TinyBLS377};
    use rand_chacha::ChaCha20Rng;
    use ark_std::rand::SeedableRng;	

	/// 
	pub const BLOCK_SCHEDULE: &[BlockNumber] = &[
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	];

	pub const WHEN: BlockNumber = 10;
	pub const OTP: &[u8] = b"823185";

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

        let seed = vec![1, 2, 3];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder, ChaCha20Rng>(
            seed.clone(),
            BLOCK_SCHEDULE.to_vec(),
            0,
            double_public,
            &mut rng,
        ).unwrap();

        assert!(murmur_store.metadata.keys().len() == BLOCK_SCHEDULE.len());
        assert!(murmur_store.root.0.len() == 32);
        assert!(murmur_store.proof.len() == 80);
        assert!(murmur_store.public_key.len() == 48);
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_can_generate_valid_output_and_verify_it() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let seed = vec![1, 2, 3];
        let aux_data = vec![2, 3, 4, 5];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder, ChaCha20Rng>(
            seed.clone(),
            BLOCK_SCHEDULE.to_vec(),
            0,
            double_public,
            &mut rng,
        ).unwrap();

        let root = murmur_store.root.clone();
        let (proof, commitment, ciphertext, pos) = murmur_store
            .execute(
                seed.clone(), 
                WHEN, 
                aux_data.clone(),
                &mut rng,
            )
            .unwrap();

        // sanity check
        assert!(proof
            .verify(root.clone(), vec![(pos, Leaf(ciphertext.clone()))])
            .unwrap());

        assert!(verifier::verify_execute(
            root,
            proof,
            commitment,
            ciphertext,
            OTP,
            &aux_data,
            pos,
        ));
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_fails_to_generate_execute_output_when_ciphertext_dne() {
		let mut rng = ChaCha20Rng::seed_from_u64(0);
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let seed = vec![1, 2, 3];
		let aux_data = vec![2, 3, 4, 5];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder, ChaCha20Rng>(
            seed.clone(),
            BLOCK_SCHEDULE.to_vec(),
            0,
            double_public,
            &mut rng,
        ).unwrap();

        // the block number when this would execute
        let when = 1000;

        match murmur_store.execute(seed.clone(), when, aux_data.clone(), &mut rng) {
            Ok(_) => panic!("There should be an error"),
            Err(e) => assert_eq!(e, Error::NoCiphertextFound),
        }
    }

    #[cfg(feature = "client")]
    #[test]
    pub fn it_fails_on_verify_bad_aux_data() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let seed = vec![1, 2, 3];
        let aux_data = vec![2, 3, 4, 5];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder, ChaCha20Rng>(
            seed.clone(),
            BLOCK_SCHEDULE.to_vec(),
            0,
            double_public,
            &mut rng,
        ).unwrap();

        let root = murmur_store.root.clone();
        let (proof, commitment, ciphertext, pos) = murmur_store
            .execute(
                seed.clone(), 
                WHEN, 
                aux_data.clone(),
                &mut rng,
            )
            .unwrap();

        let bad_aux = vec![2, 3, 13, 3];
        assert!(!verifier::verify_execute(
            root,
            proof,
            commitment,
            ciphertext,
            OTP,
            &bad_aux,
            pos,
        ));
    }

    #[test]
    pub fn it_fails_on_verify_bad_proof() {
		let mut rng = ChaCha20Rng::seed_from_u64(0);
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

		let other_keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
        let other_double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            other_keypair.into_public_key_in_signature_group().0,
            other_keypair.public.0,
        );

        let seed = vec![1, 2, 3];
		let other_seed = vec![2,3,4];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder, ChaCha20Rng>(
            seed.clone(),
            BLOCK_SCHEDULE.to_vec(),
            0,
            double_public,
            &mut rng,
        ).unwrap();

        let other_murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder, ChaCha20Rng>(
            other_seed.clone(),
            BLOCK_SCHEDULE.to_vec(),
            0,
            other_double_public,
            &mut rng,
        ).unwrap();

        let aux_data = vec![2, 3, 4, 5];

        // the block number when this would execute
        let root = murmur_store.root.clone();
        let (proof, commitment, ciphertext, pos) = other_murmur_store
            .execute(
                other_seed.clone(), 
                WHEN, 
                aux_data.clone(),
                &mut rng,
            )
            .unwrap();

        assert!(!verifier::verify_execute(
            root,
            proof,
            commitment,
            ciphertext,
            OTP,
            &aux_data,
            pos,
        ));
    }

	#[test]
	fn it_can_generate_and_verify_schnorr_proofs() {
		let mut rng = ChaCha20Rng::seed_from_u64(0);
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let seed = vec![1, 2, 3];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder, ChaCha20Rng>(
            seed.clone(),
            BLOCK_SCHEDULE.to_vec(),
            0,
            double_public,
            &mut rng,
        ).unwrap();

		let proof = murmur_store.proof;
		let pk = murmur_store.public_key;
		// now verify the proof for nonce = 0
		assert!(verifier::verify_update::<TinyBLS377>(
			proof,
			pk,			
			0,
		).is_ok());
	}

	#[test]
	fn it_cannot_verify_schnorr_proof_with_bad_nonce() {
		let mut rng = ChaCha20Rng::seed_from_u64(0);
        let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
        let double_public: DoublePublicKey<TinyBLS377> = DoublePublicKey(
            keypair.into_public_key_in_signature_group().0,
            keypair.public.0,
        );

        let seed = vec![1, 2, 3];

        let murmur_store = MurmurStore::new::<TinyBLS377, DummyIdBuilder, ChaCha20Rng>(
            seed.clone(),
            BLOCK_SCHEDULE.to_vec(),
            0,
            double_public,
            &mut rng,
        ).unwrap();

		let proof = murmur_store.proof;
		let pk = murmur_store.public_key;
		// now verify the proof for nonce = 1
		assert!(!verifier::verify_update::<TinyBLS377>(
			proof,
			pk,			
			1,
		).unwrap());
	}
}
