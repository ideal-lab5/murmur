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
use etf::murmur::calls::types::{Create, Proxy};
use etf::runtime_types::{
    bounded_collections::bounded_vec::BoundedVec, node_template_runtime::RuntimeCall,
};
use murmur_core::types::{Identity, IdentityBuilder};
pub use murmur_core::{
    murmur::{Error, MurmurStore},
    types::BlockNumber,
};
use subxt::ext::codec::Encode;

use w3f_bls::{DoublePublicKey, SerializableToBytes, TinyBLS377};

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
            validator_set_id: 0, // TODO: how to ensure correct validator set ID is used? could just always set to 1 for now, else set input param.
        };
        Identity::new(&commitment.encode())
    }
}
/// create a new MMR and use it to generate a valid call to create a murmur wallet
/// returns the call data and the mmr_store
///
/// * `name`: The name of the murmur proxy
/// * `seed`: The seed used to generate otp codes
/// * `ephem_msk`: An ephemeral secret key TODO: replace with an hkdf?
/// * `block_schedule`: A list of block numbers when the wallet will be executable
/// * `round_pubkey_bytes`: The Ideal Network randomness beacon public key
///
pub fn create(
    name: Vec<u8>,
    seed: Vec<u8>,
    ephem_msk: [u8; 32],
    block_schedule: Vec<BlockNumber>,
    round_pubkey_bytes: Vec<u8>,
) -> Result<(subxt::tx::Payload<Create>, MurmurStore), Error> {
    let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes)
        .map_err(|_| Error::InvalidPubkey)?;
    let mmr_store = MurmurStore::new::<TinyBLS377, BasicIdBuilder>(
        seed.clone().into(),
        block_schedule.clone(),
        ephem_msk,
        round_pubkey,
    )?;
    let root = mmr_store.root.clone();

    let call = etf::tx()
        .murmur()
        .create(root.0, mmr_store.metadata.len() as u64, BoundedVec(name));
    Ok((call, mmr_store))
}

/// prepare the call for immediate execution
/// Note to self: in the future, we can consider ways to prune the murmurstore as OTP codes are consumed
///     for example, we can take the next values from the map, reducing storage to 0 over time
///     However, to do this we need to think of a way to prove it with a merkle proof
///     my thought is that we would have a subtree, so first we prove that the subtree is indeed in the parent MMR
///     then we prove that the specific leaf is in the subtree.
///  We could potentially use that idea as a way to optimize the execute function in general. Rather than
///  loading the entire MMR into memory, we really only need to load a  minimal subtree containing the leaf we want to consume
/// -> add this to the 'future work' section later
///
/// * `name`: The name of the murmur proxy
/// * `seed`: The seed used to generate otp codes
/// * `when`: The block number when OTP codeds should be generated
/// * `store`: A murmur store
/// * `call`: Any valid runtime call
///
pub fn prepare_execute(
    name: Vec<u8>,
    seed: Vec<u8>,
    when: BlockNumber,
    store: MurmurStore,
    call: RuntimeCall,
) -> Result<subxt::tx::Payload<Proxy>, Error> {
    let (proof, commitment, ciphertext, pos) = 
        store.execute(seed.clone(), when, call.encode())?;
    let size = proof.mmr_size();
    let proof_items: Vec<Vec<u8>> = proof
        .proof_items()
        .iter()
        .map(|leaf| leaf.0.clone())
        .collect::<Vec<_>>();

    Ok(etf::tx().murmur().proxy(
        BoundedVec(name),
        pos,
        commitment,
        ciphertext,
        proof_items,
        size,
        call,
    ))
}

#[cfg(test)]
mod tests {

    use super::*;
    use subxt::tx::TxPayload;

    #[test]
    pub fn it_can_create_an_mmr_store_and_call_data() {
        let name = b"name".to_vec();
        let seed = b"seed".to_vec();
        let ephem_msk = [1; 32];
        let block_schedule = vec![1, 2, 3, 4, 5, 6, 7];
        let double_public_bytes = murmur_test_utils::get_dummy_beacon_pubkey();
        let (call, mmr_store) = create(
            name.clone(),
            seed,
            ephem_msk,
            block_schedule,
            double_public_bytes,
        )
        .unwrap();

        let expected_call = etf::tx().murmur().create(
            mmr_store.root.0,
            mmr_store.metadata.len() as u64,
            BoundedVec(name),
        );

        let actual_details = call.validation_details().unwrap();
        let expected_details = expected_call.validation_details().unwrap();

        assert_eq!(actual_details.pallet_name, expected_details.pallet_name,);

        assert_eq!(actual_details.call_name, expected_details.call_name,);

        assert_eq!(actual_details.hash, expected_details.hash,);
    }

    #[test]
    pub fn it_can_prepare_valid_execution_call_data() {
        let name = b"name".to_vec();
        let seed = b"seed".to_vec();
        let ephem_msk = [1; 32];
        let block_schedule = vec![1, 2, 3, 4, 5, 6, 7];
        let double_public_bytes = murmur_test_utils::get_dummy_beacon_pubkey();
        let (call, mmr_store) = create(
            name.clone(),
            seed.clone(),
            ephem_msk,
            block_schedule,
            double_public_bytes,
        )
        .unwrap();

        let bob = subxt_signer::sr25519::dev::bob().public_key();
        let bob2 = subxt_signer::sr25519::dev::bob().public_key();
        let balance_transfer_call =
            etf::runtime_types::node_template_runtime::RuntimeCall::Balances(
                etf::balances::Call::transfer_allow_death {
                    dest: subxt::utils::MultiAddress::<_, u32>::from(bob),
                    value: 1,
                },
            );

        let balance_transfer_call_2 =
            etf::runtime_types::node_template_runtime::RuntimeCall::Balances(
                etf::balances::Call::transfer_allow_death {
                    dest: subxt::utils::MultiAddress::<_, u32>::from(bob2),
                    value: 1,
                },
            );

        let actual_call = prepare_execute(
            name.clone(),
            seed.clone(),
            1,
            mmr_store.clone(),
            balance_transfer_call,
        )
        .unwrap();

        let (proof, commitment, ciphertext, pos) = mmr_store
            .execute(seed.clone(), 1, balance_transfer_call_2.encode())
            .unwrap();

        let size = proof.mmr_size();
        let proof_items: Vec<Vec<u8>> = proof
            .proof_items()
            .iter()
            .map(|leaf| leaf.0.clone())
            .collect::<Vec<_>>();
        let expected_call = etf::tx().murmur().proxy(
            BoundedVec(name),
            0,
            commitment,
            ciphertext,
            proof_items,
            size,
            balance_transfer_call_2,
        );

        let actual_details = actual_call.validation_details().unwrap();
        let expected_details = expected_call.validation_details().unwrap();

        assert_eq!(actual_details.pallet_name, expected_details.pallet_name,);

        assert_eq!(actual_details.call_name, expected_details.call_name,);

        assert_eq!(actual_details.hash, expected_details.hash,);
    }
}
