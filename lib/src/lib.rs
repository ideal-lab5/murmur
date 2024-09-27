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
use murmur_core::{
    murmur::MurmurStore,
    types::{BlockNumber, Identity, IdentityBuilder},
};
use subxt::ext::codec::Encode;
use w3f_bls::{DoublePublicKey, EngineBLS, SerializableToBytes, TinyBLS377};

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "artifacts/metadata.scale")]
pub mod etf {}

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

pub async fn create(
    name: String,
    seed: String,
    ephem_msk: [u8; 32],
    block_schedule: Vec<BlockNumber>,
    round_pubkey_bytes: Vec<u8>,
) -> (
    subxt::tx::Payload<etf::murmur::calls::types::Create>,
    MurmurStore,
) {
    let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();
    let mmr_store = MurmurStore::new::<TinyBLS377, BasicIdBuilder>(
        seed.clone().into(),
        block_schedule.clone(),
        ephem_msk,
        round_pubkey,
    );
    let root = mmr_store.root.clone();
    let name = name.as_bytes().to_vec();
    let call = etf::tx().murmur().create(
        root.0.into(),
        mmr_store.metadata.len() as u64,
        etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(name),
    );
    (call, mmr_store)
}

/// Prepare the call for immediate execution
// Note: in the future, we can consider ways to prune the murmurstore as OTP codes are consumed
//     for example, we can take the next values from the map, reducing storage to 0 over time
//     However, to do this we need to think of a way to prove it with a merkle proof
//     my though is that we would have a subtree, so first we prove that the subtree is indeed in the parent MMR
//     then we prove that the specific leaf is in the subtree.
//  We could potentially use that idea as a way to optimize the execute function in general. Rather than
//  loading the entire MMR into memory, we really only need to load a  minimal subtree containing the leaf we want to consume
// -> add this to the 'future work' section later
pub async fn prepare_execute<E: EngineBLS>(
    name: Vec<u8>,
    seed: Vec<u8>,
    when: BlockNumber,
    store: MurmurStore,
    call: etf::runtime_types::node_template_runtime::RuntimeCall,
) -> subxt::tx::Payload<etf::murmur::calls::types::Proxy> {
    let (proof, commitment, ciphertext, pos) = store
        .execute(seed.clone(), when, call.encode().to_vec())
        .unwrap();

    let proof_items: Vec<Vec<u8>> = proof
        .proof_items()
        .iter()
        .map(|leaf| leaf.0.to_vec().clone())
        .collect::<Vec<_>>();

    let bounded = etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(name);

    etf::tx()
        .murmur()
        .proxy(bounded, pos, commitment, ciphertext, proof_items, call)
}
