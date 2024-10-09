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
use subxt::{
    backend::rpc::RpcClient, client::OnlineClient, config::SubstrateConfig, ext::codec::Encode,
};
use w3f_bls::{DoublePublicKey, SerializableToBytes, TinyBLS377};
use zeroize::Zeroize;

pub use etf::runtime_types::{
    bounded_collections::bounded_vec::BoundedVec, node_template_runtime::RuntimeCall,
};
pub use murmur_core::{
    murmur::{Error, MurmurStore},
    types::BlockNumber,
};

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

#[derive(Serialize)]
/// Data needed to build a valid call for creating a murmur wallet.
pub struct CreateData {
    /// The root of the MMR
    pub root: Vec<u8>,
    /// The size of the MMR
    pub size: u64,
    pub mmr_store: MurmurStore,
}

#[derive(Serialize)]
/// Data needed to build a valid call for a proxied execution.
pub struct ProxyData {
    pub position: u64,
    /// The hash of the commitment
    pub hash: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub proof_items: Vec<Vec<u8>>,
    pub size: u64,
}

/// Create a new MMR and return the data needed to build a valid call for creating a murmur wallet.
///
/// * `seed`: The seed used to generate otp codes
/// * `ephem_msk`: An ephemeral secret key TODO: replace with an hkdf?
/// * `block_schedule`: A list of block numbers when the wallet will be executable
/// * `round_pubkey_bytes`: The Ideal Network randomness beacon public key
///
pub fn create(
    mut seed: Vec<u8>,
    mut ephem_msk: [u8; 32],
    block_schedule: Vec<BlockNumber>,
    round_pubkey_bytes: Vec<u8>,
) -> Result<CreateData, Error> {
    let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes)
        .map_err(|_| Error::InvalidPubkey)?;
    let mmr_store = MurmurStore::new::<TinyBLS377, BasicIdBuilder>(
        seed.clone(),
        block_schedule.clone(),
        ephem_msk,
        round_pubkey,
    )?;
    ephem_msk.zeroize();
    seed.zeroize();
    let root = mmr_store.root.clone();

    Ok(CreateData {
        root: root.0,
        size: mmr_store.metadata.len() as u64,
        mmr_store,
    })
}

/// Return the data needed for the immediate execution of the proxied call.
/// * `seed`: The seed used to generate otp codes
/// * `when`: The block number when OTP codeds should be generated
/// * `store`: A murmur store
/// * `call`: Proxied call. Any valid runtime call
///
// Note to self: in the future, we can consider ways to prune the murmurstore as OTP codes are consumed
//     for example, we can take the next values from the map, reducing storage to 0 over time
//     However, to do this we need to think of a way to prove it with a merkle proof
//     my thought is that we would have a subtree, so first we prove that the subtree is indeed in the parent MMR
//     then we prove that the specific leaf is in the subtree.
//  We could potentially use that idea as a way to optimize the execute function in general. Rather than
//  loading the entire MMR into memory, we really only need to load a  minimal subtree containing the leaf we want to consume
// -> add this to the 'future work' section later
pub fn prepare_execute(
    mut seed: Vec<u8>,
    when: BlockNumber,
    store: MurmurStore,
    call: &RuntimeCall,
) -> Result<ProxyData, Error> {
    let (proof, commitment, ciphertext, pos) = store.execute(seed.clone(), when, call.encode())?;
    seed.zeroize();
    let size = proof.mmr_size();
    let proof_items: Vec<Vec<u8>> = proof
        .proof_items()
        .iter()
        .map(|leaf| leaf.0.clone())
        .collect::<Vec<_>>();

    Ok(ProxyData {
        position: pos,
        hash: commitment,
        ciphertext,
        proof_items,
        size,
    })
}

/// Async connection to the Ideal Network
/// if successful then fetch data
/// else error if unreachable
pub async fn idn_connect(
) -> Result<(OnlineClient<SubstrateConfig>, BlockNumber, Vec<u8>), Box<dyn std::error::Error>> {
    println!("🎲 Connecting to Ideal network (local node)");
    let ws_url = std::env::var("WS_URL").unwrap_or_else(|_| {
        let fallback_url = "ws://localhost:9944".to_string();
        println!(
            "⚠️ WS_URL environment variable not set. Using fallback URL: {}",
            fallback_url
        );
        fallback_url
    });

    let rpc_client = RpcClient::from_url(&ws_url).await?;
    let client = OnlineClient::<SubstrateConfig>::from_rpc_client(rpc_client.clone()).await?;
    println!("🔗 RPC Client: connection established");

    // fetch the round public key from etf runtime storage
    let round_key_query = subxt::dynamic::storage("Etf", "RoundPublic", ());
    let result = client
        .storage()
        .at_latest()
        .await?
        .fetch(&round_key_query)
        .await?;
    let round_pubkey_bytes = result.unwrap().as_type::<Vec<u8>>()?;

    println!("🔑 Successfully retrieved the round public key.");

    let current_block = client.blocks().at_latest().await?;
    let current_block_number: BlockNumber = current_block.header().number;
    println!("🧊 Current block number: #{:?}", current_block_number);
    Ok((client, current_block_number, round_pubkey_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn it_can_create_an_mmr_store() {
        let seed = b"seed".to_vec();
        let ephem_msk = [1; 32];
        let block_schedule = vec![1, 2, 3, 4, 5, 6, 7];
        let double_public_bytes = murmur_test_utils::get_dummy_beacon_pubkey();
        let create_data = create(
            seed.clone(),
            ephem_msk,
            block_schedule.clone(),
            double_public_bytes.clone(),
        )
        .unwrap();

        let mmr_store = MurmurStore::new::<TinyBLS377, BasicIdBuilder>(
            seed,
            block_schedule,
            ephem_msk,
            DoublePublicKey::<TinyBLS377>::from_bytes(&double_public_bytes).unwrap(),
        )
        .unwrap();

        assert_eq!(create_data.mmr_store.root, mmr_store.root);
        assert_eq!(create_data.size, 7);
    }

    #[test]
    pub fn it_can_prepare_valid_execution_call_data() {
        let seed = b"seed".to_vec();
        let ephem_msk = [1; 32];
        let block_schedule = vec![1, 2, 3, 4, 5, 6, 7];
        let double_public_bytes = murmur_test_utils::get_dummy_beacon_pubkey();
        let create_data =
            create(seed.clone(), ephem_msk, block_schedule, double_public_bytes).unwrap();

        let bob = subxt_signer::sr25519::dev::bob().public_key();
        let balance_transfer_call =
            &etf::runtime_types::node_template_runtime::RuntimeCall::Balances(
                etf::balances::Call::transfer_allow_death {
                    dest: subxt::utils::MultiAddress::<_, u32>::from(bob),
                    value: 1,
                },
            );

        let proxy_data = prepare_execute(
            seed.clone(),
            1,
            create_data.mmr_store.clone(),
            balance_transfer_call,
        )
        .unwrap();

        let (proof, commitment, ciphertext, _pos) = create_data
            .mmr_store
            .execute(seed.clone(), 1, balance_transfer_call.encode())
            .unwrap();

        let size = proof.mmr_size();
        let proof_items: Vec<Vec<u8>> = proof
            .proof_items()
            .iter()
            .map(|leaf| leaf.0.clone())
            .collect::<Vec<_>>();

        assert_eq!(proxy_data.position, 0);
        assert_eq!(proxy_data.hash, commitment);
        assert_eq!(proxy_data.ciphertext, ciphertext);
        assert_eq!(proxy_data.proof_items, proof_items);
        assert_eq!(proxy_data.size, size);
    }
}
