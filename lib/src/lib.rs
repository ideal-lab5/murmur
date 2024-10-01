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
use etf::runtime_types::{
    bounded_collections::bounded_vec::BoundedVec, node_template_runtime::RuntimeCall,
};
use murmur_core::types::{Identity, IdentityBuilder};
use subxt::{
    backend::rpc::RpcClient, client::OnlineClient, config::SubstrateConfig, ext::codec::Encode,
};
use w3f_bls::{DoublePublicKey, SerializableToBytes, TinyBLS377};

pub use etf::murmur::calls::types::{Create, Proxy};
pub use murmur_core::{murmur::MurmurStore, types::BlockNumber};
pub use subxt::tx::Payload as TxPayload;

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
    name: String,
    seed: String,
    ephem_msk: [u8; 32],
    block_schedule: Vec<BlockNumber>,
    round_pubkey_bytes: Vec<u8>,
) -> (TxPayload<Create>, MurmurStore) {
    let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap(); // TODO: error handlking
    let mmr_store = MurmurStore::new::<TinyBLS377, BasicIdBuilder>(
        seed.clone().into(),
        block_schedule.clone(),
        ephem_msk,
        round_pubkey,
    );
    let root = mmr_store.root.clone();
    let name = name.as_bytes().to_vec();

    let call = etf::tx()
        .murmur()
        .create(root.0, mmr_store.metadata.len() as u64, BoundedVec(name));
    (call, mmr_store)
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
pub async fn prepare_execute(
    name: String,
    seed: String,
    when: BlockNumber,
    store: MurmurStore,
    call: RuntimeCall,
) -> TxPayload<Proxy> {
    let (proof, commitment, ciphertext, pos) = store
        .execute(seed.clone().into(), when, call.encode())
        .unwrap();
    let size: u64 = proof.mmr_size();
    let proof_items: Vec<Vec<u8>> = proof
        .proof_items()
        .iter()
        .map(|leaf| leaf.0.clone())
        .collect::<Vec<_>>();

    etf::tx().murmur().proxy(
        BoundedVec(name.into()),
        pos,
        commitment,
        ciphertext,
        proof_items,
        size,
        call,
    )
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
