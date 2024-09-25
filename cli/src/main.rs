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

#![allow(missing_docs)]
use subxt::{
    client::OnlineClient,
    config::SubstrateConfig,
    backend::rpc::{RpcClient, RpcParams},
};
use subxt_signer::sr25519::dev;

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "artifacts/metadata.scale")]
pub mod etf {}

use std::collections::BTreeMap;
use std::ops::Index;
use std::io::{Read, Write, BufRead, BufReader};
use std::fs::File;
use std::time::Duration;
use std::collections::HashMap;

use clap::{Args, Parser, Subcommand};

use ckb_merkle_mountain_range::{
    helper::leaf_index_to_pos,
    MerkleProof,
    MMR, Merge, Result as MMRResult, MMRStore,
    util::{
        MemMMR,
        MemStore
    },
};

use rand_chacha::{
    ChaCha20Rng,
    rand_core::SeedableRng,
};

use std::io;

use subxt::ext::codec::Encode;
use beefy::{known_payloads, Payload, Commitment, VersionedFinalityProof};
use sp_core::{Bytes, Decode};

use murmur_core::{
    types::{
        BlockNumber,
        Leaf,
        MergeLeaves,
        Identity,
        IdentityBuilder,
        Ciphertext,
    },
    murmur::MurmurStore,
};
use etf_crypto_primitives::{
    ibe::fullident::{IBESecret},
    encryption::tlock::{TLECiphertext, tle}
};

use ark_serialize::CanonicalDeserialize;
use ark_ff::UniformRand;
use rand_core::OsRng;

use w3f_bls::{EngineBLS, TinyBLS377, SerializableToBytes, DoublePublicKey};

use std::time::Instant;

/// Command line
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// create a new murmur wallet
    New(WalletCreationDetails),
    /// dispatch (proxy) a call to a murmur wallet in the future
    ScheduleExecute(WalletExecuteDetails),
    /// dispatch (proxy) a call to a murmur wallet
    Execute(WalletExecuteDetails),
}

#[derive(Parser)]
struct WalletCreationDetails {
    #[arg(long)]
    name: String,
    #[arg(long)]
    seed: String,
    #[clap(long)]
    validity: u32,
}

#[derive(Parser)]
struct WalletExecuteDetails {
    #[arg(long)]
    name: String,
    #[arg(long)]
    seed: String,
    #[arg(short, long)]
    amount: String,
}

pub enum CLIError {

}

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let before = Instant::now();
    // first we need to connect to a node and fetch the round key and current block number
    println!("🎲 Connecting to Ideal network (local node)");
            
    let rpc_client = RpcClient::from_url("ws://localhost:9944").await?;
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
    let current_block_number = current_block.header().number;

    println!("🧊 Current block number: #{:?}", current_block_number);

    // why do I have two clients??
    let etf = OnlineClient::<SubstrateConfig>::new().await?;

    // let mut mmr_store_file = File::create("mmr_store").unwrap();
    // let store = MemStore::default();

    // TODO: HKDF? just hash the seed?
    let ephem_msk = [1;32]; 

    match &cli.commands {
        Commands::New(args) => {        
            println!("🏭 Murmur: Generating Merkle mountain range");
            // 1. prepare block schedule
            let mut schedule: Vec<BlockNumber> = Vec::new();
            for i in 2..args.validity + 2 {
                // wallet is 'active' in 2 blocks 
                let next_block = current_block_number.clone() + i as u32;
                schedule.push(next_block);
            }
            // 2. create mmr
            let (call, mmr_store) = create(
                args.name.clone(),
                args.seed.clone(),
                ephem_msk,
                schedule,
                round_pubkey_bytes,
            ).await;
            // 3. add to storage
            write_mmr_store(mmr_store.clone());
            // TODO: make the origin configurable
            // sign and send the call
            let from = dev::alice();
            let events = etf
                .tx()
                .sign_and_submit_then_watch_default(&call, &from)
                .await?;
            println!("✅ MMR proxy account creation successful!");
            
        },
        // Commands::ScheduleExecute(args) => {
        //     // build balance transfer
        //     let bob = AccountKeyring::Bob.to_account_id().into();
        //     // get the value argument
        //     let v: u128 = args.amount
        //         .split_whitespace()
        //         .map(|r| r.replace('_', "").parse().unwrap())
        //         .collect::<Vec<_>>()[0];
        //     let balance_transfer_call = RuntimeCall::Balances(
        //         BalancesCall::transfer_allow_death {
        //             dest: bob,
        //             value: v,
        //     });
        //     let call = prepare_execution_payload_for_proxy::<TinyBLS377>(
        //         etf.clone(),
        //         args.name.clone().as_bytes().to_vec(),
        //         args.seed.clone().as_bytes().to_vec(),
        //         args.when.clone(),
        //         balance_transfer_call,
        //     ).await;
        //     // sign and send the tx (with the alice wallet for now)
        //     dispatch_sealed_tx::<TinyBLS377, BasicIdBuilder>(
        //         etf,
        //         args.when, 
        //         ephem_msk,
        //         round_pubkey,
        //         call,
        //     ).await;
        // },
        Commands::Execute(args) => {
            // build balance transfer
            let bob =  dev::alice().public_key();
            // get the value argument
            let v: u128 = args.amount
                .split_whitespace()
                .map(|r| r.replace('_', "").parse().unwrap())
                .collect::<Vec<_>>()[0];
            // TODO: cleanup type defs
            let balance_transfer_call = etf::runtime_types::node_template_runtime::RuntimeCall::Balances(
                etf::balances::Call::transfer_allow_death {
                    dest: subxt::utils::MultiAddress::<_, u32>::from(bob),
                    value: v,
            });

            let store: MurmurStore = load_mmr_store();
            // store.to_mmr(&mut mmr).unwrap();
            
            let tx = prepare_execute(
                // etf.clone(),
                args.name.clone().as_bytes().to_vec(),
                args.seed.clone().as_bytes().to_vec(),
                current_block_number,
                store,
                balance_transfer_call,
            ).await;
            // submit the tx using alice to sign it
            etf.tx()
                .sign_and_submit_then_watch_default(&tx, &dev::alice())
                .await;
        },
        _ => panic!("Hey, don't do that!"),
    }
    println!("Elapsed time: {:.2?}", before.elapsed());
    Ok(())
}

/// create a new MMR and use it to generate a valid call to create a murmur wallet
/// returns the call data and the mmr_store
///
/// * `name`: The name of the murmur wallet
/// * `seed`: The seed used to generate otp codes
/// * `ephem_msk`: An ephemeral secret key TODO: replace with an hkdf?
/// * `block_schedule`: A list of block numbers when the wallet will be executable
/// * `round_pubkey_bytes`: The Ideal Network randomness beacon public key
///
pub async fn create(
    name: String,
    seed: String,
    ephem_msk: [u8;32],
    block_schedule: Vec<BlockNumber>,
    round_pubkey_bytes: Vec<u8>,
) -> (subxt::tx::Payload<etf::murmur::calls::types::Create>, MurmurStore) {
    let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();
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
        .create(
            root.0.into(),
            mmr_store.metadata.len() as u64,
            etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(name));
    (call, mmr_store)
}

/// prepare the call for immediate execution
/// Note to self: in the future, we can consider ways to prune the murmurstore as OTP codes are consumed
///     for example, we can take the next values from the map, reducing storage to 0 over time
///     However, to do this we need to think of a way to prove it with a merkle proof
///     my though is that we would have a subtree, so first we prove that the subtree is indeed in the parent MMR
///     then we prove that the specific leaf is in the subtree.
///  We could potentially use that idea as a way to optimize the execute function in general. Rather than
///  loading the entire MMR into memory, we really only need to load a  minimal subtree containing the leaf we want to consume
/// -> add this to the 'future work' section later
pub async fn prepare_execute(
    name: Vec<u8>,
    seed: Vec<u8>,
    when: BlockNumber,
    store: MurmurStore,
    call: etf::runtime_types::node_template_runtime::RuntimeCall,
) -> subxt::tx::Payload<etf::murmur::calls::types::Proxy> {   
    let call_data = call.encode();

    let root = store.root.clone();

    let (proof, commitment, ciphertext, pos) = store.execute(
        seed.clone(), when, call.encode().to_vec(),
    ).unwrap();

    let proof_items: Vec<Vec<u8>> = proof.proof_items().iter()
        .map(|leaf| leaf.0.to_vec().clone())
        .collect::<Vec<_>>();

    let bounded = etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(name);
   
    etf::tx().murmur().proxy(
        bounded,
        pos,
        commitment,
        ciphertext,
        proof_items,
        call,
    )
}

// /// prepare the proxy call for a scheduled transaction
// async fn prepare_execution_payload_for_proxy<E: EngineBLS>(
//     etf: OnlineClient<SubstrateConfig>,
//     name: Vec<u8>,
//     seed: Vec<u8>,
//     when: BlockNumber,
//     call: RuntimeCall,
// ) -> RuntimeCall {
//     let data: Vec<(BlockNumber, Ciphertext)> = load_mmr_store();
//     let ciphertext = data.iter().filter(|d| d.0 == when).collect().unwrap()[0];

//     let call_data = call.encode();
//     // prepare the proof required to used the mmr wallet at the specific block height
//     let payload = murmur::execute::<E>(
//         seed,
//         when,
//         call_data,
//         leaves.clone(),
//     ).map_err(|e| println!("Murmur execution failed due to {:?}", e)).unwrap();

//     // let root: Leaf = payload.root;
//     let hash: Vec<u8> = payload.hash;
//     let proof: MerkleProof<Leaf, MergeLeaves> = payload.proof;
//     let target_leaf: Leaf = payload.target;
//     let pos: u64 = payload.pos;

//     let proof_items: Vec<Vec<u8>> = proof.proof_items().iter()
//         .map(|leaf| leaf.0.to_vec().clone())
//         .collect::<Vec<_>>();

//     let bounded = <BoundedVec<_, ConstU32<32>>>::truncate_from(name);
    
//     RuntimeCall::Murmur(MurmurCall::proxy {
//         name: bounded,
//         position: pos,
//         target_leaf: target_leaf.0,
//         proof: proof_items,
//         ciphertext,
//         call: Box::new(call),
//         hash,
//     })
// }



// /// dispatch a shielded (timelocked) transaction for a future block
// async fn dispatch_sealed_tx<E: EngineBLS, I: IdentityBuilder<BlockNumber>>(
//     etf: OnlineClient<SubstrateConfig>,
//     when: BlockNumber,
//     ephemeral_msk: [u8;32],
//     pk: DoublePublicKey<E>,
//     proxy_call: RuntimeCall,
// ) {
//     let proxy_call_bytes: &[u8] = &proxy_call.encode();
//     // then construct a scheduled transaction for "when"
//     // 1. tlock
//     let identity = I::build_identity(when);
//     let timelocked_proxy_call = murmur::timelock_encrypt::<E>(
//         identity,
//         pk.1,
//         ephemeral_msk,
//         proxy_call_bytes,
//     );
//     let bounded_ciphertext = etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(timelocked_proxy_call);
//     // 2. build tx
//     let sealed_tx = etf::tx()
//         .scheduler()
//         .schedule_sealed(when, 127, bounded_ciphertext);
//     // 3. submit tx
//     let events = etf
//         .tx()
//         .sign_and_submit_then_watch_default(&sealed_tx, &dev::alice())
//         .await;
// }

/// read an MMR from a file
fn load_mmr_store() -> MurmurStore {
    let mmr_store_file = File::open("mmr_store")
        .expect("Unable to open file");
    let data: MurmurStore = 
        serde_cbor::from_reader(mmr_store_file).unwrap();
    
    data
}

/// Write the MMR data to a file (no seed)
fn write_mmr_store(mmr_store: MurmurStore) {
    let mut mmr_store_file = File::create("mmr_store")
        .expect("should be ok");
    // TODO: error handling
    serde_cbor::to_writer(mmr_store_file, &mmr_store)
        .unwrap();
}

#[cfg(test)]
mod tests {
    // pub fn test_can_read_write_mmr_store() { }
}
