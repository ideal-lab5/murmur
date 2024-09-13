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

use std::io::{Read, Write, BufRead, BufReader};
use std::fs::File;
use std::time::Duration;
use std::collections::HashMap;

use clap::{Args, Parser, Subcommand};

use ckb_merkle_mountain_range::{
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

// use ratatui::{
//     crossterm::event::{self, KeyCode, KeyEventKind},
//     style::Stylize,
//     widgets::Paragraph,
//     DefaultTerminal,
// };

use node_template_runtime::{self, MurmurCall, RuntimeCall, BalancesCall};

use subxt::ext::codec::Encode;
use beefy::{known_payloads, Payload, Commitment, VersionedFinalityProof};
use sp_core::{Bytes, Decode};

use murmur_core::{
    types::{
        BlockNumber,
        Leaf,
        MergeLeaves,
    },
    murmur,
};
use etf_crypto_primitives::{
    ibe::fullident::{IBESecret, Identity},
    encryption::tlock::{TLECiphertext, tle}
};

use ark_serialize::CanonicalDeserialize;
use ark_ff::UniformRand;
use rand_core::OsRng;

use w3f_bls::{EngineBLS, TinyBLS377, SerializableToBytes, DoublePublicKey};

use sp_keyring::AccountKeyring;
use frame_support::{BoundedVec, traits::ConstU32};

use std::time::Instant;
use indicatif::ProgressBar;

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
    /// create a new OTP wallet
    New(WalletCreationDetails),
    /// dispatch (proxy) a call to an OTP wallet
    Execute(WalletExecuteDetails),
}

#[derive(Parser)]
struct WalletCreationDetails {
    #[arg(long)]
    name: String,
    #[arg(long)]
    seed: String,
    #[clap(short, long, value_delimiter = ' ', num_args = 1..)]
    schedule: Vec<BlockNumber>,
}

#[derive(Parser)]
struct WalletExecuteDetails {
    #[arg(long)]
    name: String,
    #[arg(long)]
    seed: String,
    #[arg(long)]
    when: BlockNumber,
    #[arg(short, long)]
    amount: String,
}

pub enum CLIError {

}

// use sha3::Digest;

// fn main() -> io::Result<()>  {
//     let mut terminal = ratatui::init();
//     terminal.clear()?;
//     let app_result = run(terminal);
//     ratatui::restore();
//     app_result
// }

// fn run(mut terminal: DefaultTerminal) -> io::Result<()> {
//     loop {
//         terminal.draw(|frame| {
//             let greeting = Paragraph::new("Hello Ratatui! (press 'q' to quit)")
//                 .white()
//                 .on_blue();
//             frame.render_widget(greeting, frame.area());
//         })?;

//         if let event::Event::Key(key) = event::read()? {
//             if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
//                 return Ok(());
//             }
//         }
//     }
// }

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

    let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();
    println!("🔑 Successfully retrieved the round public key.");
    let current_block = client.blocks().at_latest().await?;
    let current_block_number = current_block.header().number;

    println!("🧊 Current block number: #{:?}", current_block_number);
    let etf = OnlineClient::<SubstrateConfig>::new().await?;

    // let mut mmr_store_file = File::create("mmr_store").unwrap();
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);

    // TODO: HKDF? just hash the seed?
    let ephem_msk = [1;32];

    match &cli.commands {
        Commands::New(args) => {        
            println!("🏭 Murmur: Generating Merkle mountain range");
            // create leaves
            let leaves = murmur::create::<TinyBLS377>(
                args.seed.clone().into(),
                args.schedule.clone(),
                ephem_msk,
                round_pubkey,
            );
            // populate MMR
            leaves.iter().for_each(|leaf| {
                // TODO: error handling
                mmr.push(leaf.1.clone()).unwrap();
            });

            println!("Write leaves {:?}", leaves.len());
            write_leaves(&leaves);

            let root = mmr.get_root()
                .expect("The MMR root should be calculable");
            let name = args.name.as_bytes().to_vec();

            // prepare and send tx from 'alice' account (for now)
            // should be configurable
            let create_anon_tx = etf::tx()
                .otp()
                .create(
                    root.0.into(), 
                    etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(name));
            // TODO: make the origin configurable
            let from = dev::alice();
            let events = etf
                .tx()
                .sign_and_submit_then_watch_default(&create_anon_tx, &from)
                .await?;
            println!("✅ MMR proxy account creation successful!");
            
        },
        Commands::Execute(args) => {
            
            // build balance transfer
            let bob = AccountKeyring::Bob.to_account_id().into();
            // get the value argument
            let v: u128 = args.amount
                .split_whitespace()
                .map(|r| r.replace('_', "").parse().unwrap())
                .collect::<Vec<_>>()[0];
            let balance_transfer_call = RuntimeCall::Balances(
                BalancesCall::transfer_allow_death {
                    dest: bob,
                    value: v,
            });
            handle_execute::<TinyBLS377>(
                etf.clone(),
                args.name.clone().as_bytes().to_vec(),
                args.seed.clone().as_bytes().to_vec(),
                args.when.clone(),
                ephem_msk,
                round_pubkey,
                balance_transfer_call,
            ).await;
        }, 
        _ => panic!("Hey, don't do that!"),
    }
    println!("Elapsed time: {:.2?}", before.elapsed());
    Ok(())
}

fn handle_create() {

}

async fn handle_execute<E: EngineBLS>(
    etf: OnlineClient<SubstrateConfig>,
    name: Vec<u8>,
    seed: Vec<u8>,
    when: BlockNumber,
    ephemeral_msk: [u8;32],
    pk: DoublePublicKey<E>,
    call: RuntimeCall,
) -> Option<()> {
    println!("Murmur: Execute Wallet Balance Transfer");
    let mut rng = ChaCha20Rng::seed_from_u64(1);

    let leaves: Vec<(BlockNumber, Leaf)> = load_leaves();

    let call_data = call.encode();
    let payload = murmur::execute::<E>(
        seed,
        when,
        call_data,
        leaves.clone(),
    ).map_err(|e| println!("Murmur execution failed due to {:?}", e)).unwrap();

    let root: Leaf = payload.root;
    let hash: Vec<u8> = payload.hash;
    let proof: MerkleProof<Leaf, MergeLeaves> = payload.proof;
    let target_leaf: Leaf = payload.target;
    let pos: u64 = payload.pos;

    let proof_items: Vec<Vec<u8>> = proof.proof_items().iter()
        .map(|leaf| leaf.0.to_vec().clone())
        .collect::<Vec<_>>();

    let bounded = <BoundedVec<_, ConstU32<32>>>::truncate_from(name);

    
    let proxy_call = RuntimeCall::Murmur(MurmurCall::proxy {
        name: bounded,
        position: pos,
        target_leaf: target_leaf.0,
        proof: proof_items,
        call: Box::new(call),
        when,
        hash,
    });

    let proxy_call_bytes: &[u8] = &proxy_call.encode();
    // then construct a scheduled transaction for "when"
    // 1. tlock
    let identity = murmur::build_identity(when);
    let timelocked_proxy_call = murmur::timelock_encrypt::<E>(
        identity,
        pk.1,
        ephemeral_msk,
        proxy_call_bytes,
    );
    let bounded_ciphertext = etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(timelocked_proxy_call);
    // 2. build tx
    let sealed_tx = etf::tx()
        .scheduler()
        .schedule_sealed(when, 127, bounded_ciphertext);
    // 3. submit tx
    
    let events = etf
        .tx()
        .sign_and_submit_then_watch_default(&sealed_tx, &dev::alice())
        .await;
    None

}

/// read an MMR from a file
fn load_leaves() -> Vec<(BlockNumber, Leaf)> {
    let mmr_store_file = File::open("mmr_store")
        .expect("Unable to open file");
    let leaves: Vec<(BlockNumber, Leaf)> = 
        serde_cbor::from_reader(mmr_store_file).unwrap();
    leaves
}

/// Write the MMR to a file
fn write_leaves(leaves: &[(BlockNumber, Leaf)]) {
    let mut mmr_store_file = File::create("mmr_store")
        .expect("should be ok");
    serde_cbor::to_writer(mmr_store_file, &leaves)
        .unwrap();
}

#[cfg(test)]
mod tests {
    // pub fn test_can_read_write_leaves() {
        
    // }
}