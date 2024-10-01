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
use subxt::{backend::rpc::RpcClient, client::OnlineClient, config::SubstrateConfig};
use subxt_signer::sr25519::dev;
use std::fs::File;
use std::time::Instant;
use clap::{Parser, Subcommand};
use thiserror::Error;
use etf::runtime_types::node_template_runtime::RuntimeCall::Balances;
use sp_core::crypto::Ss58Codec;
use murmur_lib::{
    etf, create, prepare_execute, 
    MurmurStore, BlockNumber
};

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
    /// dispatch (proxy) a call to a murmur wallet
    Execute(WalletExecuteDetails),
}

#[derive(Parser)]
struct WalletCreationDetails {
    #[arg(long, short)]
    name: String,
    #[arg(long, short)]
    seed: String,
    #[clap(long, short)]
    validity: u32
}

#[derive(Parser)]
struct WalletExecuteDetails {
    #[arg(long, short)]
    name: String,
    #[arg(long, short)]
    seed: String,
    #[arg(long, short)]
    to: String,
    #[arg(short, long)]
    amount: String
}

#[derive(Error, Debug)]
pub enum CLIError {
    #[error("invalid public key")]
    InvalidPubkey,
}

/// the mmr_store file location
/// in future, make configurable
pub const MMR_STORE_FILEPATH: &str = "mmr_store";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let before = Instant::now();
    let ephem_msk = [1; 32];

    let (client, current_block_number, round_pubkey_bytes) = idn_connect().await?;

    match &cli.commands {
        Commands::New(args) => {
            println!("🏭 Murmur: Generating Merkle mountain range");
            // 1. prepare block schedule
            let mut schedule: Vec<BlockNumber> = Vec::new();
            for i in 2..args.validity + 2 {
                // wallet is 'active' in 2 blocks
                let next_block_number: BlockNumber = current_block_number + i;
                schedule.push(next_block_number);
            }
            // 2. create mmr
            let (call, mmr_store) = create(
                args.name.clone(),
                args.seed.clone(),
                ephem_msk,
                schedule,
                round_pubkey_bytes,
            );
            // 3. add to storage
            write_mmr_store(mmr_store.clone(), MMR_STORE_FILEPATH);
            // sign and send the call
            let from = dev::alice();
            let _events = client
                .tx()
                .sign_and_submit_then_watch_default(&call, &from)
                .await?;
            println!("✅ MMR proxy account creation successful!");
        }
        Commands::Execute(args) => {
            let from_ss58 = sp_core::crypto::AccountId32::from_ss58check(&args.to)
                .unwrap();

            let bytes: &[u8] = from_ss58.as_ref();
            let from_ss58_sized: [u8;32] = bytes.try_into().unwrap();
            let to = subxt::utils::AccountId32::from(from_ss58_sized);
            let v: u128 = args
                .amount
                .split_whitespace()
                .map(|r| r.replace('_', "").parse().unwrap())
                .collect::<Vec<_>>()[0];
            let balance_transfer_call = Balances(etf::balances::Call::transfer_allow_death {
                dest: subxt::utils::MultiAddress::<_, u32>::from(to),
                value: v,
            });

            let store: MurmurStore = load_mmr_store(MMR_STORE_FILEPATH);
            let target_block_number: BlockNumber = current_block_number + 1;
            println!("💾 Recovered Murmur store from local file");
            let tx = prepare_execute(
                args.name.clone(),
                args.seed.clone(),
                target_block_number,
                store,
                balance_transfer_call,
            )
            .await;
            // submit the tx using alice to sign it
            let _result = client.tx()
                .sign_and_submit_then_watch_default(&tx, &dev::alice())
                .await;
        },
    }
    println!("Elapsed time: {:.2?}", before.elapsed());
    Ok(())
}

/// async connection to the Ideal Network
/// if successful then fetch data
/// else error if unreachable
async fn idn_connect() -> 
    Result<(OnlineClient<SubstrateConfig>, BlockNumber, Vec<u8>), Box<dyn std::error::Error>> {
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
    let current_block_number: BlockNumber = current_block.header().number;
    println!("🧊 Current block number: #{:?}", current_block_number);
    Ok((client, current_block_number, round_pubkey_bytes))
}

/// read an MMR from a file
fn load_mmr_store(path: &str) -> MurmurStore {
    let mmr_store_file = File::open(path).expect("Unable to open file");
    let data: MurmurStore = serde_cbor::from_reader(mmr_store_file).unwrap();
    data
}

/// Write the MMR data to a file
fn write_mmr_store(mmr_store: MurmurStore, path: &str) {
    let mmr_store_file = File::create(path).expect("It should create the file");
    serde_cbor::to_writer(mmr_store_file, &mmr_store).unwrap();
}
