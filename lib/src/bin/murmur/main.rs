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

use clap::{Parser, Subcommand};
use murmur_lib::{
	create, etf, prepare_execute, BlockNumber, BoundedVec, MurmurStore, RuntimeCall,
};

use rand_core::{OsRng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sp_core::crypto::Ss58Codec;
use std::{fs::File, time::Instant};
use subxt::{
	backend::rpc::RpcClient, client::OnlineClient, config::SubstrateConfig,
};
use subxt_signer::sr25519::dev;
use thiserror::Error;

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
	validity: u32,
}

#[derive(Parser)]
struct WalletExecuteDetails {
	#[arg(long, short)]
	name: String,
	#[arg(long, short)]
	seed: String,
	#[arg(long, short)]
	to: String,
	#[arg(short, long, value_parser = clap::value_parser!(u128))]
	amount: u128,
}

#[derive(Error, Debug)]
pub enum CLIError {
	#[error("invalid public key")]
	InvalidPubkey,
	#[error("invalid address")]
	InvalidRecipient,
	#[error("could not parse input to a u128")]
	InvalidSendAmount,
	#[error("something went wrong while creating the MMR")]
	MurmurCreationFailed,
	#[error("something went wrong while executing the MMR wallet")]
	MurmurExecutionFailed,
	#[error("the murmur store is corrupted or empty")]
	CorruptedMurmurStore,
}

/// the mmr_store file location
/// in future, make configurable
pub const MMR_STORE_FILEPATH: &str = "mmr_store";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let cli = Cli::parse();
	let before = Instant::now();

	let (client, current_block_number, round_pubkey_bytes) = idn_connect().await?;
    let mut rng = ChaCha20Rng::from_rng(&mut OsRng).unwrap();

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
			let mmr_store = create(
                args.seed.as_bytes().to_vec(),
                0,
                schedule,
                round_pubkey_bytes,
                &mut rng,
            ).map_err(|_| CLIError::MurmurCreationFailed)?;

			// 3. add to storage
			write_mmr_store(mmr_store.clone(), MMR_STORE_FILEPATH);

			// 4. build the call
			let call = etf::tx().murmur().create(
				mmr_store.root.0,
				mmr_store.metadata.keys().len() as u64,
				BoundedVec(args.name.as_bytes().to_vec()),
			);

			// 5. sign and send the call
			client.tx().sign_and_submit_then_watch_default(&call, &dev::alice()).await?;

			println!("✅ MMR proxy account creation successful!");
		},
		Commands::Execute(args) => {
			// 1. build proxied call
			let from_ss58 = sp_core::crypto::AccountId32::from_ss58check(&args.to)
				.map_err(|_| CLIError::InvalidRecipient)?;
			let bytes: &[u8] = from_ss58.as_ref();
			let from_ss58_sized: [u8; 32] =
				bytes.try_into().map_err(|_| CLIError::InvalidRecipient)?;
			let to = subxt::utils::AccountId32::from(from_ss58_sized);
			let balance_transfer_call =
				RuntimeCall::Balances(etf::balances::Call::transfer_allow_death {
					dest: subxt::utils::MultiAddress::<_, u32>::from(to),
					value: args.amount,
				});

			// 2. load the MMR store
			let store: MurmurStore = load_mmr_store(MMR_STORE_FILEPATH)?;
			println!("💾 Recovered Murmur store from local file");

			// 3. get the proxy data
			let proxy_data = prepare_execute(
				args.seed.as_bytes().to_vec(),
				current_block_number + 1,
				store,
				&balance_transfer_call,
                &mut rng,
			)
			.map_err(|_| CLIError::MurmurExecutionFailed)?;

			// 4. build the call
			let call = etf::tx().murmur().proxy(
				BoundedVec(args.name.as_bytes().to_vec()),
				proxy_data.position,
				proxy_data.hash,
				proxy_data.ciphertext,
				proxy_data.proof_items,
				proxy_data.size,
				balance_transfer_call,
			);
			// 5. sign and send the call
			client.tx().sign_and_submit_then_watch_default(&call, &dev::alice()).await?;
		},
	}
	println!("Elapsed time: {:.2?}", before.elapsed());
	Ok(())
}

/// Async connection to the Ideal Network
/// if successful then fetch data
/// else error if unreachable
async fn idn_connect(
) -> Result<(OnlineClient<SubstrateConfig>, BlockNumber, Vec<u8>), Box<dyn std::error::Error>> {
	println!("🎲 Connecting to Ideal network (local node)");
	let ws_url = std::env::var("WS_URL").unwrap_or_else(|_| {
		let fallback_url = "ws://localhost:9944".to_string();
		println!("⚠️ WS_URL environment variable not set. Using fallback URL: {}", fallback_url);
		fallback_url
	});

	let rpc_client = RpcClient::from_url(&ws_url).await?;
	let client = OnlineClient::<SubstrateConfig>::from_rpc_client(rpc_client.clone()).await?;
	println!("🔗 RPC Client: connection established");

	// fetch the round public key from etf runtime storage
	let round_key_query = subxt::dynamic::storage("Etf", "RoundPublic", ());
	let result = client.storage().at_latest().await?.fetch(&round_key_query).await?;
	let round_pubkey_bytes = result.unwrap().as_type::<Vec<u8>>()?;

	println!("🔑 Successfully retrieved the round public key.");

	let current_block = client.blocks().at_latest().await?;
	let current_block_number: BlockNumber = current_block.header().number;
	println!("🧊 Current block number: #{:?}", current_block_number);
	Ok((client, current_block_number, round_pubkey_bytes))
}

/// read an MMR from a file
fn load_mmr_store(path: &str) -> Result<MurmurStore, CLIError> {
	let mmr_store_file = File::open(path).expect("Unable to open file");
	let data: MurmurStore =
		serde_cbor::from_reader(mmr_store_file).map_err(|_| CLIError::CorruptedMurmurStore)?;
	Ok(data)
}

/// Write the MMR data to a file
fn write_mmr_store(mmr_store: MurmurStore, path: &str) {
	let mmr_store_file = File::create(path).expect("It should create the file");
	serde_cbor::to_writer(mmr_store_file, &mmr_store).unwrap();
}
