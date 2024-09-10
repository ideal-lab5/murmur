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
    #[arg()]
    name: String,
    #[arg()]
    password: String,
    #[arg(long)]
    block_number: u64,
    #[arg(short, long)]
    amount: String,
}

use sha3::Digest;

/// read an MMR from a file
fn load_leaves() -> Vec<(u64, Leaf)> {
    let mmr_store_file = File::open("mmr_store")
        .expect("Unable to open file");
    let leaves: Vec<(u64, Leaf)> = serde_cbor::from_reader(mmr_store_file)
        .unwrap();
    leaves
}

/// Write the MMR to a file
fn write_leaves(leaves: &[(BlockNumber, Leaf)]) {
    let mut mmr_store_file = File::create("mmr_store")
        .expect("should be ok");
    serde_cbor::to_writer(mmr_store_file, &leaves)
        .unwrap();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
   
    let cli = Cli::parse();

    let before = Instant::now();
    match &cli.commands {
        Commands::New(args) => {
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
            println!("🏭 Murmur: Generating Merkle mountain range");

            let etf = OnlineClient::<SubstrateConfig>::new().await?;

            let mut mmr_store_file = File::create("mmr_store").unwrap();
            let store = MemStore::default();
            let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);

            // TODO: HKDF? just hash the seed?
            let ephem_msk = [1;32];
            let leaves = murmur::create::<TinyBLS377>(
                args.seed.clone().into(),
                args.schedule.clone(),
                ephem_msk,
                round_pubkey,
            );

            leaves.iter().for_each(|leaf| {
                // TODO: error handling
                mmr.push(leaf.1.clone()).unwrap();
            });

            write_leaves(&leaves);

            let root = mmr.get_root()
                .expect("The MMR root should be calculable");

            let name = args.name.as_bytes().to_vec();

            let create_anon_tx = etf::tx()
                .otp()
                .create(
                    root.0.into(), 
                    etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(name));
            // TODO: make the origin a parameter
            let from = dev::alice();
            let events = etf
                .tx()
                .sign_and_submit_then_watch_default(&create_anon_tx, &from)
                .await?;
            println!("✅ MMR proxy account creation successful!");
            
        }
        _ => panic!("Hey, don't do that!"),
    }
    println!("Elapsed time: {:.2?}", before.elapsed());
    Ok(())
}


/// construct the encoded commitment for the round in which block_number h
async fn get_validator_set_id(
    client: OnlineClient<SubstrateConfig>,
    block_number: BlockNumber,
) -> Result<u64, Box<dyn std::error::Error>>  {
    let epoch_index_query = subxt::dynamic::storage("Beefy", "ValidatorSetId", ());
    let result = client.storage()
        .at_latest()
        .await?
        .fetch(&epoch_index_query)
        .await?;
    let epoch_index = result.unwrap().as_type::<u64>()?;
    
    Ok(epoch_index)
}

/// perform timelock encryption over BLS12-377
async fn tlock_encrypt<E: EngineBLS>(
    client: OnlineClient<SubstrateConfig>,
    round_pubkey: E::PublicKeyGroup,
    message: Vec<u8>,
    target: BlockNumber,
) -> Result<TLECiphertext<E>, Box<dyn std::error::Error>> {
    println!("🔒 Encrypting the message for target block #{:?}", target);
    // let msk = SecretKey(E::Scalar::rand(&mut OsRng));
    let epoch_index = get_validator_set_id(client.clone(), target).await?;
    let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
    let commitment = Commitment { payload, block_number: target, validator_set_id: epoch_index };
    // validators sign the SCALE encoded commitment, so that becomes our identity for TLE as well
    let id = Identity::new(&commitment.encode());
    // generate a random secret key
    let sk: [u8;32] = [1;32];
    // 2) tlock for encoded commitment (TODO: error handling)
    let ciphertext = tle(
        round_pubkey,
        sk,
        &message,
        id,
        OsRng,
    ).unwrap();
    Ok(ciphertext)
}

// /// perform timelock encryption over BLS12-377
// async fn tlock_decrypt<E: EngineBLS>(
//     ciphertext: TLECiphertext<E>,
//     signatures: Vec<IBESecret<E>>,
// ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//     let result = ciphertext.decrypt(signatures).unwrap();
//     Ok(result.message)
// }

#[cfg(test)]
mod tests {
    // pub fn test_can_read_write_leaves() {
        
    // }
}