#![allow(missing_docs)]
use subxt::{OnlineClient, PolkadotConfig, config::Header};
use subxt_signer::sr25519::dev;

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "./artifacts/metadata.scale")]
pub mod etf {}

mod otp;


use std::io::{Read, Write, BufRead, BufReader};
use std::fs::File;
use std::time::Duration;
use clap::{Args, Parser, Subcommand};

use ckb_merkle_mountain_range::{
    MMR, Merge, Result as MMRResult,
    util::{MemMMR, MemStore},
};

use rand_chacha::{
    ChaCha20Rng,
    rand_core::SeedableRng,
};

use etf_crypto_primitives::{
    ibe::fullident::BfIbe,
    client::etf_client::{AesIbeCt, DefaultEtfClient, EtfClient},
    utils::{convert_to_bytes, hash_to_g1},
};

use sp_keyring::AccountKeyring;
use node_runtime::{self, BalancesCall, OtpCall, RuntimeCall, pallet_etf::Ciphertext};
use frame_support::{BoundedVec, traits::ConstU32};

use std::time::Instant;
use indicatif::ProgressBar;

use codec::Encode;

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
    #[arg()]
    name: String,
    #[arg()]
    password: String,
//     min: u32,
//     max: u32,
}

#[derive(Parser)]
struct WalletExecuteDetails {
    #[arg()]
    name: String,
    #[arg()]
    password: String,
    #[arg(long)]
    delay: u64,
    #[arg(short, long)]
    amount: String,
}

use sp_core::Bytes;
use sha3::Digest;

#[derive(Eq, PartialEq, Clone, Debug, Default)]
struct Leaf(pub Vec<u8>);
impl From<Vec<u8>> for Leaf {
    fn from(data: Vec<u8>) -> Self {
        let mut hasher = sha3::Sha3_256::default();
        hasher.update(&data);
        let hash = hasher.finalize();
        Leaf(hash.to_vec().into())
    }
}

struct MergeLeaves;

impl Merge for MergeLeaves {
    type Item = Leaf;
    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> MMRResult<Self::Item> {
		let mut hasher = sha3::Sha3_256::default();
        hasher.update(&lhs.0);
        hasher.update(&rhs.0);
        let hash = hasher.finalize();
        Ok(Leaf(hash.to_vec().into()))
    }
}
// /// the runtime call type
// type Call = runtime_types::node::RuntimeCall;
// /// the balances call type
// type BalancesCall = runtime_types::pallet_balances::pallet::Call;
// /// the proxy call type
// type ProxyCall = runtime_types::pallet_proxy::pallet::Call;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
   
    let cli = Cli::parse();

    let before = Instant::now();
    match &cli.commands {
        Commands::New(args) => {
            println!("OTP Wallet Client: Create new wallet");
           
            let bar = ProgressBar::new_spinner();
            bar.enable_steady_tick(Duration::from_millis(100));

            // TODO: should probably use sha256 instead
            let mut hasher = sha3::Sha3_256::default();
            hasher.update(args.password.as_bytes());
            let hash = hasher.finalize();

            let totp = otp::BOTPGenerator::new(hash.to_vec());
            let etf = OnlineClient::<PolkadotConfig>::new().await?;
            let current_block = etf.blocks().at_latest().await?;
            let current_slot_number: u64 = current_block.storage()
                .fetch(&etf::storage().aura().current_slot())
                .await?.unwrap().0;
            let ibe_params = current_block.storage()
                .fetch(&etf::storage().etf().ibe_params())
                .await?.unwrap();
        
            let mut rng = ChaCha20Rng::seed_from_u64(1);

            // write MMR leaves to a file
            let mut mmr_store_file = File::create("mmr_store").unwrap();

            let store = MemStore::default();
            let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);

            println!("Generating Codes");
            let mut ciphertexts = Vec::new();
            for i in 1..101 {
                let id = (current_slot_number + i).to_string().as_bytes().to_vec();
                let otp_code = totp.generate((current_slot_number + i) as u32);
                // TODO: Do we need to encrypt the entire otp code or just a hash of it?
                // AesIbeCt
                let ct = DefaultEtfClient::<BfIbe>::encrypt(
                    ibe_params.1.clone(),
                    ibe_params.2.clone(),
                    &otp_code.as_bytes(), 
                    vec![id],
                    1,
                    &mut rng,
                ).unwrap();
                

                let s = Ciphertext {
                    ciphertext: <BoundedVec<_, ConstU32<512>>>::truncate_from(ct.aes_ct.ciphertext),
                    nonce: <BoundedVec<_, ConstU32<96>>>::truncate_from(ct.aes_ct.nonce),
                    capsule: <BoundedVec<_, ConstU32<512>>>::truncate_from(ct.etf_ct[0].clone()),
                };

                // mmr_store_file.write_all(&s.encode());
                // mmr_store_file.write_all(b"\n");
                let _ = mmr.push(Leaf::from(s.encode()));
                ciphertexts.push(s);
            }

            write_leaves(&ciphertexts);
            let root = mmr.get_root().expect("The MMR root should be calculable");

            let name = args.name.as_bytes().to_vec();

            let create_anon_tx = etf::tx()
                .otp()
                .create(
                    root.0.into(), 
                    etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(name));
            let from = dev::alice();
            let events = etf
                .tx()
                .sign_and_submit_then_watch_default(&create_anon_tx, &from)
                .await?
                .wait_for_finalized_success()
                .await?;

            println!("Submitted transaction");
            // Find a Transfer event and print it.
            let transfer_event = events.find_first::<etf::otp::events::OtpProxyCreated>()?;
            if let Some(_event) = transfer_event {
                println!("OTP wallet creation successful!");
                bar.finish();
            }
        },
        Commands::Execute(args) => {
            println!("OTP Wallet Client: Execute Wallet Balance Transfer");
           
            let bar = ProgressBar::new_spinner();
            bar.enable_steady_tick(Duration::from_millis(100));
            let mut hasher = sha3::Sha3_256::default();
            hasher.update(args.password.as_bytes());
            let hash = hasher.finalize();
            let totp = otp::BOTPGenerator::new(hash.to_vec());
            let etf = OnlineClient::<PolkadotConfig>::new().await?;

            let mut rng = ChaCha20Rng::seed_from_u64(1);
            let mut block_subscription = etf.blocks().subscribe_all().await?;
            if let Some(Ok(current_block)) = block_subscription.next().await {
                let current_slot_number: u64 = current_block.storage()
                    .fetch(&etf::storage().aura().current_slot())
                    .await?.unwrap().0;
                let ibe_params = current_block.storage()
                    .fetch(&etf::storage().etf().ibe_params())
                    .await?.unwrap();
                // Build a balance transfer extrinsic.
                // let dest = dev::bob().public_key().into();
                let bob = AccountKeyring::Bob.to_account_id().into();

                let v: u128 = args.amount
                    .split_whitespace()
                    .map(|r| r.replace('_', "").parse().unwrap())
                    .collect::<Vec<_>>()[0];

                let balance_transfer_call = RuntimeCall::Balances(BalancesCall::transfer_allow_death {
                    dest: bob,
                    value: v,
                });

                let otp_code = totp.generate((current_slot_number + args.delay - 1) as u32);
                println!("Will execute at {:?} using code {:?} ", current_block.header().number + (args.delay as u32), otp_code);

                let bounded = <BoundedVec<_, ConstU32<32>>>::truncate_from(args.name.as_bytes().to_vec());
                let id = (current_slot_number + args.delay).to_string().as_bytes().to_vec();

                let expected_otp_ciphertext = DefaultEtfClient::<BfIbe>::encrypt(
                    ibe_params.1.clone(),
                    ibe_params.2.clone(),
                    &otp_code.as_bytes(),
                    vec![id.clone()],
                    1,
                    &mut rng,
                ).unwrap();

                let expected_otp_ct = Ciphertext {
                    ciphertext: <BoundedVec<_, ConstU32<512>>>::truncate_from(expected_otp_ciphertext.aes_ct.ciphertext),
                    nonce: <BoundedVec<_, ConstU32<96>>>::truncate_from(expected_otp_ciphertext.aes_ct.nonce),
                    capsule: <BoundedVec<_, ConstU32<512>>>::truncate_from(expected_otp_ciphertext.etf_ct[0].clone()),
                };

                // prepare the merkle proof
                let mut mmr = load_mmr();
                // get the position of the expected otp ciphertext
                let pos = mmr.push(Leaf::from(expected_otp_ct.encode())).unwrap();
                let proof = mmr.gen_proof(vec![pos]).expect("should be ok");
                let proof_items: Vec<Vec<u8>> = proof.proof_items().iter()
                    .map(|leaf| leaf.0.to_vec().clone())
                    .collect::<Vec<_>>();

                // println!("Successfully created the Merkle proof");
                let proxy_call = RuntimeCall::OTP(OtpCall::proxy {
                    name: bounded,
                    otp: otp_code.as_bytes().to_vec().as_slice().try_into().expect("should be ok"),
                    ciphertext: expected_otp_ct,
                    position: pos,
                    proof: proof_items,
                    call: Box::new(balance_transfer_call),
                });

                let timelocked_proxy_call = DefaultEtfClient::<BfIbe>::encrypt(
                    ibe_params.1.clone(),
                    ibe_params.2.clone(),
                    &proxy_call.encode(), 
                    vec![id],
                    1,
                    &mut rng,
                ).unwrap();

                let sealed_tx = etf::tx()
                    .scheduler()
                    .schedule_sealed(
                        current_block.header().number + args.delay as u32, 127, 
                        etf::runtime_types::pallet_etf::Ciphertext {
                            ciphertext: 
                                etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(timelocked_proxy_call.aes_ct.ciphertext),
                            nonce: 
                                etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(timelocked_proxy_call.aes_ct.nonce),
                            capsule: 
                                etf::runtime_types::bounded_collections::bounded_vec::BoundedVec(timelocked_proxy_call.etf_ct[0].clone()),
                });

                let events = etf
                    .tx()
                    .sign_and_submit_then_watch_default(&sealed_tx, &dev::alice())
                    .await?
                    .wait_for_finalized_success()
                    .await?;
            }
            bar.finish();
            println!("Done!");
            
        }
        _ => panic!("Hey, don't do that!"),
    }
    println!("Elapsed time: {:.2?}", before.elapsed());
    Ok(())
}

fn load_mmr() -> MemMMR<Leaf, MergeLeaves> {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeLeaves>::new(0, store);
    let file = File::open("mmr_store").expect("Unable to open file");
    let mut reader = BufReader::new(file);
    let mut file_contents = Vec::new();

    reader.read_to_end(&mut file_contents).expect("Unable to read file");

    let mut start = 0;
    while let Some(mut end) = file_contents[start..].iter().position(|&x| x == b'\n') {
        end += start;
        let leaf = Leaf::from(file_contents[start..end].to_vec());
        let _ = mmr.push(leaf).expect("Unable to push Leaf");
        start = end + 1;
    }

    mmr
}

// Write the ciphertext to a file
// TODO error handling
fn write_leaves(ciphertexts: &[Ciphertext]) {
   let mut mmr_store_file = File::create("mmr_store").expect("should be ok");
    
    for s in ciphertexts {
        // Serialize the struct to CBOR format
        // let encoded = serde_json::to_vec(s)?;
        mmr_store_file.write_all(&s.encode()).expect("should be ok");
        mmr_store_file.write_all(b"\n").expect("should be ok");
    }
    
}

// /// convert a u64 to a Vec
// fn get_slot(i: u64) -> Vec<u8> {
//     i.to_string().as_bytes().to_vec()
// }