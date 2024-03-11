#![allow(missing_docs)]
use subxt::{OnlineClient, PolkadotConfig, config::Header};
use subxt_signer::sr25519::dev;

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "../artifacts/metadata.scale")]
pub mod etf {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new API client, configured to talk to Polkadot nodes.
    // let api = OnlineClient::<PolkadotConfig>::new().await?;
    // // fetch current block details we need:
    // let current_block = api.blocks().at_latest().await?;
    // // get validators and digests
    // let validators = current_block.storage().fetch(&etf::storage().aura().authorities()).await?.unwrap();
    // let digest_logs = &current_block.header().digest.logs;

    // println!("{:?}", digest_logs);

    // Create a new API client, configured to talk to Polkadot nodes.
    let api = OnlineClient::<PolkadotConfig>::new().await?;
    let mut last_block_number = 0u32; // Store the last processed block number

    loop {
        // Fetch the latest FINALIZED block
        let current_block = api.blocks().at_latest().await?;
        let current_block_number = current_block.header().number;
        // Check if a new block has been received
        if current_block_number != last_block_number {
            // Update the last processed block number
            last_block_number = current_block_number;

            // Fetch validators and digests for the current block
            let validators = current_block.storage().fetch(&etf::storage().aura().authorities()).await?.unwrap();
            let digest_logs = &current_block.header().digest.logs;

            // Print out the digest logs
            println!("Block Number: {}", current_block_number);
            println!("Validators: {:?}", validators);
            println!("Digest Logs: {:?}", digest_logs);
        }

        // Wait for some time before checking for the next block
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    Ok(())
}

