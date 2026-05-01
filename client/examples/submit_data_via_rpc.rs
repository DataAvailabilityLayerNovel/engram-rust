use avail_rust_client::prelude::*;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{timeout, Duration};

fn env_u32(key: &str, default: u32) -> u32 {
	env::var(key).ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
	let endpoint = env::var("ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9951".to_string());
	let app_id = env_u32("APP_ID", 7);
	let payload = env::var("PAYLOAD").unwrap_or_else(|_| {
		let ts = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		format!("engram-submit-{ts}")
	});

	let client = Client::new(&endpoint).await?;
	let signer = alice();

	let options = Options::new(app_id);
	let tx = client.tx().data_availability().submit_data(payload.as_bytes().to_vec());
	let submitted = tx.sign_and_submit(&signer, options).await?;
	println!("submitted ext_hash={:?}", submitted.ext_hash);

	let receipt = timeout(Duration::from_secs(90), submitted.receipt(true))
		.await
		.map_err(|_| "Timed out waiting for transaction receipt")??;
	let Some(receipt) = receipt else { return Err("Transaction got dropped (no receipt)".into()); };

	let events = receipt.events().await?;
	if !events.is_extrinsic_success_present() {
		return Err("Extrinsic did not succeed".into());
	}

	println!("submit_data ok");
	println!("endpoint={endpoint}");
	println!("app_id={app_id}");
	println!("block_height={}", receipt.block_height);
	println!("block_hash={:?}", receipt.block_hash);
	println!("ext_hash={:?}", receipt.ext_hash);
	Ok(())
}

