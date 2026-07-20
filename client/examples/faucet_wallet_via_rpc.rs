use avail_rust_client::prelude::*;
use std::{env, fs};
use tokio::time::{Duration, timeout};

fn env_value(key: &str) -> Result<String, Error> {
	env::var(key).map_err(|_| "missing required environment variable".into())
}

fn env_u64(key: &str, default: u64) -> u64 {
	env::var(key)
		.ok()
		.and_then(|value| value.parse::<u64>().ok())
		.unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
	env::var(key)
		.ok()
		.map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
		.unwrap_or(default)
}

fn parse_secret_line(line: &str) -> Option<String> {
	let trimmed = line.trim();
	if trimmed.is_empty() || trimmed.starts_with('#') {
		return None;
	}
	let raw = trimmed
		.split_once('=')
		.map(|(_, value)| value.trim())
		.unwrap_or(trimmed);
	let unquoted = raw.trim_matches('"').trim_matches('\'').trim();
	if unquoted.is_empty() {
		None
	} else {
		Some(unquoted.to_string())
	}
}

fn read_treasury_seed() -> Result<String, Error> {
	let path = env_value("TREASURY_SEED_PATH")?;
	let content = fs::read_to_string(path).map_err(|_| "failed to read treasury seed")?;
	content
		.lines()
		.find_map(parse_secret_line)
		.ok_or_else(|| "treasury seed is empty".into())
}

async fn print_balance(client: &Client, address: AccountId, prefix: &str) -> Result<(), Error> {
	let info = client.best().account_info(address.clone()).await?;
	println!("{prefix}_address={address}");
	println!("{prefix}_nonce={}", info.nonce);
	println!("{prefix}_free={}", info.data.free);
	println!("{prefix}_reserved={}", info.data.reserved);
	println!("{prefix}_frozen={}", info.data.frozen);
	Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
	let endpoint = env::var("ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9952".to_string());
	let mode = env::var("MODE").unwrap_or_else(|_| "balance".to_string());

	match mode.as_str() {
		"balance" | "validate" => {
			let address = env_value("ADDRESS")?
				.parse::<AccountId>()
				.map_err(|_| "invalid address")?;
			let client = Client::new(&endpoint).await?;
			println!("ok=true");
			println!("mode={mode}");
			println!("endpoint={endpoint}");
			print_balance(&client, address, "account").await?;
		},
		"treasury" => {
			let seed = read_treasury_seed()?;
			let signer = Keypair::from_str(&seed)?;
			let address = signer.public_key().to_account_id();
			let client = Client::new(&endpoint).await?;
			println!("ok=true");
			println!("mode=treasury");
			println!("endpoint={endpoint}");
			print_balance(&client, address, "treasury").await?;
		},
		"transfer" => {
			let destination = env_value("ADDRESS")?
				.parse::<AccountId>()
				.map_err(|_| "invalid address")?;
			let amount = env_value("AMOUNT_PLANCK")?
				.parse::<u128>()
				.map_err(|_| "invalid AMOUNT_PLANCK")?;
			let min_treasury_balance = env::var("MIN_TREASURY_BALANCE_PLANCK")
				.unwrap_or_else(|_| "0".to_string())
				.parse::<u128>()
				.map_err(|_| "invalid MIN_TREASURY_BALANCE_PLANCK")?;
			let seed = read_treasury_seed()?;
			let signer = Keypair::from_str(&seed)?;
			let client = Client::new(&endpoint).await?;
			let treasury = signer.public_key().to_account_id();
			let treasury_before = client.best().account_info(treasury.clone()).await?;
			let recipient_before = client.best().account_info(destination.clone()).await?;
			let required_balance = amount
				.checked_add(min_treasury_balance)
				.ok_or("treasury balance check overflow")?;
			if treasury_before.data.free < required_balance {
				return Err("treasury balance too low".into());
			}

			let tx = client.tx().balances().transfer_keep_alive(destination.clone(), amount);
			let submitted = tx.sign_and_submit(&signer, Default::default()).await?;
			let wait_finalized = env_bool("WAIT_FINALIZED", false);
			let receipt_timeout_secs = env_u64("RECEIPT_TIMEOUT_SECS", 90);
			let receipt = timeout(Duration::from_secs(receipt_timeout_secs), submitted.receipt(wait_finalized))
				.await
				.map_err(|_| "timed out waiting for transfer receipt")??;
			let Some(receipt) = receipt else {
				return Err("transfer transaction dropped".into());
			};
			let events = receipt.events().await?;
			if !events.is_extrinsic_success_present() {
				return Err("transfer extrinsic did not succeed".into());
			}
			let transfer = events
				.first::<avail::balances::events::Transfer>()
				.ok_or("transfer event missing")?;
			let treasury_after = client.best().account_info(treasury.clone()).await?;
			let recipient_after = client.best().account_info(destination.clone()).await?;

			println!("ok=true");
			println!("mode=transfer");
			println!("endpoint={endpoint}");
			println!("treasury_address={treasury}");
			println!("recipient_address={destination}");
			println!("amount_planck={amount}");
			println!("min_treasury_balance_planck={min_treasury_balance}");
			println!("treasury_free_before={}", treasury_before.data.free);
			println!("treasury_free_after={}", treasury_after.data.free);
			println!("recipient_free_before={}", recipient_before.data.free);
			println!("recipient_free_after={}", recipient_after.data.free);
			println!("ext_hash={:?}", receipt.ext_hash);
			println!("block_height={}", receipt.block_height);
			println!("block_hash={:?}", receipt.block_hash);
			println!("event_from={}", transfer.from);
			println!("event_to={}", transfer.to);
			println!("event_amount={}", transfer.amount);
			println!("wait_finalized={wait_finalized}");
		},
		_ => return Err("unsupported MODE".into()),
	}

	Ok(())
}
