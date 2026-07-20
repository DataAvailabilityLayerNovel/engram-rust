use avail_rust_client::prelude::*;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Error> {
	let endpoint = env::var("ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9952".to_string());
	let signer = alice();
	let account = signer.public_key().to_account_id();
	let info = Client::new(&endpoint)
		.await?
		.best()
		.account_info(account.clone())
		.await?;

	println!("account={account}");
	println!("nonce={}", info.nonce);
	println!("free={}", info.data.free);
	println!("reserved={}", info.data.reserved);
	println!("frozen={}", info.data.frozen);
	Ok(())
}
