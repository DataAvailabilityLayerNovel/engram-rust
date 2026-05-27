//! Fetch a single Kate cell scalar at (block, row, col) and write 32-byte LE encoding to OUT_PATH.
use avail_rust_client::prelude::*;
use avail_rust_core::rpc::kate::Cell;
use std::env;
use std::fs;
use std::path::Path;

fn env_u32(key: &str) -> Result<u32, Error> {
	let raw = env::var(key).map_err(|_| Error::from("missing env var"))?;
	raw.parse::<u32>()
		.map_err(|_| Error::from("invalid u32 env var"))
}

fn u256_to_bytes32(x: U256) -> [u8; 32] {
	let mut out = [0u8; 32];
	out.copy_from_slice(&x.to_little_endian());
	out
}

fn hex32(bytes: &[u8; 32]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<(), Error> {
	let endpoint = env::var("ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9951".to_string());
	let block = env_u32("BLOCK")?;
	let row = env_u32("ROW")?;
	let col = env_u32("COL")?;
	let out_path = env::var("OUT_PATH").map_err(|_| Error::from("missing OUT_PATH"))?;

	let client = Client::new(&endpoint).await?;
	let block_hash = client
		.chain()
		.block_hash(Some(block))
		.await?
		.ok_or("block hash not found for BLOCK")?;

	let cell = Cell { row, col };
	let proofs = client
		.chain()
		.kate_query_proof(vec![cell], Some(block_hash))
		.await?;
	let (scalar, _proof) = proofs
		.into_iter()
		.next()
		.ok_or("kate_query_proof returned no proofs")?;

	let bytes = u256_to_bytes32(scalar);
	if let Some(parent) = Path::new(&out_path).parent() {
		if !parent.as_os_str().is_empty() {
			fs::create_dir_all(parent).map_err(|_| Error::from("create_dir_all failed"))?;
		}
	}
	fs::write(&out_path, bytes).map_err(|_| Error::from("write cell file failed"))?;

	println!("fetch_kate_cell ok");
	println!("endpoint={endpoint}");
	println!("block={block} row={row} col={col}");
	println!("out_path={out_path}");
	println!("submitted_cell_len=32");
	println!("submitted_cell_hex={}", hex32(&bytes));
	Ok(())
}
