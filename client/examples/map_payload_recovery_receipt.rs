use avail_rust_client::prelude::*;
use avail_rust_core::{
	header::DataLookupItem,
	rpc::system::fetch_extrinsics::Options as FetchExtrinsicsOptions,
};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::Path, str::FromStr};

const DATA_CHUNK_SIZE: u32 = 31;
const BLOCK_CHUNK_SIZE: u32 = 32;
const V4_RUNTIME_GRID_ROWS_FALLBACK: u32 = 64;
const V4_RUNTIME_GRID_COLS_FALLBACK: u32 = 64;

#[derive(Debug, Deserialize)]
struct SubmissionReceipt {
	network: String,
	user_run_id: String,
	user_run_dir: String,
	payload_sha256: String,
	payload_size: u64,
	submit_full: String,
	submit_endpoint: String,
	app_id: u32,
	block_number: u32,
	block_hash: String,
	extrinsic_hash: String,
	finalized: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ExpandedAppRange {
	app_id: u32,
	start_scalar: u32,
	end_scalar: u32,
	scalar_count: u32,
}

#[derive(Debug, Serialize)]
struct AppIdRange {
	app_id: u32,
	start_scalar: u32,
	end_scalar: u32,
	scalar_count: u32,
	start_stream_byte: u64,
	end_stream_byte: u64,
}

#[derive(Debug, Serialize)]
struct Grid {
	rows: u32,
	cols: u32,
	chunk_size: u32,
	block_chunk_size: u32,
	source: String,
}

#[derive(Debug, Serialize)]
struct RequiredCell {
	scalar_index: u32,
	row: u32,
	col: u32,
}

#[derive(Debug, Serialize)]
struct ExpectedPayload {
	size: u64,
	sha256: String,
}

#[derive(Debug, Serialize)]
struct ExtrinsicMatch {
	tx_index: u32,
	ext_hash: String,
	pallet_id: u8,
	variant_id: u8,
	signer_app_id: Option<u32>,
}

#[derive(Debug, Serialize)]
struct PayloadRecoveryMap {
	version: u32,
	mapper: String,
	network: String,
	user_run_id: String,
	user_run_dir: String,
	submit_full: String,
	endpoint: String,
	block_number: u32,
	block_hash: String,
	extrinsic_hash: String,
	tx_index: u32,
	extrinsic_match: ExtrinsicMatch,
	header_extension: String,
	data_lookup_size_scalars: u32,
	data_lookup_ranges: Vec<ExpandedAppRange>,
	app_id_range_from_data_lookup: AppIdRange,
	grid: Grid,
	required_original_grid_cells: Vec<RequiredCell>,
	expected_payload: ExpectedPayload,
	finalized: bool,
	recovery_status: String,
	notes: Vec<String>,
}

fn usage() -> String {
	"usage: map_payload_recovery_receipt <submission-receipt.json> [payload-recovery-map.json]".to_string()
}

fn expand_lookup(size: u32, index: Vec<DataLookupItem>) -> Vec<ExpandedAppRange> {
	let mut ranges = Vec::new();
	let mut prev_app_id = 0u32;
	let mut offset = 0u32;

	for item in index {
		ranges.push(ExpandedAppRange {
			app_id: prev_app_id,
			start_scalar: offset,
			end_scalar: item.start,
			scalar_count: item.start.saturating_sub(offset),
		});
		prev_app_id = item.app_id;
		offset = item.start;
	}

	if offset < size {
		ranges.push(ExpandedAppRange {
			app_id: prev_app_id,
			start_scalar: offset,
			end_scalar: size,
			scalar_count: size.saturating_sub(offset),
		});
	}

	ranges
}

fn required_cells(range: &AppIdRange, cols: u32) -> Result<Vec<RequiredCell>, Box<dyn std::error::Error>> {
	if cols == 0 {
		return Err("block length cols must be non-zero".into());
	}

	let mut cells = Vec::with_capacity(range.scalar_count as usize);
	for scalar_index in range.start_scalar..range.end_scalar {
		cells.push(RequiredCell {
			scalar_index,
			row: scalar_index / cols,
			col: scalar_index % cols,
		});
	}
	Ok(cells)
}

fn env_u32(name: &str) -> Result<Option<u32>, Box<dyn std::error::Error>> {
	match env::var(name) {
		Ok(value) => Ok(Some(value.parse::<u32>().map_err(|err| {
			format!("{name} must be a positive integer, got {value:?}: {err}")
		})?)),
		Err(env::VarError::NotPresent) => Ok(None),
		Err(err) => Err(format!("failed to read {name}: {err}").into()),
	}
}

fn v4_runtime_grid_fallback() -> Result<(u32, u32, u32, String), Box<dyn std::error::Error>> {
	let rows = env_u32("AVAIL_RUNTIME_GRID_ROWS")?.unwrap_or(V4_RUNTIME_GRID_ROWS_FALLBACK);
	let cols = env_u32("AVAIL_RUNTIME_GRID_COLS")?.unwrap_or(V4_RUNTIME_GRID_COLS_FALLBACK);
	let chunk_size = env_u32("AVAIL_RUNTIME_GRID_BLOCK_CHUNK_SIZE")?.unwrap_or(BLOCK_CHUNK_SIZE);
	if rows == 0 || cols == 0 || chunk_size == 0 {
		return Err("runtime grid fallback rows, cols, and block chunk size must be non-zero".into());
	}
	Ok((
		rows,
		cols,
		chunk_size,
		"v4_private_testnet_runtime_grid_fallback".to_string(),
	))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = env::args().collect::<Vec<_>>();
	if args.len() < 2 || args.len() > 3 {
		return Err(usage().into());
	}

	let receipt_path = &args[1];
	let out_path = args.get(2).cloned().unwrap_or_else(|| {
		let parent = Path::new(receipt_path)
			.parent()
			.unwrap_or_else(|| Path::new("."));
		parent
			.join("payload-recovery-map.json")
			.to_string_lossy()
			.into_owned()
	});

	let receipt: SubmissionReceipt = serde_json::from_slice(&fs::read(receipt_path)?)?;
	let endpoint = env::var("ENDPOINT").unwrap_or_else(|_| receipt.submit_endpoint.clone());
	let client = Client::new(&endpoint).await?;
	let chain = client.chain();

	let expected_block_hash = <H256 as FromStr>::from_str(&receipt.block_hash)?;
	let actual_block_hash = chain
		.block_hash(Some(receipt.block_number))
		.await?
		.ok_or("block hash not found for receipt block_number")?;
	if actual_block_hash != expected_block_hash {
		return Err(format!(
			"receipt block hash mismatch: receipt={} chain={actual_block_hash:?}",
			receipt.block_hash
		)
		.into());
	}

	let tx_hash = <H256 as FromStr>::from_str(&receipt.extrinsic_hash)?;
	let ext_infos = client
		.block(receipt.block_number)
		.extrinsic_infos(
			FetchExtrinsicsOptions::new()
				.encode_as(EncodeSelector::None)
				.filter(tx_hash),
		)
		.await?;
	let ext_info = ext_infos
		.first()
		.ok_or("extrinsic hash from receipt was not found in receipt block")?;
	if let Some(signer) = &ext_info.signer_payload {
		if signer.app_id != receipt.app_id {
			return Err(format!(
				"receipt app_id mismatch: receipt={} extrinsic={}",
				receipt.app_id, signer.app_id
			)
			.into());
		}
	}

	let header = chain
		.block_header(Some(expected_block_hash))
		.await?
		.ok_or("block header not found for receipt block hash")?;

	let (header_extension, lookup_size, lookup_index, fallback_grid) = match header.extension {
		HeaderExtension::V3(ext) => {
			let fallback = (ext.commitment.rows > 0 && ext.commitment.cols > 0).then(|| {
				(
					u32::from(ext.commitment.rows),
					u32::from(ext.commitment.cols),
					BLOCK_CHUNK_SIZE,
					"v3_header_commitment_fallback".to_string(),
				)
			});
			("V3".to_string(), ext.app_lookup.size, ext.app_lookup.index, fallback)
		},
		HeaderExtension::V4(ext) => (
			"V4".to_string(),
			ext.app_lookup.size,
			ext.app_lookup.index,
			Some(v4_runtime_grid_fallback()?),
		),
	};

	let (grid_rows, grid_cols, block_chunk_size, grid_source) =
		match chain.kate_block_length(Some(expected_block_hash)).await {
			Ok(block_length) => (
				block_length.rows,
				block_length.cols,
				block_length.chunk_size,
				"kate_blockLength".to_string(),
			),
			Err(err) => {
				let fallback = fallback_grid.ok_or_else(|| {
					format!("kate_blockLength failed and no header fallback is available: {err:?}")
				})?;
				eprintln!(
					"payload_recovery_map_warning=kate_blockLength_unavailable_using_{} rows={} cols={} block_chunk_size={} err={err:?}",
					fallback.3, fallback.0, fallback.1, fallback.2
				);
				fallback
			},
		};

	let data_lookup_ranges = expand_lookup(lookup_size, lookup_index);
	let selected = data_lookup_ranges
		.iter()
		.find(|range| range.app_id == receipt.app_id && range.scalar_count > 0)
		.or_else(|| data_lookup_ranges.iter().find(|range| range.app_id == receipt.app_id))
		.ok_or("receipt app_id was not present in header extension DataLookup")?;

	let app_id_range = AppIdRange {
		app_id: receipt.app_id,
		start_scalar: selected.start_scalar,
		end_scalar: selected.end_scalar,
		scalar_count: selected.scalar_count,
		start_stream_byte: u64::from(selected.start_scalar) * u64::from(DATA_CHUNK_SIZE),
		end_stream_byte: u64::from(selected.end_scalar) * u64::from(DATA_CHUNK_SIZE),
	};

	let grid = Grid {
		rows: grid_rows,
		cols: grid_cols,
		chunk_size: DATA_CHUNK_SIZE,
		block_chunk_size,
		source: grid_source,
	};
	let capacity = grid
		.rows
		.checked_mul(grid.cols)
		.ok_or("grid capacity overflow")?;
	if app_id_range.end_scalar > capacity {
		return Err(format!(
			"app_id range exceeds grid capacity: end_scalar={} capacity={capacity}",
			app_id_range.end_scalar
		)
		.into());
	}

	let map = PayloadRecoveryMap {
		version: 1,
		mapper: "avail-rust/client/examples/map_payload_recovery_receipt.rs".to_string(),
		network: receipt.network,
		user_run_id: receipt.user_run_id,
		user_run_dir: receipt.user_run_dir,
		submit_full: receipt.submit_full,
		endpoint,
		block_number: receipt.block_number,
		block_hash: format!("{actual_block_hash:?}"),
		extrinsic_hash: format!("{:?}", ext_info.ext_hash),
		tx_index: ext_info.ext_index,
		extrinsic_match: ExtrinsicMatch {
			tx_index: ext_info.ext_index,
			ext_hash: format!("{:?}", ext_info.ext_hash),
			pallet_id: ext_info.pallet_id,
			variant_id: ext_info.variant_id,
			signer_app_id: ext_info.signer_payload.as_ref().map(|s| s.app_id),
		},
		header_extension,
		data_lookup_size_scalars: lookup_size,
		data_lookup_ranges,
		required_original_grid_cells: required_cells(&app_id_range, grid.cols)?,
		app_id_range_from_data_lookup: app_id_range,
		grid,
		expected_payload: ExpectedPayload {
			size: receipt.payload_size,
			sha256: receipt.payload_sha256,
		},
		finalized: receipt.finalized,
		recovery_status: "mapped_only_not_retrieved".to_string(),
		notes: vec![
			"This map identifies the app-id grid cell range needed for a later payload recovery step.".to_string(),
			"It does not retrieve CDA cells, verify symbols, decode the app stream, or reassemble the payload.".to_string(),
			"The app-id range may contain multiple submissions with the same app_id in the same block; exact payload extraction is a later recovery step keyed by tx_index/extrinsic_hash.".to_string(),
		],
	};

	if let Some(parent) = Path::new(&out_path).parent() {
		if !parent.as_os_str().is_empty() {
			fs::create_dir_all(parent)?;
		}
	}
	fs::write(&out_path, serde_json::to_vec_pretty(&map)?)?;
	println!("payload_recovery_map_ok=yes");
	println!("payload_recovery_map={out_path}");
	println!("tx_index={}", map.tx_index);
	println!(
		"app_id_range={}..{}",
		map.app_id_range_from_data_lookup.start_scalar, map.app_id_range_from_data_lookup.end_scalar
	);
	println!("required_original_grid_cells={}", map.required_original_grid_cells.len());
	Ok(())
}
