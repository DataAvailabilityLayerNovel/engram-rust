use avail_rust_client::prelude::*;
use avail_rust_core::{
	ext::sp_crypto_hashing::blake2_256, header::DataLookupItem,
	rpc::system::fetch_extrinsics::Options as FetchExtrinsicsOptions,
};
use codec::Encode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
	collections::{BTreeMap, HashMap},
	env, fs,
	path::{Path, PathBuf},
	str::FromStr,
};

const DATA_CHUNK_SIZE: usize = 31;
const SCALAR_SIZE: usize = 32;
const ROW_EXTENSION_V4: u32 = 2;
const COL_EXTENSION_V4: u32 = 2;
const DEFAULT_P2P_COLS: u32 = 32;
const P2P_ROWS: u32 = 32;
const DEFAULT_CANARY_RUN_DIR: &str = "/home/ubuntu/engram/testnet/runs/engram-private-testnet-canary-20260603T084703Z";
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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

#[derive(Debug, Clone, Serialize)]
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
	extended_rows: u32,
	extended_cols: u32,
	runtime_reported_rows: u32,
	runtime_reported_cols: u32,
	source: String,
}

#[derive(Debug, Serialize)]
struct RequiredOriginalCell {
	scalar_index: u32,
	row: u32,
	col: u32,
	runtime_original_row: u32,
	runtime_original_col: u32,
	custody_virtual_row: u32,
	custody_col: u32,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeOwner {
	store_name: String,
	store_host: String,
	store_cda_multiaddr: String,
	store_peer_id: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	network_row: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	matrix_row: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	custody_col: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	destination_cell_replica: Option<u32>,
	runtime_p2p_row: u32,
	runtime_p2p_col: u32,
	source: String,
}

#[derive(Debug, Serialize)]
struct RequiredCdaCell {
	scalar_index: u32,
	original_row: u32,
	original_col: u32,
	runtime_original_row: u32,
	runtime_original_col: u32,
	custody_virtual_row: u32,
	ext_row: u32,
	ext_col: u32,
	custody_col: u32,
	custody_route_method: String,
	runtime_owner: RuntimeOwner,
	runtime_owner_candidates: Vec<RuntimeOwner>,
	expected_chunk_hex: String,
	expected_cell_le_hex: String,
}

#[derive(Debug, Serialize)]
struct CoordinateMapping {
	status: String,
	method: String,
	row_extension: u32,
	col_extension: u32,
	store_custody_cols: u32,
	custody_route_method: String,
}

#[derive(Debug, Serialize)]
struct RuntimeStoreOwnership {
	status: String,
	source: String,
	method: String,
	missing_owner_coverage: Vec<String>,
	owner_count: usize,
	active_owner_count: usize,
	generated_owner_count: usize,
	inactive_owner_filtered_count: usize,
	active_owner_scope: ActiveOwnerScope,
	owners: Vec<RuntimeOwner>,
	publisher_env: PublisherEnv,
}

#[derive(Debug, Clone, Serialize)]
struct ActiveOwnerScope {
	profile: String,
	mode: String,
	network_rows: Vec<u32>,
	replicas_per_destination_cell: u32,
	fat_replicas_per_column: Option<u32>,
	owner_count: usize,
	generated_owner_count: usize,
	inactive_owner_filtered_count: usize,
}

#[derive(Debug, Serialize)]
struct PublisherEnv {
	#[serde(rename = "CDA_RAW_CELL_OWNER_STORE_MULTIADDRS")]
	cda_raw_cell_owner_store_multiaddrs: String,
}

#[derive(Debug, Serialize)]
struct ExpectedAppStream {
	unpadded_size: usize,
	padded_size: usize,
	sha256: String,
	padded_sha256: String,
	chunk_size: usize,
	chunk_count: u32,
	padded_hex: String,
	chunks_hex: Vec<String>,
	compatibility_note: String,
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
	required_original_grid_cells: Vec<RequiredOriginalCell>,
	expected_payload: ExpectedPayload,
	finalized: bool,
	recovery_status: String,
	notes: Vec<String>,
	required_cda_ext_cells: Vec<RequiredCdaCell>,
	coordinate_mapping: CoordinateMapping,
	runtime_store_ownership: RuntimeStoreOwnership,
	expected_app_stream: ExpectedAppStream,
}

fn usage() -> String {
	"usage: build_payload_recovery_map_native <submission-receipt.json> [payload-recovery-map.json]".to_string()
}

fn blake2_256_hex(data: &[u8]) -> String {
	format!("0x{}", const_hex::encode(blake2_256(data)))
}

fn blake2_256_raw(data: &[u8]) -> [u8; 32] {
	blake2_256(data)
}

fn sha256_hex(data: &[u8]) -> String {
	let digest = Sha256::digest(data);
	const_hex::encode(digest)
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

fn next_power_of_two(value: u32) -> u32 {
	if value <= 1 { 1 } else { value.next_power_of_two() }
}

fn computed_grid_rows(total_scalars: u32, runtime_cols: u32) -> Result<u32, Box<dyn std::error::Error>> {
	if runtime_cols == 0 {
		return Err("runtime grid cols must be non-zero".into());
	}
	let current_height = total_scalars.saturating_add(runtime_cols - 1) / runtime_cols;
	Ok(next_power_of_two(current_height.max(1)))
}

fn custody_cols_from_env() -> Result<u32, Box<dyn std::error::Error>> {
	let value = env::var("CDA_CUSTODY_COLS").unwrap_or_else(|_| DEFAULT_P2P_COLS.to_string());
	let custody_cols = value
		.parse::<u32>()
		.map_err(|err| format!("invalid CDA_CUSTODY_COLS={value}: {err}"))?;
	if !matches!(custody_cols, 8 | 16 | 32) {
		return Err(format!("unsupported CDA_CUSTODY_COLS={custody_cols}; expected 8, 16, or 32").into());
	}
	Ok(custody_cols)
}

fn parse_u32_list(value: &str) -> Vec<u32> {
	value
		.split(',')
		.filter_map(|item| item.trim().parse::<u32>().ok())
		.collect()
}

fn env_u32(name: &str) -> Option<u32> {
	env::var(name).ok().and_then(|value| value.parse::<u32>().ok())
}

fn active_scope_from_env(generated_owners: &[RuntimeOwner]) -> ActiveOwnerScope {
	let profile = env::var("CDA_ACTIVE_TOPOLOGY_PROFILE")
		.or_else(|_| env::var("CDA_TOPOLOGY_PROFILE"))
		.unwrap_or_else(|_| "stage-c".to_string());
	let mode = env::var("ENGRAM_REQUIRED_CELL_OWNER_SCOPE").unwrap_or_else(|_| {
		if profile == "stage-c" {
			"all".to_string()
		} else {
			"active".to_string()
		}
	});
	let default_rows = match profile.as_str() {
		"stage-b" | "stage-b-plus" => vec![0],
		_ => {
			let mut rows = generated_owners
				.iter()
				.filter_map(|owner| owner.network_row)
				.collect::<Vec<_>>();
			rows.sort_unstable();
			rows.dedup();
			if rows.is_empty() { vec![0] } else { rows }
		},
	};
	let network_rows = env::var("CDA_ACTIVE_STORE_Q_NETWORK_ROWS")
		.ok()
		.map(|value| parse_u32_list(&value))
		.filter(|rows| !rows.is_empty())
		.unwrap_or(default_rows);
	let replicas_per_destination_cell =
		env_u32("CDA_ACTIVE_STORE_Q_REPLICAS_PER_DESTINATION_CELL").unwrap_or_else(|| match profile.as_str() {
			"stage-b" => 1,
			"stage-b-plus" => 2,
			_ => u32::MAX,
		});
	let fat_replicas_per_column = env_u32("CDA_ACTIVE_FAT_REPLICAS_PER_COLUMN");

	ActiveOwnerScope {
		profile,
		mode,
		network_rows,
		replicas_per_destination_cell,
		fat_replicas_per_column,
		owner_count: 0,
		generated_owner_count: generated_owners.len(),
		inactive_owner_filtered_count: 0,
	}
}

fn filter_active_owners(
	generated_owners: &[RuntimeOwner],
	scope: &ActiveOwnerScope,
) -> Result<Vec<RuntimeOwner>, Box<dyn std::error::Error>> {
	if scope.mode.as_str() == "all" || scope.profile.as_str() == "stage-c" {
		return Ok(generated_owners.to_vec());
	}
	let metadata_missing = generated_owners
		.iter()
		.any(|owner| owner.network_row.is_none() || owner.destination_cell_replica.is_none());
	if metadata_missing {
		return Err("active Store-Q owner filtering requires network_row and destination_cell_replica metadata".into());
	}
	let active = generated_owners
		.iter()
		.filter(|owner| {
			let network_row = owner.network_row.unwrap_or(u32::MAX);
			let replica = owner.destination_cell_replica.unwrap_or(u32::MAX);
			scope.network_rows.contains(&network_row) && replica < scope.replicas_per_destination_cell
		})
		.cloned()
		.collect::<Vec<_>>();
	if active.is_empty() {
		return Err("active Store-Q owner filtering produced an empty publisher owner set".into());
	}
	Ok(active)
}

fn custody_col_from_extended(ext_col: u32, custody_cols: u32) -> u32 {
	(ext_col / COL_EXTENSION_V4) % custody_cols
}

fn custody_virtual_row(original_row: u32, original_col: u32, runtime_cols: u32, custody_cols: u32) -> u32 {
	let bands = runtime_cols.saturating_add(custody_cols - 1) / custody_cols;
	original_row * bands.max(1) + (original_col / custody_cols)
}

fn scalar_to_runtime_cell_hex(chunk: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
	if chunk.len() > DATA_CHUNK_SIZE {
		return Err(format!("app stream chunk exceeds {DATA_CHUNK_SIZE} bytes").into());
	}
	let mut raw = [0u8; SCALAR_SIZE];
	raw[..chunk.len()].copy_from_slice(chunk);
	raw.reverse();
	Ok(const_hex::encode(raw))
}

fn pad_app_stream(app_stream: &[u8], scalar_count: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	let padded_size = scalar_count as usize * DATA_CHUNK_SIZE;
	if app_stream.len() > padded_size {
		return Err(format!(
			"expected app stream len {} exceeds DataLookup padded len {padded_size}",
			app_stream.len()
		)
		.into());
	}
	let mut out = app_stream.to_vec();
	out.resize(padded_size, 0);
	Ok(out)
}

fn base58_decode(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	let mut out = vec![0u8];
	for byte in value.bytes() {
		let digit = BASE58_ALPHABET
			.iter()
			.position(|candidate| *candidate == byte)
			.ok_or_else(|| format!("invalid base58 peer id character: {:?}", byte as char))? as u32;
		let mut carry = digit;
		for item in out.iter_mut().rev() {
			let acc = u32::from(*item) * 58 + carry;
			*item = (acc & 0xff) as u8;
			carry = acc >> 8;
		}
		while carry > 0 {
			out.insert(0, (carry & 0xff) as u8);
			carry >>= 8;
		}
	}
	let leading_zeroes = value.bytes().take_while(|byte| *byte == b'1').count();
	let first_non_zero = out.iter().position(|byte| *byte != 0).unwrap_or(out.len());
	let mut decoded = vec![0u8; leading_zeroes];
	decoded.extend_from_slice(&out[first_non_zero..]);
	Ok(decoded)
}

fn grid_position_from_peer_id(peer_id: &str, custody_cols: u32) -> Result<(u32, u32), Box<dyn std::error::Error>> {
	let raw = base58_decode(peer_id)?;
	let digest = blake2_256_raw(&raw);
	let row = u16::from_le_bytes([digest[0], digest[1]]) as u32 % P2P_ROWS;
	let col = u16::from_le_bytes([digest[2], digest[3]]) as u32 % custody_cols;
	Ok((row, col))
}

fn parse_csv_line(line: &str) -> Vec<String> {
	line.trim_end_matches('\r')
		.split(',')
		.map(|value| value.trim().to_string())
		.collect()
}

fn read_runtime_store_owners(
	canary_run_dir: &Path,
	custody_cols: u32,
) -> Result<(PathBuf, BTreeMap<u32, Vec<RuntimeOwner>>, Vec<RuntimeOwner>), Box<dyn std::error::Error>> {
	let inv_path = canary_run_dir.join("final-inventories").join("canary-store-nodes.csv");
	let content = fs::read_to_string(&inv_path)
		.map_err(|err| format!("store runtime inventory not found: {}: {err}", inv_path.display()))?;
	let mut lines = content.lines();
	let header = lines.next().ok_or("store runtime inventory is empty")?;
	let headers = parse_csv_line(header);
	let header_index = headers
		.iter()
		.enumerate()
		.map(|(idx, key)| (key.clone(), idx))
		.collect::<HashMap<_, _>>();

	let field = |row: &[String], name: &str| -> Result<String, Box<dyn std::error::Error>> {
		let idx = *header_index
			.get(name)
			.ok_or_else(|| format!("store inventory missing required column {name}"))?;
		row.get(idx)
			.cloned()
			.filter(|value| !value.is_empty())
			.ok_or_else(|| format!("store inventory row missing value for {name}").into())
	};
	let optional_u32 = |row: &[String], name: &str| -> Option<u32> {
		header_index
			.get(name)
			.and_then(|idx| row.get(*idx))
			.and_then(|value| value.parse::<u32>().ok())
	};

	let mut owners_by_col = BTreeMap::<u32, Vec<RuntimeOwner>>::new();
	let mut all_owners = Vec::<RuntimeOwner>::new();

	for line in lines.filter(|line| !line.trim().is_empty()) {
		let row = parse_csv_line(line);
		let peer_id = field(&row, "runtime_cda_peer_id")?;
		let (runtime_row, runtime_col) = grid_position_from_peer_id(&peer_id, custody_cols)?;
		let inventory_col = field(&row, "runtime_p2p_col")?.parse::<u32>()?;
		if runtime_col != inventory_col {
			return Err(format!(
				"runtime store inventory column mismatch: store={} peer={} inventory_col={} computed_col={}",
				field(&row, "store_name")?,
				peer_id,
				inventory_col,
				runtime_col
			)
			.into());
		}

		let owner = RuntimeOwner {
			store_name: field(&row, "store_name")?,
			store_host: field(&row, "store_host")?,
			store_cda_multiaddr: field(&row, "store_cda_multiaddr")?,
			store_peer_id: peer_id,
			network_row: optional_u32(&row, "network_row"),
			matrix_row: optional_u32(&row, "matrix_row"),
			custody_col: optional_u32(&row, "custody_col"),
			destination_cell_replica: optional_u32(&row, "destination_cell_replica"),
			runtime_p2p_row: runtime_row,
			runtime_p2p_col: runtime_col,
			source: "canary-store-nodes.csv + position_from_peer_id_bytes".to_string(),
		};
		owners_by_col.entry(runtime_col).or_default().push(owner.clone());
		all_owners.push(owner);
	}

	for owners in owners_by_col.values_mut() {
		owners.sort_by(|left, right| {
			(left.store_name.as_str(), left.store_peer_id.as_str())
				.cmp(&(right.store_name.as_str(), right.store_peer_id.as_str()))
		});
	}
	all_owners.sort_by(|left, right| {
		(left.runtime_p2p_col, left.store_name.as_str(), left.store_peer_id.as_str()).cmp(&(
			right.runtime_p2p_col,
			right.store_name.as_str(),
			right.store_peer_id.as_str(),
		))
	});

	Ok((inv_path, owners_by_col, all_owners))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = env::args().collect::<Vec<_>>();
	if args.len() < 2 || args.len() > 3 {
		return Err(usage().into());
	}

	let receipt_path = &args[1];
	let out_path = args.get(2).cloned().unwrap_or_else(|| {
		let parent = Path::new(receipt_path).parent().unwrap_or_else(|| Path::new("."));
		parent.join("payload-recovery-map.json").to_string_lossy().into_owned()
	});

	let receipt: SubmissionReceipt = serde_json::from_slice(&fs::read(receipt_path)?)?;
	let endpoint = env::var("ENDPOINT").unwrap_or_else(|_| receipt.submit_endpoint.clone());
	let canary_run_dir = env::var("CANARY_RUN_DIR").unwrap_or_else(|_| DEFAULT_CANARY_RUN_DIR.to_string());
	let custody_cols = custody_cols_from_env()?;
	let (owner_inventory_path, _owners_by_col, all_runtime_owners) =
		read_runtime_store_owners(Path::new(&canary_run_dir), custody_cols)?;
	let mut active_owner_scope = active_scope_from_env(&all_runtime_owners);
	let active_runtime_owners = filter_active_owners(&all_runtime_owners, &active_owner_scope)?;
	let mut active_owners_by_col = BTreeMap::<u32, Vec<RuntimeOwner>>::new();
	for owner in &active_runtime_owners {
		active_owners_by_col
			.entry(owner.runtime_p2p_col)
			.or_default()
			.push(owner.clone());
	}
	for owners in active_owners_by_col.values_mut() {
		owners.sort_by(|left, right| {
			left.network_row
				.cmp(&right.network_row)
				.then(left.destination_cell_replica.cmp(&right.destination_cell_replica))
				.then(left.store_name.cmp(&right.store_name))
		});
	}
	active_owner_scope.owner_count = active_runtime_owners.len();
	active_owner_scope.generated_owner_count = all_runtime_owners.len();
	active_owner_scope.inactive_owner_filtered_count =
		all_runtime_owners.len().saturating_sub(active_runtime_owners.len());

	let client = Client::new(&endpoint).await?;
	let chain = client.chain();

	let expected_block_hash = <H256 as FromStr>::from_str(&receipt.block_hash)?;
	let actual_block_hash = chain
		.block_hash(Some(receipt.block_number))
		.await?
		.ok_or("block hash not found for receipt block_number")?;
	if actual_block_hash != expected_block_hash {
		return Err(
			format!("receipt block hash mismatch: receipt={} chain={actual_block_hash:?}", receipt.block_hash).into()
		);
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
			return Err(
				format!("receipt app_id mismatch: receipt={} extrinsic={}", receipt.app_id, signer.app_id).into()
			);
		}
	}

	let legacy_block = chain
		.legacy_block(Some(expected_block_hash))
		.await?
		.ok_or("block not found for receipt block hash")?;
	let tx_index_usize = ext_info.ext_index as usize;
	let tx_bytes = legacy_block
		.block
		.extrinsics
		.get(tx_index_usize)
		.ok_or_else(|| {
			format!(
				"tx_index {} is outside block extrinsics len {}",
				ext_info.ext_index,
				legacy_block.block.extrinsics.len()
			)
		})?
		.clone();
	let actual_ext_hash = blake2_256_hex(&tx_bytes);
	if actual_ext_hash.to_ascii_lowercase() != receipt.extrinsic_hash.to_ascii_lowercase() {
		return Err(format!(
			"receipt extrinsic hash mismatch: receipt={} actual={actual_ext_hash}",
			receipt.extrinsic_hash
		)
		.into());
	}

	let header = chain
		.block_header(Some(expected_block_hash))
		.await?
		.ok_or("block header not found for receipt block hash")?;

	let (header_extension, lookup_size, lookup_index) = match header.extension {
		HeaderExtension::V3(ext) => ("V3".to_string(), ext.app_lookup.size, ext.app_lookup.index),
		HeaderExtension::V4(ext) => ("V4".to_string(), ext.app_lookup.size, ext.app_lookup.index),
	};

	let block_length = chain
		.kate_block_length(Some(expected_block_hash))
		.await
		.map_err(|err| format!("kate_blockLength failed for {expected_block_hash:?}: {err:?}"))?;
	let runtime_rows = block_length.rows;
	let runtime_cols = block_length.cols;
	if runtime_rows == 0 || runtime_cols == 0 {
		return Err("kate_blockLength returned zero rows or cols".into());
	}

	let data_lookup_ranges = expand_lookup(lookup_size, lookup_index);
	let selected = data_lookup_ranges
		.iter()
		.find(|range| range.app_id == receipt.app_id && range.scalar_count > 0)
		.or_else(|| data_lookup_ranges.iter().find(|range| range.app_id == receipt.app_id))
		.ok_or("receipt app_id was not present in header extension DataLookup")?
		.clone();

	let app_id_range = AppIdRange {
		app_id: receipt.app_id,
		start_scalar: selected.start_scalar,
		end_scalar: selected.end_scalar,
		scalar_count: selected.scalar_count,
		start_stream_byte: u64::from(selected.start_scalar) * DATA_CHUNK_SIZE as u64,
		end_stream_byte: u64::from(selected.end_scalar) * DATA_CHUNK_SIZE as u64,
	};

	let rows = computed_grid_rows(lookup_size, runtime_cols)?;
	if rows > runtime_rows {
		return Err(format!("computed original rows {rows} exceed runtime grid rows {runtime_rows}").into());
	}
	let capacity = rows.checked_mul(runtime_cols).ok_or("grid capacity overflow")?;
	if app_id_range.end_scalar > capacity {
		return Err(format!(
			"app_id range exceeds grid capacity: end_scalar={} capacity={capacity}",
			app_id_range.end_scalar
		)
		.into());
	}

	let app_stream = vec![tx_bytes].encode();
	let app_stream_padded = pad_app_stream(&app_stream, app_id_range.scalar_count)?;
	let chunks_hex = app_stream_padded
		.chunks(DATA_CHUNK_SIZE)
		.map(const_hex::encode)
		.collect::<Vec<_>>();

	let mut required_original = Vec::with_capacity(app_id_range.scalar_count as usize);
	let mut required_cda = Vec::with_capacity(app_id_range.scalar_count as usize);
	for scalar_index in app_id_range.start_scalar..app_id_range.end_scalar {
		let local_index = (scalar_index - app_id_range.start_scalar) as usize;
		let row = scalar_index / runtime_cols;
		let col = scalar_index % runtime_cols;
		let chunk_start = local_index * DATA_CHUNK_SIZE;
		let chunk = &app_stream_padded[chunk_start..chunk_start + DATA_CHUNK_SIZE];
		let ext_row = row * ROW_EXTENSION_V4;
		let ext_col = col * COL_EXTENSION_V4;
		let custody_col = custody_col_from_extended(ext_col, custody_cols);
		let virtual_row = custody_virtual_row(row, col, runtime_cols, custody_cols);
		let owner_candidates = active_owners_by_col.get(&custody_col).cloned().unwrap_or_default();
		if owner_candidates.is_empty() {
			return Err(format!(
				"missing_owner_coverage: custody_col={custody_col} scalar_index={scalar_index} ext_row={ext_row} ext_col={ext_col}"
			)
			.into());
		}
		let runtime_owner = owner_candidates[0].clone();

		required_original.push(RequiredOriginalCell {
			scalar_index,
			row,
			col,
			runtime_original_row: row,
			runtime_original_col: col,
			custody_virtual_row: virtual_row,
			custody_col,
		});
		required_cda.push(RequiredCdaCell {
			scalar_index,
			original_row: row,
			original_col: col,
			runtime_original_row: row,
			runtime_original_col: col,
			custody_virtual_row: virtual_row,
			ext_row,
			ext_col,
			custody_col,
			custody_route_method: format!("fixed_{custody_cols}_column_row_major_wrap"),
			runtime_owner,
			runtime_owner_candidates: owner_candidates,
			expected_chunk_hex: const_hex::encode(chunk),
			expected_cell_le_hex: scalar_to_runtime_cell_hex(chunk)?,
		});
	}

	let owner_multiaddrs = active_runtime_owners
		.iter()
		.map(|owner| owner.store_cda_multiaddr.as_str())
		.collect::<Vec<_>>()
		.join(" ");

	let map = PayloadRecoveryMap {
		version: 1,
		mapper: "native_rust_onchain_recovery_map_phase_10_1".to_string(),
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
		app_id_range_from_data_lookup: app_id_range.clone(),
		grid: Grid {
			rows,
			cols: runtime_cols,
			chunk_size: DATA_CHUNK_SIZE as u32,
			block_chunk_size: SCALAR_SIZE as u32,
			extended_rows: rows * ROW_EXTENSION_V4,
			extended_cols: runtime_cols * COL_EXTENSION_V4,
			runtime_reported_rows: runtime_rows,
			runtime_reported_cols: runtime_cols,
			source: "native_rust_radix2_equivalent_of_runtime_extended_grid_v4".to_string(),
		},
		required_original_grid_cells: required_original,
		expected_payload: ExpectedPayload {
			size: receipt.payload_size,
			sha256: receipt.payload_sha256,
		},
		finalized: receipt.finalized,
		recovery_status: "mapped_with_cda_extended_coordinates_not_retrieved".to_string(),
		notes: vec![
			"Phase 10.1 generated this map natively in Rust from receipt, on-chain header data, kate_blockLength, and current Store inventory.".to_string(),
			"Current JSON schema is preserved for compatibility with existing publication, retrieval, and reassembly scripts.".to_string(),
			"Required CDA cells use runtime-grid dimensions and systematic row/column extension coordinates, not first equal-value matches.".to_string(),
			format!("Store custody routing uses {custody_cols} physical columns from CDA_CUSTODY_COLS: custody_col=(ext_col/COL_EXTENSION_V4)%{custody_cols}; wider runtime grids are additional row-major bands over the same Store columns."),
			"expected_app_stream.padded_hex and chunks_hex are compatibility-only fields until native reassembly can use hash-based compact evidence.".to_string(),
		],
		required_cda_ext_cells: required_cda,
		coordinate_mapping: CoordinateMapping {
			status: "yes".to_string(),
			method: format!("systematic_runtime_coordinate_with_fixed_{custody_cols}_column_custody(ext_row=original_row*ROW_EXTENSION_V4,ext_col=original_col*COL_EXTENSION_V4,custody_col=(ext_col/COL_EXTENSION_V4)%CDA_CUSTODY_COLS)"),
			row_extension: ROW_EXTENSION_V4,
			col_extension: COL_EXTENSION_V4,
			store_custody_cols: custody_cols,
			custody_route_method: format!("fixed_{custody_cols}_column_row_major_wrap"),
		},
		runtime_store_ownership: RuntimeStoreOwnership {
			status: "yes".to_string(),
			source: owner_inventory_path.to_string_lossy().into_owned(),
			method: "position_from_peer_id_bytes(runtime_cda_peer_id)".to_string(),
			missing_owner_coverage: Vec::new(),
			owner_count: all_runtime_owners.len(),
			active_owner_count: active_runtime_owners.len(),
			generated_owner_count: all_runtime_owners.len(),
			inactive_owner_filtered_count: all_runtime_owners
				.len()
				.saturating_sub(active_runtime_owners.len()),
			active_owner_scope,
			owners: all_runtime_owners,
			publisher_env: PublisherEnv {
				cda_raw_cell_owner_store_multiaddrs: owner_multiaddrs,
			},
		},
		expected_app_stream: ExpectedAppStream {
			unpadded_size: app_stream.len(),
			padded_size: app_stream_padded.len(),
			sha256: sha256_hex(&app_stream),
			padded_sha256: sha256_hex(&app_stream_padded),
			chunk_size: DATA_CHUNK_SIZE,
			chunk_count: app_id_range.scalar_count,
			padded_hex: const_hex::encode(&app_stream_padded),
			chunks_hex,
			compatibility_note: "padded_hex and chunks_hex are compatibility-only; future native reassembly should regenerate chunks from chain data and verify hashes.".to_string(),
		},
	};

	if let Some(parent) = Path::new(&out_path).parent() {
		if !parent.as_os_str().is_empty() {
			fs::create_dir_all(parent)?;
		}
	}
	fs::write(&out_path, serde_json::to_vec_pretty(&map)?)?;
	println!("payload_recovery_map_native_ok=yes");
	println!("payload_recovery_map={out_path}");
	println!("tx_index={}", map.tx_index);
	println!(
		"app_id_range={}..{}",
		map.app_id_range_from_data_lookup.start_scalar, map.app_id_range_from_data_lookup.end_scalar
	);
	println!("required_cda_ext_cells={}", map.required_cda_ext_cells.len());
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::{custody_col_from_extended, custody_virtual_row};

	#[test]
	fn cda8_extended_columns_wrap_across_eight_custody_columns() {
		assert_eq!(custody_col_from_extended(0, 8), 0);
		assert_eq!(custody_col_from_extended(14, 8), 7);
		assert_eq!(custody_col_from_extended(16, 8), 0);
		assert_eq!(custody_col_from_extended(62, 8), 7);
		assert_eq!(custody_col_from_extended(64, 8), 0);
		assert_eq!(custody_col_from_extended(126, 8), 7);
	}

	#[test]
	fn cda8_virtual_rows_preserve_wrapped_column_bands() {
		assert_eq!(custody_virtual_row(0, 0, 64, 8), 0);
		assert_eq!(custody_virtual_row(0, 63, 64, 8), 7);
		assert_eq!(custody_virtual_row(1, 0, 64, 8), 8);
	}
}
