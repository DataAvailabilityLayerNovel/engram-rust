use avail_rust_client::{
	codec::{Compact, Decode, Encode},
	conversions::account_id_like,
	prelude::*,
	subxt_core::config::{Hasher, substrate::BlakeTwo256},
	subxt_signer::sr25519,
};
use avail_rust_core::{
	ExtrinsicExtra, ExtrinsicSignature, MultiAddress, MultiSignature,
	substrate::extrinsic::{ExtrinsicAdditional, GenericExtrinsic},
};
use serde_json::json;
use std::{
	borrow::Cow,
	env,
	time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::{Duration, timeout};

fn env_u32(key: &str, default: u32) -> u32 {
	env::var(key)
		.ok()
		.and_then(|v| v.parse::<u32>().ok())
		.unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
	env::var(key)
		.ok()
		.and_then(|v| v.parse::<u64>().ok())
		.unwrap_or(default)
}

fn unix_ms() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_millis() as u64)
		.unwrap_or(0)
}

fn env_required(key: &str) -> Result<String, Error> {
	env::var(key).map_err(|_| Error::Other(format!("missing {key}")))
}

fn read_file(path: &str) -> Result<Vec<u8>, Error> {
	std::fs::read(path).map_err(|e| Error::Other(format!("read {path} failed: {e}")))
}

fn write_file(path: &str, data: &[u8]) -> Result<(), Error> {
	std::fs::write(path, data).map_err(|e| Error::Other(format!("write {path} failed: {e}")))
}

fn hex_decode(value: &str) -> Result<Vec<u8>, Error> {
	const_hex::decode(value.trim_start_matches("0x")).map_err(|e| Error::Other(e.to_string()))
}

fn hex_encode(value: impl AsRef<[u8]>) -> String {
	format!("0x{}", const_hex::encode(value.as_ref()))
}

fn numeric_hex_u32(value: u32) -> String {
	format!("0x{value:08x}")
}

fn numeric_hex_u128(value: u128) -> String {
	format!("0x{value:032x}")
}

fn json_string(value: &serde_json::Value, key: &str) -> Result<String, Error> {
	value
		.get(key)
		.and_then(|v| v.as_str())
		.map(ToOwned::to_owned)
		.ok_or_else(|| Error::Other(format!("prepared transaction missing {key}")))
}

fn normalize_signature_type(value: &str) -> String {
	match value.trim().to_lowercase().as_str() {
		"ed25519" => "ed25519".to_string(),
		"ecdsa" | "ethereum" => "ecdsa".to_string(),
		"unknown" | "" => "unknown".to_string(),
		_ => "sr25519".to_string(),
	}
}

fn candidate_signature_types(preferred: &str, signature_bytes: &[u8]) -> Result<Vec<String>, Error> {
	let preferred = normalize_signature_type(preferred);
	if preferred != "unknown" {
		return Ok(vec![preferred]);
	}

	match signature_bytes {
		[0, ..] if signature_bytes.len() == 65 => Ok(vec!["ed25519".to_string()]),
		[1, ..] if signature_bytes.len() == 65 => Ok(vec!["sr25519".to_string()]),
		[2, ..] if signature_bytes.len() == 66 => Ok(vec!["ecdsa".to_string()]),
		[..] if signature_bytes.len() == 65 => Ok(vec!["ecdsa".to_string()]),
		[..] if signature_bytes.len() == 64 => Err(Error::Other(
			"64-byte wallet signature is ambiguous; wallet account type must be sr25519 or ed25519".into(),
		)),
		_ => Err(Error::Other(format!("unsupported wallet signature encoding: {} bytes", signature_bytes.len()))),
	}
}

fn multisig_for(signature_type: &str, signature_bytes: &[u8]) -> Result<MultiSignature, Error> {
	let signature_type = normalize_signature_type(signature_type);
	match signature_type.as_str() {
		"ed25519" => {
			let mut bytes = signature_bytes.to_vec();
			if bytes.len() == 65 && bytes[0] == 0 {
				bytes.remove(0);
			}
			let signature: [u8; 64] = bytes
				.as_slice()
				.try_into()
				.map_err(|_| Error::Other(format!("ed25519 signature must be 64 bytes, got {}", bytes.len())))?;
			Ok(MultiSignature::Ed25519(signature))
		},
		"ecdsa" => {
			let mut bytes = signature_bytes.to_vec();
			if bytes.len() == 66 && bytes[0] == 2 {
				bytes.remove(0);
			}
			let signature: [u8; 65] = bytes
				.as_slice()
				.try_into()
				.map_err(|_| Error::Other(format!("ecdsa signature must be 65 bytes, got {}", bytes.len())))?;
			Ok(MultiSignature::Ecdsa(signature))
		},
		_ => {
			let mut bytes = signature_bytes.to_vec();
			if bytes.len() == 65 && bytes[0] == 1 {
				bytes.remove(0);
			}
			let signature: [u8; 64] = bytes
				.as_slice()
				.try_into()
				.map_err(|_| Error::Other(format!("sr25519 signature must be 64 bytes, got {}", bytes.len())))?;
			Ok(MultiSignature::Sr25519(signature))
		},
	}
}

fn is_bad_proof_like(error: &impl std::fmt::Display) -> bool {
	let text = error.to_string().to_lowercase();
	text.contains("badproof")
		|| text.contains("bad proof")
		|| text.contains("temporarily banned")
		|| text.contains("1012")
}

fn sr25519_signature_payload_bytes(signature_bytes: &[u8]) -> Result<[u8; 64], Error> {
	let mut bytes = signature_bytes.to_vec();
	if bytes.len() == 65 && bytes[0] == 1 {
		bytes.remove(0);
	}
	bytes
		.as_slice()
		.try_into()
		.map_err(|_| Error::Other(format!("sr25519 signature must be 64 bytes, got {}", bytes.len())))
}

fn sr25519_signature_verifies(
	account_id: &AccountId,
	signature_bytes: &[u8],
	signing_payload: &[u8],
) -> Result<bool, Error> {
	let signature = sr25519::Signature(sr25519_signature_payload_bytes(signature_bytes)?);
	let pubkey = sr25519::PublicKey(*AsRef::<[u8; 32]>::as_ref(account_id));
	Ok(sr25519::verify(&signature, signing_payload, &pubkey))
}

fn json_hex_bytes(value: &serde_json::Value, key: &str) -> Result<Vec<u8>, Error> {
	hex_decode(&json_string(value, key)?)
}

fn json_numeric_hex_u32(value: &serde_json::Value, key: &str) -> Result<u32, Error> {
	let raw = json_string(value, key)?;
	let digits = raw
		.strip_prefix("0x")
		.ok_or_else(|| Error::Other(format!("SignerPayloadJSON {key} must start with 0x")))?;
	if digits.len() != 8 {
		return Err(Error::Other(format!("SignerPayloadJSON {key} must be an 8-digit numeric hex value, got {raw}")));
	}
	u32::from_str_radix(digits, 16).map_err(|e| Error::Other(format!("invalid SignerPayloadJSON {key} {raw}: {e}")))
}

fn json_numeric_hex_u128(value: &serde_json::Value, key: &str) -> Result<u128, Error> {
	let raw = json_string(value, key)?;
	let digits = raw
		.strip_prefix("0x")
		.ok_or_else(|| Error::Other(format!("SignerPayloadJSON {key} must start with 0x")))?;
	if digits.len() != 32 {
		return Err(Error::Other(format!("SignerPayloadJSON {key} must be a 32-digit numeric hex value, got {raw}")));
	}
	u128::from_str_radix(digits, 16).map_err(|e| Error::Other(format!("invalid SignerPayloadJSON {key} {raw}: {e}")))
}

fn wallet_signing_data_from_json(value: &serde_json::Value) -> Result<Vec<u8>, Error> {
	let extensions = value
		.get("signedExtensions")
		.and_then(|value| value.as_array())
		.ok_or_else(|| Error::Other("SignerPayloadJSON signedExtensions must be an array".into()))?;
	let extension_names = extensions
		.iter()
		.map(|value| {
			value
				.as_str()
				.ok_or_else(|| Error::Other("SignerPayloadJSON signedExtensions must contain strings".into()))
		})
		.collect::<Result<Vec<_>, _>>()?;

	let mut encoded = json_hex_bytes(value, "method")?;
	for extension in &extension_names {
		match *extension {
			"CheckMortality" | "CheckEra" => encoded.extend(json_hex_bytes(value, "era")?),
			"CheckNonce" => encoded.extend(Compact(json_numeric_hex_u32(value, "nonce")?).encode()),
			"ChargeTransactionPayment" => encoded.extend(Compact(json_numeric_hex_u128(value, "tip")?).encode()),
			"CheckAppId" => {
				let app_id = value
					.get("appId")
					.and_then(|value| value.as_u64())
					.and_then(|value| u32::try_from(value).ok())
					.ok_or_else(|| Error::Other("SignerPayloadJSON appId must be a u32 number".into()))?;
				encoded.extend(Compact(app_id).encode());
			},
			"CheckNonZeroSender" | "CheckSpecVersion" | "CheckTxVersion" | "CheckGenesis" | "CheckWeight" => {},
			unknown => {
				return Err(Error::Other(format!(
					"SignerPayloadJSON self-check does not know signed extension {unknown}"
				)));
			},
		}
	}
	for extension in &extension_names {
		match *extension {
			"CheckSpecVersion" => encoded.extend(json_numeric_hex_u32(value, "specVersion")?.encode()),
			"CheckTxVersion" => encoded.extend(json_numeric_hex_u32(value, "transactionVersion")?.encode()),
			"CheckGenesis" => encoded.extend(json_hex_bytes(value, "genesisHash")?),
			"CheckMortality" | "CheckEra" => encoded.extend(json_hex_bytes(value, "blockHash")?),
			"CheckNonZeroSender" | "CheckNonce" | "CheckWeight" | "ChargeTransactionPayment" | "CheckAppId" => {},
			unknown => {
				return Err(Error::Other(format!(
					"SignerPayloadJSON self-check does not know signed extension {unknown}"
				)));
			},
		}
	}
	Ok(encoded)
}

async fn prepare() -> Result<(), Error> {
	let endpoint = env::var("ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9951".to_string());
	let app_id = env_u32("APP_ID", 7);
	let account_address = env_required("ACCOUNT_ADDRESS")?;
	let signature_type =
		normalize_signature_type(&env::var("SIGNATURE_TYPE").unwrap_or_else(|_| "unknown".to_string()));
	let payload_file = env_required("PAYLOAD_FILE")?;
	let prepared_file = env::var("PREPARED_FILE").ok();
	let payload = read_file(&payload_file)?;
	let payload_sha256 = {
		use sha2::{Digest, Sha256};
		const_hex::encode(Sha256::digest(&payload))
	};

	let client = Client::new(&endpoint).await?;
	let account_id = account_id_like::to_account_id(account_address.as_str())?;
	let mut options = Options::new(app_id);
	if let Ok(value) = env::var("NONCE") {
		if !value.is_empty() {
			options = options.nonce(value.parse::<u32>().map_err(|_| Error::Other("invalid NONCE".into()))?);
		}
	}
	let tx = client.tx().data_availability().submit_data(payload.clone());
	let refined_options = options.build(&client, &account_id, None).await?;
	let extra = ExtrinsicExtra::from(&refined_options);
	let additional = ExtrinsicAdditional {
		spec_version: client.online_client().spec_version(),
		tx_version: client.online_client().transaction_version(),
		genesis_hash: client.online_client().genesis_hash(),
		fork_hash: refined_options.mortality.block_hash,
	};
	let payload = avail_rust_core::ExtrinsicPayload::new_borrowed(&tx.call, extra, additional);
	let call_hex = hex_encode(payload.call.as_ref().encode());
	let extra_hex = hex_encode(payload.extra.encode());
	let additional_hex = hex_encode(payload.additional.encode());
	let signing_data = payload.signing_data();
	let signing_hash = BlakeTwo256::hash(&signing_data);
	let (signing_payload, signing_payload_mode) = if signing_data.len() > 256 {
		(signing_hash.as_ref().to_vec(), "blake2_256")
	} else {
		(signing_data.clone(), "raw")
	};
	let signed_extensions = vec![
		"CheckNonZeroSender",
		"CheckSpecVersion",
		"CheckTxVersion",
		"CheckGenesis",
		"CheckMortality",
		"CheckNonce",
		"CheckWeight",
		"ChargeTransactionPayment",
		"CheckAppId",
	];
	let signer_payload_json = json!({
		"address": account_address,
		"blockHash": format!("{:?}", payload.additional.fork_hash),
		"blockNumber": numeric_hex_u32(refined_options.mortality.block_height),
		"era": hex_encode(payload.extra.era.encode()),
		"genesisHash": format!("{:?}", payload.additional.genesis_hash),
		"method": call_hex,
		"nonce": numeric_hex_u32(payload.extra.nonce),
		"specVersion": numeric_hex_u32(payload.additional.spec_version),
		"tip": numeric_hex_u128(payload.extra.tip),
		"transactionVersion": numeric_hex_u32(payload.additional.tx_version),
		"signedExtensions": signed_extensions,
		"version": 4,
		"appId": payload.extra.app_id,
		"withSignedTransaction": true,
	});
	let wallet_signing_data = wallet_signing_data_from_json(&signer_payload_json)?;
	if wallet_signing_data != signing_data {
		return Err(Error::Other(format!(
			"SignerPayloadJSON self-check failed: wallet encoded {} bytes but Rust prepared {} bytes",
			wallet_signing_data.len(),
			signing_data.len()
		)));
	}
	let prepared = json!({
		"version": 1,
		"mode": "wallet_signed_submit_data",
		"endpoint": endpoint,
		"app_id": app_id,
		"account_address": account_address,
		"account_id": account_id.to_string(),
		"nonce": payload.extra.nonce,
		"tip": payload.extra.tip.to_string(),
		"payload_file": payload_file,
		"payload_sha256": payload_sha256,
		"payload_size": read_file(&payload_file)?.len(),
		"call_hex": call_hex,
		"extra_hex": extra_hex,
		"additional_hex": additional_hex,
		"signing_data_hex": hex_encode(&signing_data),
		"signing_data_bytes": signing_data.len(),
		"signing_hash_hex": hex_encode(signing_hash.as_ref()),
		"signing_payload_hex": hex_encode(&signing_payload),
		"signing_payload_bytes": signing_payload.len(),
		"signing_payload_mode": signing_payload_mode,
		"signature_type": signature_type,
		"signer_payload_json": signer_payload_json,
		"spec_version": payload.additional.spec_version,
		"transaction_version": payload.additional.tx_version,
		"genesis_hash": format!("{:?}", payload.additional.genesis_hash),
		"mortality_block_hash": format!("{:?}", payload.additional.fork_hash),
		"mortality_block_number": refined_options.mortality.block_height,
	});
	if let Some(path) = prepared_file.as_deref() {
		let mut encoded = serde_json::to_vec_pretty(&prepared).map_err(|e| Error::Other(e.to_string()))?;
		encoded.push(b'\n');
		write_file(path, &encoded)?;
	}

	println!("wallet_submit_mode=prepare");
	println!("endpoint={}", prepared["endpoint"].as_str().unwrap_or(""));
	println!("app_id={app_id}");
	println!("account_address={}", prepared["account_address"].as_str().unwrap_or(""));
	println!("account_id={}", prepared["account_id"].as_str().unwrap_or(""));
	println!("nonce={}", payload.extra.nonce);
	println!("payload_sha256={}", prepared["payload_sha256"].as_str().unwrap_or(""));
	println!("payload_size={}", prepared["payload_size"].as_u64().unwrap_or(0));
	println!("call_hex={}", prepared["call_hex"].as_str().unwrap_or(""));
	println!("extra_hex={}", prepared["extra_hex"].as_str().unwrap_or(""));
	println!("additional_hex={}", prepared["additional_hex"].as_str().unwrap_or(""));
	println!("signing_payload_hex={}", prepared["signing_payload_hex"].as_str().unwrap_or(""));
	println!("signing_payload_mode={signing_payload_mode}");
	println!("signing_payload_bytes={}", signing_payload.len());
	println!("signing_data_bytes={}", signing_data.len());
	println!("signature_type={}", prepared["signature_type"].as_str().unwrap_or("unknown"));
	if let Some(path) = prepared_file {
		println!("prepared_file={path}");
	}
	Ok(())
}

async fn submit() -> Result<(), Error> {
	let prepared_file = env_required("PREPARED_FILE")?;
	let signature_hex = env::var("SIGNATURE_HEX").unwrap_or_default();
	let signed_tx_hex = env::var("SIGNED_TX_HEX").unwrap_or_default();
	let receipt_timeout_secs = env_u64("RECEIPT_TIMEOUT_SECS", 240);
	let prepared_bytes = read_file(&prepared_file)?;
	let prepared: serde_json::Value =
		serde_json::from_slice(&prepared_bytes).map_err(|e| Error::Other(e.to_string()))?;
	let endpoint = json_string(&prepared, "endpoint")?;
	let account_address = json_string(&prepared, "account_address")?;
	let call_hex = json_string(&prepared, "call_hex")?;
	let extra_hex = json_string(&prepared, "extra_hex")?;
	let additional_hex = json_string(&prepared, "additional_hex")?;
	let signature_type = json_string(&prepared, "signature_type").unwrap_or_else(|_| "unknown".to_string());

	let client = Client::new(&endpoint).await?;
	let account_id = account_id_like::to_account_id(account_address.as_str())?;
	let call_bytes = hex_decode(&call_hex)?;
	let call = ExtrinsicCall::try_from(call_bytes.as_slice()).map_err(Error::Other)?;
	let extra_bytes = hex_decode(&extra_hex)?;
	let extra = ExtrinsicExtra::decode(&mut extra_bytes.as_slice())?;
	let additional_bytes = hex_decode(&additional_hex)?;
	let additional = ExtrinsicAdditional::decode(&mut additional_bytes.as_slice())?;

	let finalized_height = client.finalized().block_height().await?;
	let submit_start_ts_ms = unix_ms();
	println!("submit_start_ts_ms={submit_start_ts_ms}");
	if !signed_tx_hex.trim().is_empty() {
		let signed_tx_bytes = hex_decode(&signed_tx_hex)?;
		let ext_hash = client.chain().submit_raw(&signed_tx_bytes).await?;
		println!("submitted signed_transaction ext_hash={:?}", ext_hash);
		let receipt = timeout(
			Duration::from_secs(receipt_timeout_secs),
			TransactionReceipt::from_range(
				client.clone(),
				format!("{:?}", ext_hash),
				finalized_height,
				finalized_height.saturating_add(512),
				true,
			),
		)
		.await
		.map_err(|_| Error::Other("Timed out waiting for transaction receipt".into()))??;
		let Some(receipt) = receipt else {
			return Err(Error::Other("Transaction got dropped (no receipt)".into()));
		};
		let events = receipt.events().await?;
		if !events.is_extrinsic_success_present() {
			return Err(Error::Other("Extrinsic did not succeed".into()));
		}
		let submit_receipt_ts_ms = unix_ms();
		println!("submit_receipt_ts_ms={submit_receipt_ts_ms}");
		println!("submit_data ok");
		println!("endpoint={endpoint}");
		println!("app_id={}", prepared.get("app_id").and_then(|v| v.as_u64()).unwrap_or(0));
		println!("receipt_timeout_secs={receipt_timeout_secs}");
		println!("nonce={}", extra.nonce);
		println!("block_height={}", receipt.block_height);
		println!("block_hash={:?}", receipt.block_hash);
		println!("ext_hash={:?}", receipt.ext_hash);
		println!("account_address={account_address}");
		println!("account_id={}", account_id);
		println!("signature_type=signed_transaction");
		println!("spec_version={}", additional.spec_version);
		println!("transaction_version={}", additional.tx_version);
		return Ok(());
	}
	if signature_hex.trim().is_empty() {
		return Err(Error::Other("missing SIGNATURE_HEX or SIGNED_TX_HEX".into()));
	}
	let signature_bytes = hex_decode(&signature_hex)?;
	let mut submit_errors = Vec::new();
	let mut submitted_type = None;
	let mut submitted_hash = None;
	for candidate in candidate_signature_types(&signature_type, &signature_bytes)? {
		if candidate == "sr25519" {
			match sr25519_signature_verifies(
				&account_id,
				&signature_bytes,
				&hex_decode(&json_string(&prepared, "signing_payload_hex")?)?,
			) {
				Ok(true) => {},
				Ok(false) => {
					submit_errors
						.push(format!("{candidate}: local signature verification failed for prepared signing payload"));
					continue;
				},
				Err(error) => {
					submit_errors.push(format!("{candidate}: local signature verification failed: {error}"));
					continue;
				},
			}
		}
		let signature = match multisig_for(&candidate, &signature_bytes) {
			Ok(signature) => signature,
			Err(error) => {
				submit_errors.push(format!("{candidate}: {error}"));
				continue;
			},
		};
		let tx = GenericExtrinsic {
			signature: Some(ExtrinsicSignature {
				address: MultiAddress::Id(account_id.clone()),
				signature,
				extra: extra.clone(),
			}),
			call: Cow::Owned(call.clone()),
		};
		match client.chain().submit(&tx).await {
			Ok(ext_hash) => {
				submitted_type = Some(candidate);
				submitted_hash = Some(ext_hash);
				break;
			},
			Err(error) if is_bad_proof_like(&error) => {
				submit_errors.push(format!("{candidate}: {error}"));
				continue;
			},
			Err(error) => return Err(error.into()),
		}
	}
	let Some(ext_hash) = submitted_hash else {
		return Err(Error::Other(format!(
			"wallet signature was rejected without signature-type fallback: {}",
			submit_errors.join(" | ")
		)));
	};
	let submitted_type = submitted_type.unwrap_or_else(|| normalize_signature_type(&signature_type));
	println!("submitted ext_hash={:?}", ext_hash);
	let receipt = timeout(
		Duration::from_secs(receipt_timeout_secs),
		TransactionReceipt::from_range(
			client.clone(),
			format!("{:?}", ext_hash),
			finalized_height,
			finalized_height.saturating_add(512),
			true,
		),
	)
	.await
	.map_err(|_| Error::Other("Timed out waiting for transaction receipt".into()))??;
	let Some(receipt) = receipt else {
		return Err(Error::Other("Transaction got dropped (no receipt)".into()));
	};
	let events = receipt.events().await?;
	if !events.is_extrinsic_success_present() {
		return Err(Error::Other("Extrinsic did not succeed".into()));
	}
	let submit_receipt_ts_ms = unix_ms();
	println!("submit_receipt_ts_ms={submit_receipt_ts_ms}");
	println!("submit_data ok");
	println!("endpoint={endpoint}");
	println!("app_id={}", prepared.get("app_id").and_then(|v| v.as_u64()).unwrap_or(0));
	println!("receipt_timeout_secs={receipt_timeout_secs}");
	println!("nonce={}", extra.nonce);
	println!("block_height={}", receipt.block_height);
	println!("block_hash={:?}", receipt.block_hash);
	println!("ext_hash={:?}", receipt.ext_hash);
	println!("account_address={account_address}");
	println!("account_id={}", account_id);
	println!("signature_type={submitted_type}");
	println!("spec_version={}", additional.spec_version);
	println!("transaction_version={}", additional.tx_version);
	Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
	match env::var("MODE").unwrap_or_else(|_| "prepare".to_string()).as_str() {
		"prepare" => prepare().await,
		"submit" => submit().await,
		other => Err(Error::Other(format!("unknown MODE: {other}"))),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn signer_payload_u32_values_use_numeric_hex() {
		assert_eq!(numeric_hex_u32(1), "0x00000001");
		assert_eq!(numeric_hex_u32(50), "0x00000032");
		assert_eq!(numeric_hex_u32(267), "0x0000010b");
		assert_eq!(numeric_hex_u32(57_386), "0x0000e02a");
		assert_eq!(numeric_hex_u128(0), "0x00000000000000000000000000000000");
	}

	#[test]
	fn signer_payload_json_reconstructs_rust_signing_bytes() {
		let signed_extensions = vec![
			"CheckNonZeroSender",
			"CheckSpecVersion",
			"CheckTxVersion",
			"CheckGenesis",
			"CheckMortality",
			"CheckNonce",
			"CheckWeight",
			"ChargeTransactionPayment",
			"CheckAppId",
		];
		let payload = json!({
			"address": "5GeK2686DGtdWZPG2wAZRrABgYnFd4ByqCvTiAD4yt4vbgeB",
			"appId": 7,
			"blockHash": "0xb07868fea1667701f690fbf2ba04868078959173954855c341efd4adc4acd768",
			"blockNumber": "0x0000e02a",
			"era": "0xa400",
			"genesisHash": "0xa768b4825295a0789e2960de41edd26d831f7732988078aed5a5bec3579df464",
			"method": "0x1d01446a6e666b61736b61646173616461736461",
			"nonce": "0x0000010b",
			"signedExtensions": signed_extensions,
			"specVersion": "0x00000032",
			"tip": "0x00000000000000000000000000000000",
			"transactionVersion": "0x00000001",
			"version": 4,
			"withSignedTransaction": true,
		});
		let expected = hex_decode(
			"0x1d01446a6e666b61736b61646173616461736461a4002d04001c3200000001000000a768b4825295a0789e2960de41edd26d831f7732988078aed5a5bec3579df464b07868fea1667701f690fbf2ba04868078959173954855c341efd4adc4acd768",
		)
		.unwrap();

		assert_eq!(wallet_signing_data_from_json(&payload).unwrap(), expected);
	}

	#[test]
	fn unknown_signature_type_is_inferred_without_rpc_fallbacks() {
		let mut sr25519 = vec![1];
		sr25519.extend([0; 64]);
		assert_eq!(candidate_signature_types("unknown", &sr25519).unwrap(), ["sr25519"]);

		let mut ed25519 = vec![0];
		ed25519.extend([0; 64]);
		assert_eq!(candidate_signature_types("unknown", &ed25519).unwrap(), ["ed25519"]);
		assert!(candidate_signature_types("unknown", &[0; 64]).is_err());
	}
}
