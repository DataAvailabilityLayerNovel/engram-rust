# Progress cập nhật hỗ trợ V4 (avail-rust)

## 1) Header V4 schema + decode
- Đã mở rộng xử lý `HeaderExtension::V4` trong core để không còn fail decode kiểu `unknown variant V4`.
- Đã tách commitment cho V4 trong `core/src/header_next.rs`:
  - `V4HeaderExtension.commitment` dùng `V4KateCommitment` (không dùng lại `KateCommitment` của V3).
  - `V4KateCommitment` dùng schema runtime mới: `column_commitments`, `data_root`.
- Đã thêm `#[serde(default)]` cho `V4CompactDataLookup.rows_per_tx` để tương thích trường hợp node không trả `rowsPerTx`.
- Đã bổ sung test cơ bản cho đường đọc `data_root` từ V4 extension.

## 2) SDK API/export và dependency alignment
- Đã export các kiểu V4 cần thiết từ core/client để downstream dùng trực tiếp.
- Đã đồng bộ version phụ thuộc nội bộ `client -> core` về `0.5.1`.

## 3) Signed extensions alignment
- Đã kiểm tra và cập nhật signed extensions của SDK để khớp runtime hiện tại:
  - Thêm `CheckNonZeroSender` vào `DefaultExtrinsicParams` tuple.
  - Thêm impl đầy đủ cho `CheckNonZeroSender` (`Params`, `ExtrinsicParams`, `ExtrinsicParamsEncoder`, `TransactionExtension`).
  - Cập nhật builder tuple params tương ứng.

## 4) Điều tra mismatch extrinsic/signing format
- Đã bổ sung debug có kiểm soát để đối chiếu payload ký và extrinsic bytes:
  - `core/src/substrate/extrinsic.rs`: thêm `signing_data()`.
  - `client/src/chain/chain.rs`: log chi tiết `call/extra/additional/signing_data/signing_hash/extrinsic_hex`.
- Cơ chế bật debug:
  - Dùng env `AVAIL_TX_DEBUG=1` (kết hợp `RUST_LOG=tx_debug=debug` khi chạy với feature tracing).

## 5) Trạng thái kiểm thử
- `cargo test -p avail-rust-core` pass.
- `cargo test -p avail-rust-core --features next` pass.
- `cargo test -p avail-rust-client` pass.
- Lint các file đã chỉnh: không có lỗi.

## 6) Việc còn lại / bước kế tiếp
- Chạy luồng submit thực tế trên node 2.3.4 với `AVAIL_TX_DEBUG=1`.
- Lấy log `tx_debug` của một giao dịch fail để chốt chính xác điểm lệch byte-level (nếu còn).
- Nếu còn mismatch, vá trực tiếp encode layout/signing envelope theo kết quả đối chiếu.