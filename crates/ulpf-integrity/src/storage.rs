//! Arrow and Parquet storage engine for the Universal Log Pre-processing Framework.
//!
//! Enforces high-assurance columnar persistence with Snappy and ZSTD compression.
//! Schema:
//! - `event_id`: Utf8 (UUIDv7)
//! - `block_id`: UInt64
//! - `leaf_index`: UInt32
//! - `timestamp`: Int64 (UTC unix millisecond timestamp)
//! - `vendor`: Utf8
//! - `raw_log`: Utf8 (Complete, uncompressed raw log string)
//! - `raw_hash`: Utf8 (SHA-256 digest in hex)
//! - `ocsf_json`: Utf8 (Serialized OCSF 1.3 JSON representation)

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use arrow::array::{
    Array, ArrayRef, Int64Array, RecordBatch, StringArray, UInt32Array, UInt64Array,
};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::arrow_writer::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};

/// Canonical record stored in Arrow and Parquet blocks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredLogRecord {
    pub event_id: String,
    pub block_id: u64,
    pub leaf_index: u32,
    pub timestamp: i64,
    pub vendor: String,
    pub raw_log: String,
    pub raw_hash: String,
    pub ocsf_json: String,
}

/// Compression formats supported for Parquet log block files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ParquetCompression {
    #[default]
    Snappy,
    Zstd,
    Uncompressed,
}

impl From<ParquetCompression> for Compression {
    fn from(comp: ParquetCompression) -> Self {
        match comp {
            ParquetCompression::Snappy => Compression::SNAPPY,
            ParquetCompression::Zstd => Compression::ZSTD(ZstdLevel::default()),
            ParquetCompression::Uncompressed => Compression::UNCOMPRESSED,
        }
    }
}

/// Returns the official Arrow Schema for ULPF Parquet blocks.
pub fn log_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("event_id", DataType::Utf8, false),
        Field::new("block_id", DataType::UInt64, false),
        Field::new("leaf_index", DataType::UInt32, false),
        Field::new("timestamp", DataType::Int64, false),
        Field::new("vendor", DataType::Utf8, false),
        Field::new("raw_log", DataType::Utf8, false),
        Field::new("raw_hash", DataType::Utf8, false),
        Field::new("ocsf_json", DataType::Utf8, false),
    ]))
}

/// Converts a slice of `StoredLogRecord` into an Arrow `RecordBatch`.
pub fn records_to_batch(records: &[StoredLogRecord]) -> Result<RecordBatch> {
    let count = records.len();
    let mut event_ids = Vec::with_capacity(count);
    let mut block_ids = Vec::with_capacity(count);
    let mut leaf_indices = Vec::with_capacity(count);
    let mut timestamps = Vec::with_capacity(count);
    let mut vendors = Vec::with_capacity(count);
    let mut raw_logs = Vec::with_capacity(count);
    let mut raw_hashes = Vec::with_capacity(count);
    let mut ocsf_jsons = Vec::with_capacity(count);

    for r in records {
        event_ids.push(r.event_id.as_str());
        block_ids.push(r.block_id);
        leaf_indices.push(r.leaf_index);
        timestamps.push(r.timestamp);
        vendors.push(r.vendor.as_str());
        raw_logs.push(r.raw_log.as_str());
        raw_hashes.push(r.raw_hash.as_str());
        ocsf_jsons.push(r.ocsf_json.as_str());
    }

    let schema = log_schema();
    let columns: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from(event_ids)),
        Arc::new(UInt64Array::from(block_ids)),
        Arc::new(UInt32Array::from(leaf_indices)),
        Arc::new(Int64Array::from(timestamps)),
        Arc::new(StringArray::from(vendors)),
        Arc::new(StringArray::from(raw_logs)),
        Arc::new(StringArray::from(raw_hashes)),
        Arc::new(StringArray::from(ocsf_jsons)),
    ];

    RecordBatch::try_new(schema, columns).context("Failed to construct Arrow RecordBatch")
}

/// Converts an Arrow `RecordBatch` into a list of `StoredLogRecord`.
pub fn batch_to_records(batch: &RecordBatch) -> Result<Vec<StoredLogRecord>> {
    let get_str = |col: usize, name: &str| -> Result<&StringArray> {
        batch
            .column(col)
            .as_any()
            .downcast_ref::<StringArray>()
            .with_context(|| format!("Column {} ({}) is not a Utf8 StringArray", col, name))
    };

    let event_ids = get_str(0, "event_id")?;
    let block_ids = batch
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .context("Column 1 (block_id) is not a UInt64Array")?;
    let leaf_indices = batch
        .column(2)
        .as_any()
        .downcast_ref::<UInt32Array>()
        .context("Column 2 (leaf_index) is not a UInt32Array")?;
    let timestamps = batch
        .column(3)
        .as_any()
        .downcast_ref::<Int64Array>()
        .context("Column 3 (timestamp) is not an Int64Array")?;
    let vendors = get_str(4, "vendor")?;
    let raw_logs = get_str(5, "raw_log")?;
    let raw_hashes = get_str(6, "raw_hash")?;
    let ocsf_jsons = get_str(7, "ocsf_json")?;

    let num_rows = batch.num_rows();
    let mut records = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        records.push(StoredLogRecord {
            event_id: event_ids.value(i).to_string(),
            block_id: block_ids.value(i),
            leaf_index: leaf_indices.value(i),
            timestamp: timestamps.value(i),
            vendor: vendors.value(i).to_string(),
            raw_log: raw_logs.value(i).to_string(),
            raw_hash: raw_hashes.value(i).to_string(),
            ocsf_json: ocsf_jsons.value(i).to_string(),
        });
    }

    Ok(records)
}

/// Writes an Arrow `RecordBatch` to an Apache Parquet file using specified compression.
pub fn write_parquet_file(
    path: impl AsRef<Path>,
    batch: &RecordBatch,
    compression: ParquetCompression,
) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
    }

    let file =
        File::create(path).with_context(|| format!("Failed to create file at {:?}", path))?;

    let props = WriterProperties::builder()
        .set_compression(compression.into())
        .build();

    let mut writer = ArrowWriter::try_new(file, batch.schema(), Some(props))
        .context("Failed to initialize ArrowWriter")?;

    writer
        .write(batch)
        .context("Failed to write batch to Parquet")?;
    writer.close().context("Failed to close Parquet writer")?;

    Ok(())
}

/// Writes a slice of `StoredLogRecord` directly into a compressed Parquet file.
pub fn write_records_to_parquet(
    path: impl AsRef<Path>,
    records: &[StoredLogRecord],
    compression: ParquetCompression,
) -> Result<()> {
    let batch = records_to_batch(records)?;
    write_parquet_file(path, &batch, compression)
}

/// Reads all records from a Parquet file.
pub fn read_parquet_file(path: impl AsRef<Path>) -> Result<Vec<StoredLogRecord>> {
    let path = path.as_ref();
    let file =
        File::open(path).with_context(|| format!("Failed to open Parquet file at {:?}", path))?;

    let builder = ParquetRecordBatchReaderBuilder::try_new(file)
        .context("Failed to create ParquetRecordBatchReaderBuilder")?;
    let reader = builder
        .build()
        .context("Failed to build ParquetRecordBatchReader")?;

    let mut all_records = Vec::new();
    for maybe_batch in reader {
        let batch = maybe_batch.context("Failed reading record batch from Parquet")?;
        let records = batch_to_records(&batch)?;
        all_records.extend(records);
    }

    Ok(all_records)
}
