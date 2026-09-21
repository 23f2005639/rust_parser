# Universal Log Pre-processing Framework (ULPF)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.98%2B-orange.svg)](https://www.rust-lang.org/)
[![Schema](https://img.shields.io/badge/schema-OCSF%201.3-green.svg)](https://schema.ocsf.io/)
[![Integrity](https://img.shields.io/badge/integrity-RFC%206962%20Merkle-purple.svg)](https://datatracker.ietf.org/doc/html/rfc6962)
[![Air--Gap](https://img.shields.io/badge/deployment-100%25%20Air--Gapped-red.svg)](#air-gapped-deployment)

> **Submission for National Technical Research Organisation (NTRO) / Smart India Hackathon (SIH26156)**  
> **Theme:** Blockchain & Cybersecurity | **Category:** Software

A high-performance, vendor-agnostic, containerized, and strictly **air-gapped Universal Log Pre-processing Framework (ULPF)** written in **Rust**. ULPF ingests, classifies, extracts, and normalizes heterogeneous perimeter network device logs into the **Open Cybersecurity Schema Framework (OCSF 1.3)** while cryptographically proving log integrity and non-repudiation using **RFC 6962 Merkle Trees**.

---

## Key Highlights

* ⚡ **Blistering Performance:** Achieves **> 600,000 Events Per Second (EPS)** across 16 logical cores using asynchronous socket pools (`tokio` + `SO_REUSEPORT`) and zero-copy byte slicing.
* 🛡️ **Forensic Tamper Evidence (RFC 6962):** Solves the "Hash Vault Illusion" by organizing incoming logs into Certificate Transparency-grade Merkle Trees. Detects deleted, missing, or altered records in $O(\log N)$ time.
* 🔍 **Lossless Bi-directional Traceability:** Retains 100% of the raw, untouched log string linked bi-directionally to normalized OCSF events via monotonically increasing **UUIDv7** identifiers and SHA-256 digests.
* 🌐 **Standard OCSF 1.3 Schema:** Maps Cisco ASA, Fortinet FortiGate, Palo Alto PAN-OS, Suricata IDS, pfSense, and Kaggle firewall events directly to OCSF Class 4001 (`NetworkActivity`).
* 🤖 **Air-Gapped AI & Drain3 Anomaly Detection:** Features a native Rust Drain3 template miner for microsecond structural clustering (zero GPU required) and an air-gapped 1-click regex synthesizer for rapid device onboarding.
* 📦 **Production Storage:** Archives raw events and OCSF JSON into columnar **Apache Parquet** with Snappy compression ($> 82\%$ storage reduction).

---

## System Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               ULPF PIPELINE WORKFLOW                                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
 [Perimeter Network Devices] ─── (Syslog UDP/TCP: Cisco, Fortinet, Palo Alto, Suricata)
               │
               ▼
 ┌──────────────────────────────────────────────────────────────────────────────────────┐
 │ 1. HIGH-SPEED ASYNC INGESTION PLANE (crates/ulpf-core)                               │
 │   • Asynchronous Multi-Threaded Socket Pool (Tokio + SO_REUSEPORT)                   │
 │   • Time-Ordered UUIDv7 Event ID & Nanosecond Ingestion Timestamp Generation         │
 │   • 100% Lossless Raw Log Retention Buffer                                           │
 └──────────────────────────────────────────┬───────────────────────────────────────────┘
                                            ▼
 ┌──────────────────────────────────────────────────────────────────────────────────────┐
 │ 2. TWO-TIER ZERO-COPY PARSING & NORMALIZATION (crates/ulpf-core)                     │
 │   • Tier 1: Aho-Corasick Multi-Pattern Classifier ($O(m)$ Vendor Signature Detection)│
 │   • Tier 2: Zero-Copy Token Extractors (Zero Heap String Allocations)                │
 │   • Standard OCSF 1.3 Mapping: Class UID 4001 (NetworkActivity)                      │
 └─────────────────────┬────────────────────────────────────────────┬───────────────────┘
                       │ (Normalized Events)                        │ (Unmapped / Drift)
                       ▼                                            ▼
 ┌───────────────────────────────────────────┐ ┌────────────────────────────────────────┐
 │ 3. INTEGRITY & STORAGE PLANE              │ │ 4. AIR-GAPPED AI & ANOMALY PLANE       │
 │    (crates/ulpf-integrity)                │ │    (crates/ulpf-ai)                    │
 │   • RFC 6962 Standard Merkle Tree         │ │   • Native Rust Drain3 Template Miner  │
 │     - Leaf: SHA256(0x00 || raw_log)       │ │     - Microsecond structural clustering│
 │     - Node: SHA256(0x01 || left || right) │ │     - Real-time Evasion Anomaly Alert  │
 │   • Dual-Trigger Batching (1000 logs / 2s)│ │   • Air-Gapped 1-Click Onboarder       │
 │   • O(log N) Inclusion Proof Generation   │ │     - Heuristic / Local SLM Synthesizer│
 │   • Columnar Apache Parquet WORM Storage  │ │     - Auto-Validated Non-Greedy Regex  │
 │   • Forensic Bit-Flip Tamper Detector     │ │     - Hot Dynamic Parser Loading       │
 └───────────────────────────────────────────┘ └────────────────────────────────────────┘
```

---

## Supported Perimeter Device Formats

| Vendor / Platform | Log Format | Target OCSF Class | Sample Event Signature |
| :--- | :--- | :--- | :--- |
| **Cisco ASA 5500 / Firepower** | RFC 3164 Syslog | `NetworkActivity` (4001) | `%ASA-6-302013`, `%ASA-4-106023` |
| **Fortinet FortiGate** | CEF / Key-Value Syslog | `NetworkActivity` (4001) | `devname="FGT" type="traffic" srcip=...` |
| **Palo Alto PAN-OS** | CSV Syslog (60+ fields) | `NetworkActivity` (4001) | `1,2026/09/21,001801000661,TRAFFIC,...` |
| **Suricata IDS/IPS** | EVE-JSON | `NetworkActivity` (4001) | `{"event_type":"alert","src_ip":...}` |
| **pfSense** | `filterlog` CSV | `NetworkActivity` (4001) | `filterlog[123]: 4,,,1000,em0,match,block...` |
| **Kaggle Internet Firewall** | Tabular / Network Syslog | `NetworkActivity` (4001) | Action, Source/Dest Ports, Bytes, Packets |

---

## Quick Start Guide

### Prerequisites
* **Operating System:** Linux (Kernel 5.4+)
* **Toolchain:** Rust 1.80+ (`cargo`) & Python 3.10+
* **Docker & Docker Compose** (for containerized deployment)

### 1. Build from Source
```bash
# Clone repository
git clone https://github.com/your-org/ulpf.git
cd ulpf

# Compile release binaries
cargo build --release
```

Binaries will be available in `target/release/`:
* `ulpf`: Unified framework CLI (ingest, verify, onboard, benchmark)
* `ulpf-generator`: High-speed multi-threaded UDP/TCP packet blaster

---

## Running the Framework

### 1. Start Ingestion Server
```bash
# Ingest Syslog over UDP and TCP on port 5140
./target/release/ulpf ingest \
  --udp 0.0.0.0:5140 \
  --tcp 0.0.0.0:5140 \
  --parquet-dir ./data/parquet \
  --batch-size 1000 \
  --batch-timeout 2000
```

### 2. Stream Test Traffic (Blaster)
In a separate terminal, stream 50,000 mixed vendor perimeter logs at 100,000 EPS:
```bash
./target/release/ulpf-generator \
  --target 127.0.0.1:5140 \
  --proto udp \
  --rate 100000 \
  --duration 5 \
  --dataset all
```

### 3. Verify Forensic Integrity (Merkle Inclusion Proofs)
Verify an archived Parquet chunk against the anchored cryptographic ledger:
```bash
./target/release/ulpf verify \
  --file ./data/parquet/block_00001.parquet \
  --ledger ./data/ledger.jsonl
```

### 4. 1-Click Air-Gapped Device Onboarding
Feed 3 sample lines of a new, unsupported firewall format:
```bash
./target/release/ulpf onboard \
  --sample ./sample_juniper.log \
  --name "juniper_srx"
```

---

## Automated 2-Minute Demo

Run the fully automated end-to-end demonstration script:
```bash
./scripts/run_demo.sh
```
This script executes:
1. Multi-vendor high-throughput ingestion ($> 200,000\text{ EPS}$).
2. Complete OCSF 1.3 JSON extraction with UUIDv7 traceability.
3. Merkle Tree verification pass.
4. Tamper attack simulation (flipping 1 byte in storage) and automated tamper detection alert.
5. 1-click air-gapped onboarding of an unknown device format.

---

## Air-Gapped Container Deployment

Run ULPF completely offline in Docker with zero internet dependencies:
```bash
# Build and launch
docker compose up -d

# Inspect live metrics
docker compose logs -f ulpf-engine
```

---

## Deliverables Index

* 📄 **Architecture Document:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (Max 2 Pages)
* 📊 **Presentation Slides:** [`docs/PRESENTATION.md`](docs/PRESENTATION.md) (Max 5 Slides)
* 🎬 **Demo Video Walkthrough:** [`docs/DEMO.md`](docs/DEMO.md) (Max 2 Minutes)
* 🧪 **Automated Demo Runner:** [`scripts/run_demo.sh`](scripts/run_demo.sh)
* 🐳 **Docker Config:** [`Dockerfile`](Dockerfile) & [`docker-compose.yml`](docker-compose.yml)

---

## License
Licensed under the Apache License, Version 2.0.
