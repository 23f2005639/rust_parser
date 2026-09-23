# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-23T16:27:45.256680708+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 1300 logs (452.68 KB)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **2769157 EPS** | **1707190 EPS** | **0.62x** |
| **Data Bandwidth (MB/s)** | **941.67 MB/s** | **580.53 MB/s** | **0.62x** |
| **Median Latency (p50)** | 66.87 µs | **3.40 µs** | **-94.9%** |
| **99th %ile Latency (p99)** | 81.01 µs | **9.57 µs** | **-88.2%** |
| **Vendor Classification (VCA)** | **78.00%** | **78.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **96.00%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **100.00%** | Variable Masking Integrity |
| **Field Extraction Macro F1** | **85.78%** | **85.78%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **71.80%** | **71.80%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 62.84 µs | 1.30 µs | -97.9% |
| **p50 (Median)** | 66.87 µs | 3.40 µs | -94.9% |
| **p90** | 71.46 µs | 4.78 µs | -93.3% |
| **p99** | 81.01 µs | 9.57 µs | -88.2% |
| **p99.9 (Three Nines)** | 116.06 µs | 17.89 µs | -84.6% |
| **Worst Case (Max)** | 295.55 µs | 27.53 µs | -90.7% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 78.00% | 78.00% | > 95.0% |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 96.00% | > 90.0% |
| **Loghub Template Accuracy (TA %)** | 100.00% | 100.00% | > 85.0% |
| **Source IP Accuracy** | 91.1% | 91.1% | Ground Truth Exact |
| **Destination IP Accuracy** | 91.1% | 91.1% | Ground Truth Exact |
| **Source Port Accuracy** | 88.2% | 88.2% | Valid Port Range |
| **Destination Port Accuracy** | 88.2% | 88.2% | Valid Port Range |
| **Protocol Disambiguation** | 70.3% | 70.3% | OCSF 1.3 Schema 4001 |
| **Disposition Resolution Accuracy** | 71.80% | 71.80% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

