use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

use ulpf_generator::{locate_data_dir, load_dataset, DatasetKind, Protocol};

#[derive(Parser, Debug)]
#[command(
    name = "ulpf-generator",
    about = "ULPF Multi-Threaded High-Speed Syslog Traffic Generator (10k - 500k+ EPS)"
)]
struct Cli {
    /// Target destination in IP:PORT format
    #[arg(short, long, default_value = "127.0.0.1:5140")]
    target: String,

    /// Transport protocol: udp or tcp
    #[arg(short, long, default_value = "udp")]
    proto: String,

    /// Target rate in Events Per Second (EPS). Set to 0 for unthrottled maximum speed.
    #[arg(short, long, default_value_t = 50000)]
    rate: u64,

    /// Duration to generate traffic in seconds (0 for infinite)
    #[arg(short, long, default_value_t = 10)]
    duration: u64,

    /// Dataset to stream: all, cisco, fortigate, paloalto, suricata, pfsense, kaggle
    #[arg(short = 'D', long, default_value = "all")]
    dataset: String,

    /// Number of concurrent worker tasks (defaults to number of logical CPU cores)
    #[arg(short, long)]
    workers: Option<usize>,

    /// Path to data/raw directory containing log files
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Batch size of packets dispatched per worker loop iteration
    #[arg(long, default_value_t = 64)]
    batch_size: usize,
}

struct Stats {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let proto: Protocol = cli.proto.parse()?;
    let dataset_kind: DatasetKind = cli.dataset.parse()?;
    let target_addr: SocketAddr = cli
        .target
        .parse()
        .with_context(|| format!("Invalid target socket address '{}'", cli.target))?;

    let num_workers = cli.workers.unwrap_or_else(|| {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        cpus.max(2)
    });

    println!("============================================================");
    println!(" ULPF High-Speed Syslog Traffic Generator");
    println!("============================================================");
    println!("  Target:      {} ({})", target_addr, proto);
    println!("  Dataset:     {}", dataset_kind);
    if cli.rate == 0 {
        println!("  Target Rate: UNTHROTTLED (MAX EPS)");
    } else {
        println!("  Target Rate: {} EPS ({} pkts/sec across {} workers)", cli.rate, cli.rate, num_workers);
    }
    if cli.duration == 0 {
        println!("  Duration:    Infinite (Press Ctrl+C to stop)");
    } else {
        println!("  Duration:    {} seconds", cli.duration);
    }
    println!("  Workers:     {}", num_workers);
    println!("  Batch Size:  {}", cli.batch_size);

    // Locate data directory and load logs into memory
    let data_dir = locate_data_dir(cli.data_dir.as_deref())?;
    println!("  Data Path:   {:?}", data_dir);
    println!("Loading datasets into memory buffer...");
    let logs_str = load_dataset(dataset_kind, &data_dir)?;
    println!(
        "  [✓] Buffered {} unique log lines in RAM (Zero-Disk-IO during blast)",
        logs_str.len()
    );

    // Convert to Vec<Arc<[u8]>> or pre-encoded byte buffers
    let logs: Arc<Vec<Vec<u8>>> = Arc::new(
        logs_str
            .into_iter()
            .map(|s| {
                let mut b = s.into_bytes();
                if proto == Protocol::Tcp {
                    b.push(b'\n');
                }
                b
            })
            .collect(),
    );

    let stats = Arc::new(Stats {
        packets_sent: AtomicU64::new(0),
        bytes_sent: AtomicU64::new(0),
        errors: AtomicU64::new(0),
    });

    let running = Arc::new(AtomicBool::new(true));

    // Handle Ctrl+C gracefully
    let running_ctrlc = running.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("\n[!] Received Ctrl+C, shutting down generator...");
        running_ctrlc.store(false, Ordering::SeqCst);
    });

    println!("Blasting traffic to {}...", target_addr);

    // Rate calculations per worker
    let worker_rate = if cli.rate > 0 {
        (cli.rate / num_workers as u64).max(1)
    } else {
        0
    };

    let start_time = Instant::now();
    let mut worker_handles = Vec::with_capacity(num_workers);

    for worker_id in 0..num_workers {
        let logs_clone = logs.clone();
        let stats_clone = stats.clone();
        let running_clone = running.clone();
        let batch_sz = cli.batch_size;

        let handle = tokio::spawn(async move {
            match proto {
                Protocol::Udp => {
                    run_udp_worker(
                        worker_id,
                        target_addr,
                        logs_clone,
                        stats_clone,
                        running_clone,
                        worker_rate,
                        batch_sz,
                    )
                    .await;
                }
                Protocol::Tcp => {
                    run_tcp_worker(
                        worker_id,
                        target_addr,
                        logs_clone,
                        stats_clone,
                        running_clone,
                        worker_rate,
                        batch_sz,
                    )
                    .await;
                }
            }
        });
        worker_handles.push(handle);
    }

    // Reporter task
    let stats_reporter = stats.clone();
    let running_reporter = running.clone();
    let duration_secs = cli.duration;

    let reporter_handle = tokio::spawn(async move {
        let mut prev_pkts = 0u64;
        let mut prev_bytes = 0u64;
        let mut second = 0u64;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await; // first tick fires immediately

        while running_reporter.load(Ordering::Relaxed) {
            interval.tick().await;
            second += 1;

            let cur_pkts = stats_reporter.packets_sent.load(Ordering::Relaxed);
            let cur_bytes = stats_reporter.bytes_sent.load(Ordering::Relaxed);
            let cur_errors = stats_reporter.errors.load(Ordering::Relaxed);

            let delta_pkts = cur_pkts.saturating_sub(prev_pkts);
            let delta_bytes = cur_bytes.saturating_sub(prev_bytes);
            prev_pkts = cur_pkts;
            prev_bytes = cur_bytes;

            let mbytes_per_sec = (delta_bytes as f64) / (1024.0 * 1024.0);
            let total_mbytes = (cur_bytes as f64) / (1024.0 * 1024.0);

            println!(
                "[{:02}:{:02}] Rate: {:>7} pkts/s (EPS) | Bandwidth: {:>6.2} MB/s | Total: {:>9} pkts ({:>6.2} MB) | Errors: {}",
                second / 60,
                second % 60,
                delta_pkts,
                mbytes_per_sec,
                cur_pkts,
                total_mbytes,
                cur_errors
            );

            if duration_secs > 0 && second >= duration_secs {
                running_reporter.store(false, Ordering::SeqCst);
                break;
            }
        }
    });

    // Wait for reporter to finish (which signals running = false)
    let _ = reporter_handle.await;

    // Await all workers
    for h in worker_handles {
        let _ = h.await;
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let total_pkts = stats.packets_sent.load(Ordering::Relaxed);
    let total_bytes = stats.bytes_sent.load(Ordering::Relaxed);
    let total_errors = stats.errors.load(Ordering::Relaxed);
    let avg_eps = if elapsed > 0.0 {
        (total_pkts as f64 / elapsed) as u64
    } else {
        0
    };
    let avg_mb_sec = if elapsed > 0.0 {
        (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed
    } else {
        0.0
    };

    println!("\n============================================================");
    println!(" ULPF Generator Run Finished");
    println!("============================================================");
    println!("  Target:            {} ({})", target_addr, proto);
    println!("  Dataset:           {}", dataset_kind);
    println!("  Elapsed Time:      {:.2} seconds", elapsed);
    println!("  Total Packets:     {} pkts", total_pkts);
    println!("  Total Data Sent:   {:.2} MB ({} bytes)", (total_bytes as f64) / (1024.0 * 1024.0), total_bytes);
    println!("  Average Rate:      {} pkts/sec (EPS)", avg_eps);
    println!("  Average Bandwidth: {:.2} MB/sec", avg_mb_sec);
    println!("  Total Errors:      {}", total_errors);
    println!("============================================================");

    Ok(())
}

async fn run_udp_worker(
    worker_id: usize,
    target: SocketAddr,
    logs: Arc<Vec<Vec<u8>>>,
    stats: Arc<Stats>,
    running: Arc<AtomicBool>,
    target_rate: u64,
    batch_size: usize,
) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Worker {}] Failed to bind UDP socket: {}", worker_id, e);
            stats.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    if let Err(e) = socket.connect(target).await {
        eprintln!("[Worker {}] Failed to connect UDP socket to {}: {}", worker_id, target, e);
        stats.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let num_logs = logs.len();
    let mut log_idx = (worker_id * 17) % num_logs;
    let worker_start = Instant::now();
    let mut sent_count = 0u64;

    while running.load(Ordering::Relaxed) {
        let to_send = if target_rate > 0 {
            // Adaptive rate controller
            let expected_sent = (worker_start.elapsed().as_secs_f64() * target_rate as f64) as u64;
            if sent_count > expected_sent + (batch_size as u64) {
                // Ahead of schedule, pause briefly
                tokio::time::sleep(Duration::from_micros(500)).await;
                continue;
            }
            batch_size.min((expected_sent.saturating_sub(sent_count) as usize).max(1))
        } else {
            batch_size
        };

        let mut batch_bytes = 0u64;
        let mut batch_pkts = 0u64;

        for _ in 0..to_send {
            let log_bytes = &logs[log_idx];
            log_idx = (log_idx + 1) % num_logs;

            match socket.send(log_bytes).await {
                Ok(n) => {
                    batch_bytes += n as u64;
                    batch_pkts += 1;
                }
                Err(_) => {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        sent_count += batch_pkts;
        stats.packets_sent.fetch_add(batch_pkts, Ordering::Relaxed);
        stats.bytes_sent.fetch_add(batch_bytes, Ordering::Relaxed);

        if target_rate == 0 {
            // Unthrottled yield to allow cooperative task scheduling
            tokio::task::yield_now().await;
        }
    }
}

async fn run_tcp_worker(
    worker_id: usize,
    target: SocketAddr,
    logs: Arc<Vec<Vec<u8>>>,
    stats: Arc<Stats>,
    running: Arc<AtomicBool>,
    target_rate: u64,
    batch_size: usize,
) {
    let mut stream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Worker {}] Failed to connect TCP to {}: {}", worker_id, target, e);
            stats.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let num_logs = logs.len();
    let mut log_idx = (worker_id * 17) % num_logs;
    let worker_start = Instant::now();
    let mut sent_count = 0u64;

    let mut send_buf = Vec::with_capacity(batch_size * 256);

    while running.load(Ordering::Relaxed) {
        let to_send = if target_rate > 0 {
            let expected_sent = (worker_start.elapsed().as_secs_f64() * target_rate as f64) as u64;
            if sent_count > expected_sent + (batch_size as u64) {
                tokio::time::sleep(Duration::from_micros(500)).await;
                continue;
            }
            batch_size.min((expected_sent.saturating_sub(sent_count) as usize).max(1))
        } else {
            batch_size
        };

        send_buf.clear();
        for _ in 0..to_send {
            let log_bytes = &logs[log_idx];
            log_idx = (log_idx + 1) % num_logs;
            send_buf.extend_from_slice(log_bytes);
        }

        match stream.write_all(&send_buf).await {
            Ok(_) => {
                sent_count += to_send as u64;
                stats.packets_sent.fetch_add(to_send as u64, Ordering::Relaxed);
                stats.bytes_sent.fetch_add(send_buf.len() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("[Worker {}] TCP write error: {}. Reconnecting...", worker_id, e);
                tokio::time::sleep(Duration::from_millis(500)).await;
                if let Ok(new_stream) = TcpStream::connect(target).await {
                    stream = new_stream;
                }
            }
        }

        if target_rate == 0 {
            tokio::task::yield_now().await;
        }
    }
}
