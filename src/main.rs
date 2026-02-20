use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{HumanDuration, ProgressBar, ProgressState, ProgressStyle};
use keepass::Database;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use std::{fs, thread};
use crossbeam_channel::bounded;
use flate2::read::GzDecoder;

#[derive(Parser, Debug)]
#[command(
    name = "keepass4brute-rs",
    author = "r3nt0n",
    about = "High-performance KeePass database brute force tool",
    long_about = "A massively parallel Rust implementation for brute forcing KeePass databases. Significantly faster than bash version."
)]
struct Args {
    /// Path to the KeePass database file (.kdbx)
    #[arg(value_name = "DATABASE")]
    database: PathBuf,

    /// Path to the password wordlist file
    #[arg(value_name = "WORDLIST")]
    wordlist: PathBuf,

    /// Number of parallel workers (default: number of CPU cores)
    #[arg(short, long, default_value_t = num_cpus::get())]
    threads: usize,

    /// Skip the first N passwords in the wordlist (resume)
    #[arg(long, default_value_t = 0)]
    skip: usize,

    /// Stop after testing at most N passwords
    #[arg(long)]
    max_attempts: Option<usize>,

    /// Stop after N seconds
    #[arg(long)]
    timeout: Option<u64>,

    /// Do not pre-count the wordlist (faster start, unknown total)
    #[arg(long)]
    no_count: bool,

    /// Print periodic stats while running (default: true, disable with --stats=false)
    #[arg(long, default_value_t = true)]
    stats: bool,

    /// Stats interval in seconds
    #[arg(long, default_value_t = 10)]
    stats_interval: u64,

    /// Show detailed progress information
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.threads == 0 {
        anyhow::bail!("Threads must be greater than 0");
    }

    if !args.quiet {
        println!("keepass4brute-rs {} by r3nt0n (Rust 2024 Edition)", env!("CARGO_PKG_VERSION"));
        println!("https://github.com/r3nt0n/keepass4brute\n");
    }

    // Validate files exist
    if !args.database.exists() {
        anyhow::bail!("Database file not found: {}", args.database.display());
    }

    if !args.wordlist.exists() {
        anyhow::bail!("Wordlist file not found: {}", args.wordlist.display());
    }

    // Optionally pre-count passwords for progress
    let total_passwords = if !args.quiet && !args.no_count {
        let total = count_passwords(&args.wordlist)?;
        let total_after_skip = total.saturating_sub(args.skip);
        let total = match args.max_attempts {
            Some(max) => total_after_skip.min(max),
            None => total_after_skip,
        };
        Some(total)
    } else {
        None
    };

    if !args.quiet {
        println!("[+] Database: {}", args.database.display());
        println!("[+] Wordlist: {}", args.wordlist.display());
        println!("[+] Parallel workers: {}", args.threads);
        println!("[+] Skip: {}", args.skip);
        if let Some(max) = args.max_attempts {
            println!("[+] Max attempts: {}", max);
        }
        if let Some(timeout) = args.timeout {
            println!("[+] Timeout: {}s", timeout);
        }
        if let Some(total) = total_passwords {
            println!("[+] Passwords to test: {}", total);
        } else {
            println!("[+] Passwords to test: unknown");
        }
        println!("[+] Starting attack...\n");
    }

    // Setup shared state
    let found_password = Arc::new(OnceLock::<String>::new());
    let should_stop = Arc::new(AtomicBool::new(false));
    let tested_count = Arc::new(AtomicUsize::new(0));

    // Setup progress bar (unless quiet mode)
    let progress_bar = if !args.quiet {
        let pb = match total_passwords {
            Some(total) => ProgressBar::new(total as u64),
            None => ProgressBar::new_spinner(),
        };

        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({percent}%) | ETA: {eta} | {msg}")
                .unwrap()
                .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                })
                .progress_chars("█▓▒░"),
        );

        pb.set_message("Testing passwords...");
        if total_passwords.is_none() {
            pb.enable_steady_tick(Duration::from_millis(120));
        }
        Some(pb)
    } else {
        None
    };

    let start_time = Instant::now();
    let deadline = args.timeout.map(|t| start_time + Duration::from_secs(t));

    // Read database file once
    let db_data = fs::read(&args.database)?;
    let db_data_arc = Arc::new(db_data);

    // Work queue for streaming passwords
    let (work_tx, work_rx) = bounded::<String>(1024);

    // Producer: stream wordlist into the queue
    let producer_stop = Arc::clone(&should_stop);
    let producer_deadline = deadline;
    let producer_skip = args.skip;
    let wordlist_path = args.wordlist.clone();
    let producer = thread::spawn(move || -> Result<()> {
        let reader = open_wordlist_reader(&wordlist_path)?;
        let mut skipped = 0usize;

        for line in reader.lines() {
            if producer_stop.load(Ordering::Relaxed) {
                break;
            }
            if let Some(dl) = producer_deadline {
                if Instant::now() >= dl {
                    producer_stop.store(true, Ordering::Relaxed);
                    break;
                }
            }

            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if skipped < producer_skip {
                skipped += 1;
                continue;
            }

            if work_tx.send(line).is_err() {
                break;
            }
        }

        Ok(())
    });

    // Progress ticker to keep the bar updated even on small batches
    let progress_done = Arc::new(AtomicBool::new(false));
    let progress_thread = if let Some(pb) = &progress_bar {
        let pb = pb.clone();
        let tested = Arc::clone(&tested_count);
        let done = Arc::clone(&progress_done);
        Some(thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                pb.set_position(tested.load(Ordering::Relaxed) as u64);
                thread::sleep(Duration::from_millis(200));
            }
            pb.set_position(tested.load(Ordering::Relaxed) as u64);
        }))
    } else {
        None
    };

    // Optional stats thread
    let stats_thread = if args.stats && !args.quiet {
        let tested = Arc::clone(&tested_count);
        let done = Arc::clone(&progress_done);
        let pb = progress_bar.clone();
        let total = total_passwords;
        let interval = args.stats_interval.max(1);
        Some(thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let elapsed = start_time.elapsed();
                let tested_now = tested.load(Ordering::Relaxed);
                let rate = tested_now as f64 / elapsed.as_secs_f64().max(0.001);
                let msg = match total {
                    Some(t) => format!(
                        "[stats] tested: {}/{} | {:.1} attempts/s | elapsed: {}",
                        tested_now,
                        t,
                        rate,
                        HumanDuration(elapsed)
                    ),
                    None => format!(
                        "[stats] tested: {} | {:.1} attempts/s | elapsed: {}",
                        tested_now,
                        rate,
                        HumanDuration(elapsed)
                    ),
                };

                if let Some(pb) = &pb {
                    pb.println(msg);
                } else {
                    println!("{msg}");
                }

                thread::sleep(Duration::from_secs(interval));
            }
        }))
    } else {
        None
    };

    // Create worker threads
    let mut workers = Vec::new();

    for _ in 0..args.threads {
        let db_data = Arc::clone(&db_data_arc);
        let found_pass = Arc::clone(&found_password);
        let stop_flag = Arc::clone(&should_stop);
        let tested = Arc::clone(&tested_count);
        let pb = progress_bar.clone();
        let max_attempts = args.max_attempts;
        let worker_deadline = deadline;
        let work_rx = work_rx.clone();

        workers.push(thread::spawn(move || {
            test_password_chunk(
                db_data, 
                found_pass, 
                stop_flag,
                tested,
                pb,
                max_attempts,
                worker_deadline,
                work_rx,
            )
        }));
    }

    // Wait for workers to complete
    for worker in workers {
        let _ = worker
            .join()
            .map_err(|_| anyhow::anyhow!("Worker thread panicked"))??;
    }

    // Ensure producer finishes
    let _ = producer
        .join()
        .map_err(|_| anyhow::anyhow!("Producer thread panicked"))??;

    progress_done.store(true, Ordering::Relaxed);
    if let Some(t) = progress_thread {
        let _ = t.join();
    }
    if let Some(t) = stats_thread {
        let _ = t.join();
    }

    // Stop the progress bar
    if let Some(pb) = progress_bar {
        pb.finish_and_clear();
    }

    // Check if password was found
    match found_password.get() {
        Some(password) => {
            let elapsed = start_time.elapsed();
            if !args.quiet {
                println!("\n✅ Password found!");
                println!("┌──────────────────────────────────────┐");
                println!("│ Password: {}", password);
                println!("│ Time elapsed: {}", HumanDuration(elapsed));
                let tested = tested_count.load(Ordering::Relaxed);
                println!("│ Attempts per second: {:.1}", tested as f64 / elapsed.as_secs_f64());
                println!("└──────────────────────────────────────┘");
            } else {
                println!("{}", password);
            }
            Ok(())
        }
        None => {
            if tested_count.load(Ordering::Relaxed) == 0 {
                anyhow::bail!("No passwords tested (empty wordlist or skip too large)");
            }
            let elapsed = start_time.elapsed();
            if !args.quiet {
                println!("\n❌ Wordlist exhausted, no match found");
                println!("   Total time: {}", HumanDuration(elapsed));
                let tested = tested_count.load(Ordering::Relaxed);
                println!("   Passwords tested: {}", tested);
                println!("   Average speed: {:.1} attempts/second", 
                    tested as f64 / elapsed.as_secs_f64());
            }
            std::process::exit(3);
        }
    }
}

fn test_password_chunk(
    db_data: Arc<Vec<u8>>,
    found_password: Arc<OnceLock<String>>,
    should_stop: Arc<AtomicBool>,
    tested_count: Arc<AtomicUsize>,
    progress_bar: Option<ProgressBar>,
    max_attempts: Option<usize>,
    deadline: Option<Instant>,
    work_rx: crossbeam_channel::Receiver<String>,
) -> Result<()> {
    let mut batch_counter = 0usize;

    for password in work_rx.iter() {
        // Check if we should stop (another thread found the password)
        if should_stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                should_stop.store(true, Ordering::Relaxed);
                return Ok(());
            }
        }

        // Reserve an attempt (enforces max_attempts if set)
        let reserved = match max_attempts {
            Some(limit) => tested_count
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    if v < limit {
                        Some(v + 1)
                    } else {
                        None
                    }
                })
                .is_ok(),
            None => {
                tested_count.fetch_add(1, Ordering::Relaxed);
                true
            }
        };

        if !reserved {
            should_stop.store(true, Ordering::Relaxed);
            return Ok(());
        }

        // Try to open the database with this password
        let mut cursor = std::io::Cursor::new(&db_data[..]);
        if Database::open(&mut cursor, Some(&password), None).is_ok() {
            // Found it!
            let _ = found_password.set(password);
            should_stop.store(true, Ordering::Relaxed);
            return Ok(());
        }

        batch_counter += 1;
        
        // Send progress update in batches of 100
        if batch_counter >= 100 {
            if let Some(pb) = &progress_bar {
                pb.inc(batch_counter as u64);
            }
            batch_counter = 0;
        }
    }
    
    // Send any remaining batch
    if batch_counter > 0 {
        if let Some(pb) = &progress_bar {
            pb.inc(batch_counter as u64);
        }
    }
    
    Ok(())
}

fn count_passwords(path: &PathBuf) -> Result<usize> {
    let mut count = 0usize;
    let reader = open_wordlist_reader(path)?;
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            count += 1;
        }
    }
    Ok(count)
}

fn open_wordlist_reader(path: &PathBuf) -> Result<Box<dyn BufRead>> {
    let file = File::open(path).context("Failed to open wordlist")?;
    let reader: Box<dyn BufRead> = match path.extension().and_then(|s| s.to_str()) {
        Some("gz") => Box::new(io::BufReader::new(GzDecoder::new(file))),
        _ => Box::new(io::BufReader::new(file)),
    };
    Ok(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_sample_kdbx_with_known_password() {
        let db_path = PathBuf::from("tests/RedPass_prev.kdbx");
        if !db_path.exists() {
            return;
        }
        let db_data = fs::read(&db_path).expect("sample kdbx missing");
        let mut cursor = std::io::Cursor::new(&db_data[..]);
        let ok = Database::open(&mut cursor, Some("Chaineishi9cai"), None).is_ok();
        assert!(ok, "expected sample kdbx to open with provided password");
    }

    #[test]
    fn rejects_wrong_password() {
        let db_path = PathBuf::from("tests/RedPass_prev.kdbx");
        if !db_path.exists() {
            return;
        }
        let db_data = fs::read(&db_path).expect("sample kdbx missing");
        let mut cursor = std::io::Cursor::new(&db_data[..]);
        let ok = Database::open(&mut cursor, Some("definitely-wrong"), None).is_ok();
        assert!(!ok, "expected wrong password to fail");
    }
}
