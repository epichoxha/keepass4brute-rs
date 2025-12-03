use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{HumanDuration, MultiProgress, ProgressBar, ProgressState, ProgressStyle};
use keepass::Database;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::fs;
use crossbeam_channel::{bounded, Sender};
use std::thread;

#[derive(Parser, Debug)]
#[command(
    name = "keepass4brute-rs",
    version = "2.0.0",
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

    /// Show detailed progress information
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

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

    // Read all passwords into memory
    let passwords = read_passwords(&args.wordlist)?;
    let total_passwords = passwords.len();

    if !args.quiet {
        println!("[+] Database: {}", args.database.display());
        println!("[+] Wordlist: {}", args.wordlist.display());
        println!("[+] Passwords to test: {}", total_passwords);
        println!("[+] Parallel workers: {}", args.threads);
        println!("[+] Starting attack...\n");
    }

    // Setup shared state
    let found_password = Arc::new(std::sync::Mutex::new(None::<String>));
    let should_stop = Arc::new(AtomicBool::new(false));
    let tested_count = Arc::new(AtomicUsize::new(0));

    // Setup progress bar (unless quiet mode)
    let progress_bar = if !args.quiet {
        let pb = ProgressBar::new(total_passwords as u64);
        
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({percent}%) | ETA: {eta} | {msg}")
                .unwrap()
                .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                })
                .progress_chars("█▓▒░"),
        );
        
        pb.set_message("Testing passwords...");
        Some(pb)
    } else {
        None
    };

    let start_time = Instant::now();

    // Read database file once
    let db_data = fs::read(&args.database)?;
    let db_data_arc = Arc::new(db_data);

    // Create channel for progress updates
    let (progress_tx, progress_rx) = bounded::<usize>(100);

    // Clone Arcs for progress thread
    let progress_bar_clone = progress_bar.clone();
    let tested_count_clone = Arc::clone(&tested_count);

    // Start progress monitor thread
    let progress_thread = thread::spawn(move || {
        while let Ok(batch_size) = progress_rx.recv() {
            let current = tested_count_clone.fetch_add(batch_size, Ordering::Relaxed);
            if let Some(pb) = &progress_bar_clone {
                pb.set_position((current + batch_size) as u64);
            }
        }
    });

    // Create worker threads
    let mut workers = Vec::new();
    let chunk_size = (total_passwords / args.threads).max(1);
    
    for i in 0..args.threads {
        let start_idx = i * chunk_size;
        let end_idx = if i == args.threads - 1 {
            total_passwords
        } else {
            (i + 1) * chunk_size
        };
        
        if start_idx >= total_passwords {
            break;
        }

        let passwords_chunk = passwords[start_idx..end_idx].to_vec();
        let db_data = Arc::clone(&db_data_arc);
        let found_pass = Arc::clone(&found_password);
        let stop_flag = Arc::clone(&should_stop);
        let progress_tx = progress_tx.clone();

        workers.push(thread::spawn(move || {
            test_password_chunk(
                passwords_chunk, 
                db_data, 
                found_pass, 
                stop_flag,
                progress_tx,
            )
        }));
    }

    // Wait for workers to complete
    for worker in workers {
        let _ = worker.join();
    }

    // Stop progress channel
    drop(progress_tx);
    let _ = progress_thread.join();

    // Stop the progress bar
    if let Some(pb) = progress_bar {
        pb.finish_and_clear();
    }

    // Check if password was found
    let found = found_password.lock().unwrap();
    
    match &*found {
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
    passwords: Vec<String>,
    db_data: Arc<Vec<u8>>,
    found_password: Arc<std::sync::Mutex<Option<String>>>,
    should_stop: Arc<AtomicBool>,
    progress_tx: Sender<usize>,
) -> Result<()> {
    let mut batch_counter = 0;
    
    for password in passwords {
        // Check if we should stop (another thread found the password)
        if should_stop.load(Ordering::Relaxed) {
            // Send any remaining batch before exiting
            if batch_counter > 0 {
                let _ = progress_tx.send(batch_counter);
            }
            return Ok(());
        }

        // Try to open the database with this password
        let mut cursor = std::io::Cursor::new(&db_data[..]);
        if Database::open(&mut cursor, Some(&password), None).is_ok() {
            // Found it!
            let mut found = found_password.lock().unwrap();
            *found = Some(password);
            should_stop.store(true, Ordering::Relaxed);
            
            // Send any remaining batch
            if batch_counter > 0 {
                let _ = progress_tx.send(batch_counter);
            }
            return Ok(());
        }

        batch_counter += 1;
        
        // Send progress update in batches of 100
        if batch_counter >= 100 {
            let _ = progress_tx.send(batch_counter);
            batch_counter = 0;
        }
    }
    
    // Send any remaining batch
    if batch_counter > 0 {
        let _ = progress_tx.send(batch_counter);
    }
    
    Ok(())
}

fn read_passwords(path: &PathBuf) -> Result<Vec<String>> {
    let file = File::open(path).context("Failed to open wordlist")?;
    let passwords: Vec<String> = io::BufReader::new(file)
        .lines()
        .filter_map(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .collect();
    
    if passwords.is_empty() {
        anyhow::bail!("Wordlist is empty or contains no valid passwords");
    }
    
    Ok(passwords)
}