use std::path::Path;
use std::process::Command;

#[test]
fn cracks_sample_kdbx_with_small_gz_wordlist() {
    let db = Path::new("tests/RedPass_prev.kdbx");
    let wl = Path::new("tests/wordlist_small.txt.gz");
    if !db.exists() || !wl.exists() {
        return;
    }

    let output = match std::env::var("CARGO_BIN_EXE_keepass4brute_rs") {
        Ok(exe) => Command::new(exe)
            .arg(db)
            .arg(wl)
            .arg("--threads")
            .arg("2")
            .arg("--no-count")
            .arg("--quiet")
            .output()
            .expect("failed to run binary"),
        Err(_) => Command::new("cargo")
            .arg("run")
            .arg("--quiet")
            .arg("--")
            .arg(db)
            .arg(wl)
            .arg("--threads")
            .arg("2")
            .arg("--no-count")
            .arg("--quiet")
            .output()
            .expect("failed to run binary via cargo"),
    };

    assert!(
        output.status.success(),
        "binary exited with non-zero status: {:?}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim() == "Chaineishi9cai",
        "unexpected stdout: {stdout}"
    );
}
