# About the project
KDBX 4.x format (Keepass >=2.36) is not supported by keepass2john yet, so there is no known way to extract the hash and crack it.
Developed while playing Mythical Prolab from HTB

# Usage
```sh
./keepass4brute-rs <DATABASE.kdbx> <WORDLIST.txt>
```

# Examples
```sh
# Basic attack with default settings (uses all CPU cores)
./keepass4brute-rs database.kdbx rockyou.txt

# Gzip wordlist support
./keepass4brute-rs database.kdbx rockyou.txt.gz

# Specify number of threads
./keepass4brute-rs database.kdbx rockyou.txt --threads 8

# Resume from an offset, stop after N attempts, and set a timeout
./keepass4brute-rs database.kdbx rockyou.txt --skip 1000000 --max-attempts 500000 --timeout 120

```

