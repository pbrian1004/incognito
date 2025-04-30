# Setup
1. Install the latest stable version of [Rust](https://doc.rust-lang.org/book/ch01-01-installation.html) by entering the command:
   ```
   curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
   ```
2. Check whether Rust and Cargo are installed correctly by entering the following commands:
   ```
   rustc --version
   cargo --version
   ```
3. Traffic control commands [(tc)](https://man7.org/linux/man-pages/man8/tc.8.html) may only work on Linux environment, which affects `bench_wallet.rs`, `bench_retail.rs`, and  `bench_settlement.rs`.

# Benchmark
The `benches` directory provides scripts to run five examples:
1. `bench_dualring.rs` runs [DualRing-EC](https://eprint.iacr.org/2021/1213) to test the signing and verification time.
2. `bench_incognito.rs` runs proposed Incognito Schnorr Signature to test the signing and verification time.
3. `bench_wallet.rs`
4. `bench_retail.rs`
5. `bench_settlement.rs`


## Bench all without latency
```bash
cargo bench
```

## Bench with 50ms RTT
```bash
sudo tc qdisc add dev lo root netem latency 25ms
ping 127.0.0.1 -c 4
cargo bench --bench bench_wallet
cargo bench --bench bench_retail
```

## Bench with 200ms RTT
```bash
sudo tc qdisc change dev lo root netem latency 100ms
ping 127.0.0.1 -c 4
cargo bench --bench bench_wallet
cargo bench --bench bench_retail
```

## Bench with 10ms RTT
```bash
sudo tc qdisc change dev lo root netem latency 5ms
ping 127.0.0.1 -c 4
cargo bench --bench bench_settlement
```

## Cleanup
```bash
sudo tc qdisc del dev lo root
```
