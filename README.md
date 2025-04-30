# Posterior Security: Anonymity and Message Hiding of Standard Signatures

This is the implementation for the paper "Posterior Security: Anonymity and Message Hiding of Standard Signatures" in [CCS2025](https://www.sigsac.org/ccs/CCS2025/).

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
3. Traffic control commands [`tc`](https://man7.org/linux/man-pages/man8/tc.8.html) only work on Linux environment, which affects `bench_wallet.rs`, `bench_retail.rs`, and  `bench_settlement.rs`.

# Benchmark

The `benches` directory provides five scripts:
1. `bench_dualring.rs` runs [DualRing-EC](https://eprint.iacr.org/2021/1213) to test the signing and verification time.
2. `bench_incognito.rs` runs proposed Incognito Schnorr Signature to test the signing and verification time.
3. `bench_wallet.rs` simulates wallets with user and amount information.
4. `bench_retail.rs` simulates retail transactions between wallets.
5. `bench_settlement.rs` simulates transactions in a two-tier Central Bank Digital Currency [(CBDC)](https://www.bis.org/publ/othp57.pdf) system.


## Bench all without latency

```
cargo bench
```
It will take a minute for [Cargo](https://doc.rust-lang.org/book/ch01-03-hello-cargo.html) to download all the libraries used in this project. If you are using Windows or macOS, only `bench_dualring.rs` and `bench_incognito.rs` will run correctly since the other three benchmarks require `tc` commands on Linux.

Taking `bench_incognito.rs` for instance, the signing of incognito Schnorr signature spends 45 ms in average while the ring size is 64.

<img width="567" alt="incog 64" src="https://github.com/user-attachments/assets/68be43c7-452a-4fe8-bd6e-00c44e69d5a9" />


## Bench with latency

We use `tc` command to control the round-trip time (RTT) for simulations in `bench_wallet.rs`, `bench_retail.rs`, and  `bench_settlement.rs`. For 50ms RTT latency:
```
sudo tc qdisc add dev lo root netem latency 25ms
ping 127.0.0.1 -c 4
cargo bench --bench bench_wallet
cargo bench --bench bench_retail
cargo bench --bench bench_settlement
```

- `qdisc` is queueing discipline to modify.
- `add` add a new rule to a node.
- `dev lo` rules will be applied on device lo.
- `root` modify the outbound traffic scheduler.
- `netem` is network emulator.
- `latency 25ms` introduce a latency of 25 ms to get 50 ms RTT for back and forth traffics.
- `ping` send ICMP ECHO_REQUEST to network hosts.
- `127.0.0.1` is localhost.
- `-c 4` stop after sending 4 packets.

To cleanup the latency setting:
```
sudo tc qdisc del dev lo root
```

# Contact

Feel free to contact authors if you have questions:
[Tsz Hon Yuen](https://thyuen.github.io/) and Ying-Teng Chen (ying-teng.chen@monash.edu).
