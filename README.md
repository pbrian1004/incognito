# Setup
1. Install Rust programming language following [official instructions](https://doc.rust-lang.org/book/ch01-01-installation.html)
2. Traffic control commands [(tc)](https://man7.org/linux/man-pages/man8/tc.8.html) only function on Linux environment, which affects bench_retail.rs

# Benchmark
The benchmarks directory provides convenience scripts to run all the examples. There are 5 scripts:
Some body text of this section.

<a name="my-custom-anchor-point"></a>
Some text I want to provide a direct link to, but which doesn't have its own heading.

(… more content…)

[A link to that custom anchor](#my-custom-anchor-point)

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
