use std::{net::SocketAddr, time::{Duration, Instant}};

use anon::schnorr::SchnorrSignature;
use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::Field;
use futures::{SinkExt, StreamExt};
use k256::{sha2::Sha256, AffinePoint, ProjectivePoint, Scalar, Secp256k1};
use rand::rngs::OsRng;
use tokio::{net::{TcpListener, TcpStream}, runtime::Runtime};
use tokio_util::{bytes::Bytes, codec::{Framed, LengthDelimitedCodec}};

const BANKADDR: &'static str = "127.0.0.1:0";

async fn user(addr: &SocketAddr) -> Duration {
    let start = Instant::now();
    let socket = TcpStream::connect(addr).await.unwrap();

    let mut rng = OsRng::default();
    let sk = Scalar::random(&mut rng);
    let pk = ProjectivePoint::GENERATOR * sk;
    let msg = "Send 10 dollars to 0x00000".to_string();
    let sig = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&sk, &msg.as_bytes());

    let mut framed = Framed::new(socket, LengthDelimitedCodec::new());

    framed.send(Bytes::from(bincode::serialize(&pk.to_affine()).unwrap())).await.unwrap();
    framed.send(Bytes::from(msg)).await.unwrap();
    framed.send(Bytes::from(bincode::serialize(&sig).unwrap())).await.unwrap();

    start.elapsed()
}

async fn bank(listener: &TcpListener) -> Duration{
    let (socket, _) = listener.accept().await.unwrap();
    let start = Instant::now();

    let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
            
    let pk = ProjectivePoint::from(
        bincode::deserialize::<AffinePoint>(&framed.next().await.unwrap().unwrap()).unwrap()
    );
    let msg = framed.next().await.unwrap().unwrap();
    let sig: SchnorrSignature<Secp256k1> = bincode::deserialize(&framed.next().await.unwrap().unwrap()).unwrap();

    sig.verify::<Sha256>(&pk, &msg).unwrap();

    start.elapsed()
}

fn bench_retail_user(c: &mut Criterion) {
    c.bench_function("Retail USER", |b| {
        b.to_async(Runtime::new().unwrap()).iter_custom(|iters| async move{
            let bank_listener = TcpListener::bind(BANKADDR).await.unwrap();
            let bank_addr = bank_listener.local_addr().unwrap();
            
            let user_handler = tokio::spawn(async move {
                let mut duration = Duration::ZERO;
                for _ in 0..iters {
                    duration += user(&bank_addr).await;
                }
                duration
            });

            let bank_handler = tokio::spawn(async move {
                for _ in 0..iters {
                    bank(&bank_listener).await;
                }
            });

            bank_handler.await.unwrap();
            user_handler.await.unwrap()
        });
    });
}

fn bench_retail_bank(c: &mut Criterion) {
    c.bench_function("Retail BANK", |b| {
        b.to_async(Runtime::new().unwrap()).iter_custom(|iters| async move{
            let bank_listener = TcpListener::bind(BANKADDR).await.unwrap();
            let bank_addr = bank_listener.local_addr().unwrap();
            
            let user_handler = tokio::spawn(async move {
                for _ in 0..iters {
                    user(&bank_addr).await;
                }
            });

            let bank_handler = tokio::spawn(async move {
                let mut duration = Duration::ZERO;
                for _ in 0..iters {
                    duration += bank(&bank_listener).await;
                }
                duration
            });
            
            user_handler.await.unwrap();
            bank_handler.await.unwrap()
        });
    });
}

criterion_group!(benches, bench_retail_user, bench_retail_bank);
criterion_main!(benches);
