use std::{net::SocketAddr, time::{Duration, Instant}};

use anon::{incognito::{IncognitoParams, IncognitoSignature}, schnorr::SchnorrSignature};
use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::Field;
use futures::{SinkExt, StreamExt};
use k256::{sha2::Sha256, AffinePoint, ProjectivePoint, Scalar, Secp256k1};
use rand::rngs::OsRng;
use tokio::{net::{TcpListener, TcpStream}, runtime::Runtime, task::JoinSet};
use tokio_util::{bytes::Bytes, codec::{Framed, LengthDelimitedCodec}};

const CENTADDR: &'static str = "127.0.0.1:0";
const RINGSIZE: usize = 128;
const SGNUMBER: usize = 2560;

async fn commbank(addr: SocketAddr, params: &IncognitoParams::<Secp256k1, RINGSIZE>) -> Duration {
    const RINGINDX: usize = 16;

    let start = Instant::now();

    let mut rng = OsRng::default();
    let sks: Vec<_> = (0..RINGSIZE).map(|_| Scalar::random(&mut rng)).collect();
    let pks: Vec<_> = sks.iter().map(|s| ProjectivePoint::GENERATOR * s).collect();    
    
    let mut set = JoinSet::new();

    (0..SGNUMBER).for_each(|i| {
        let params = params.clone();
        let pks = pks.clone();
        let ski = sks[RINGINDX].clone();
        set.spawn(async move {
            let msg = format!("the {}-th transaction in the same interval", i);
            let signature = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&ski, &msg.as_bytes());
            let incsig = params.convert::<Sha256>(&pks, &msg.as_bytes(), &signature, RINGINDX).unwrap();
            (pks.into_iter().map(|each| each.to_affine()).collect::<Vec<_>>(), msg, incsig)
        });
    });

    let mut data_pending = Vec::new();
    while let Some(data) = set.join_next().await {
        data_pending.push(data.unwrap());
    }

    let socket = TcpStream::connect(addr).await.unwrap();
    let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
    for data in data_pending.into_iter() {
        framed.send(Bytes::from(bincode::serialize(&data).unwrap())).await.unwrap();
    };

    start.elapsed()
}

async fn centbank(listener: &TcpListener, params: &IncognitoParams::<Secp256k1, RINGSIZE>) -> Duration {
    let (socket, _) = listener.accept().await.unwrap();
    let start = Instant::now();

    let mut framed = Framed::new(socket, LengthDelimitedCodec::new());

    let mut set = JoinSet::new();

    for _ in 0..SGNUMBER {
        let params = params.clone();
        let (pks, msg, incsig): (Vec<AffinePoint>, String, IncognitoSignature<Secp256k1>) = bincode::deserialize(&framed.next().await.unwrap().unwrap()).unwrap();
        let pks = pks.into_iter().map(|each| ProjectivePoint::from(each)).collect::<Vec<_>>();
        set.spawn(async move {
            params.verify::<Sha256>(&pks, &msg.as_bytes(), &incsig)
        });
    };

    while let Some(res) = set.join_next().await {
        res.unwrap().unwrap();
    }

    start.elapsed()
}

fn bench_settlement_commbank(c: &mut Criterion) {
    c.bench_function("Settlement Commercial bank", |b| {
        b.to_async(Runtime::new().unwrap()).iter_custom(|iters| async move{
            let centbank_listener = TcpListener::bind(CENTADDR).await.unwrap();
            let centbank_addr = centbank_listener.local_addr().unwrap();

            let params = IncognitoParams::<Secp256k1, RINGSIZE>::new();
            let commbank_params = params.clone();
            let centbank_params = params.clone();
            
            let commbank_handler = tokio::spawn(async move {
                let mut duration = Duration::ZERO;
                for _ in 0..iters {
                    duration += commbank(centbank_addr, &commbank_params).await;
                }
                duration
            });

            let centbank_handler = tokio::spawn(async move {
                for _ in 0..iters{
                    centbank(&centbank_listener, &centbank_params).await;
                }
            });

            centbank_handler.await.unwrap();
            commbank_handler.await.unwrap()
        });
    });
}

fn bench_settlement_centbank(c: &mut Criterion) {
    c.bench_function("Settlement Central bank", |b| {
        b.to_async(Runtime::new().unwrap()).iter_custom(|iters| async move{
            let centbank_listener = TcpListener::bind(CENTADDR).await.unwrap();
            let centbank_addr = centbank_listener.local_addr().unwrap();
            
            let params = IncognitoParams::<Secp256k1, RINGSIZE>::new();
            let commbank_params = params.clone();
            let centbank_params = params.clone();
            
            let commbank_handler = tokio::spawn(async move {
                for _ in 0..iters {
                    commbank(centbank_addr, &commbank_params).await;
                }
            });

            let centbank_handler = tokio::spawn(async move {
                let mut duration = Duration::ZERO;
                for _ in 0..iters{
                    duration += centbank(&centbank_listener, &centbank_params).await;
                }
                duration
            });

            commbank_handler.await.unwrap();
            centbank_handler.await.unwrap()
        });
    });
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_settlement_commbank, bench_settlement_centbank
}
criterion_main!(benches);
