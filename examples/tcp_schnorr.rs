use anon::schnorr::SchnorrSignature;
use elliptic_curve::Field;
use futures::{SinkExt, StreamExt};
use k256::{sha2::Sha256, AffinePoint, ProjectivePoint, Scalar, Secp256k1};
use rand::rngs::ThreadRng;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::{bytes::Bytes, codec::{Framed, FramedRead, LengthDelimitedCodec}};

const BANKADDR: &'static str = "192.168.70.1";

#[tokio::main]
async fn main() {
    let bank_listener = TcpListener::bind(BANKADDR).await.unwrap();
    let iters = 32;

    let bank_handler = tokio::spawn(async move {
        for _ in 0..iters{
            let (socket, _) = bank_listener.accept().await.unwrap();
            tokio::spawn(async move{
                let mut framed = FramedRead::new(socket, LengthDelimitedCodec::new());
    
                let pk = ProjectivePoint::from(
                    bincode::deserialize::<AffinePoint>(&framed.next().await.unwrap().unwrap()).unwrap()
                );
                let msg = framed.next().await.unwrap().unwrap();
                let sig: SchnorrSignature<Secp256k1> = bincode::deserialize(&framed.next().await.unwrap().unwrap()).unwrap();
        
                sig.verify::<Sha256>(&pk, &msg).unwrap();
                println!("Signature verification suceeded.");
            });
        }
    });
    
    for _ in 0..iters {
        let mut rng = ThreadRng::default();
        let sk = Scalar::random(&mut rng);
        let pk = ProjectivePoint::GENERATOR * sk;
        let msg = "TEST MESSAGE".to_string();
        let sig = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&sk, &msg.as_bytes());

        let mut framed = Framed::new(TcpStream::connect(BANKADDR).await.unwrap(), LengthDelimitedCodec::new());

        framed.send(Bytes::from(bincode::serialize(&pk.to_affine()).unwrap())).await.unwrap();
        framed.send(Bytes::from(msg)).await.unwrap();
        framed.send(Bytes::from(bincode::serialize(&sig).unwrap())).await.unwrap();
    }

    bank_handler.await.unwrap();
}