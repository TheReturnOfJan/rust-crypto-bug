use secp256k1::{Message, SecretKey, PublicKey, sign, Signature as Sig, RecoveryId};
use hex::{FromHex, encode};
use k256::{
    ecdsa::{
        recoverable,
        signature::{Signature, Signer, DigestSigner},
        SigningKey, VerifyingKey,
    },
    Secp256k1,
    elliptic_curve::{FieldBytes, sec1::ToEncodedPoint},
};
use sha3::{Digest, Keccak256};

#[test]
fn sig_is_not_the_same() {
    let mut priv_bytes = [0u8; 32];
    hex::decode_to_slice("e6c09c13a38db68df81c12e599bc2a1b3cbf8f1c225b2c816fbb75bb5d30246a", &mut priv_bytes as &mut [u8]);

    let mut data = [0u8; 32];
    hex::decode_to_slice("bcf48d55045cc3f9add32a7d40e74758e50fbe01e75033bb257dec20ed2e6c27", &mut data as &mut [u8]);

    let mut digest = Keccak256::new();
    digest.update(data);
    
    let secret_key = SecretKey::parse(&priv_bytes).unwrap();
    let message = Message::parse(&digest.clone().finalize().into());
    let (sig1, id) = sign(&message, &secret_key);

    let r1 = hex::encode(&sig1.r.b32()[..]);
    let s1 = hex::encode(&sig1.s.b32()[..]);
    println!("r1: {:?}", r1);
    println!("s1: {:?}", s1);

    let signing_key = SigningKey::from_bytes(&priv_bytes[..]).unwrap();
    let sig2: recoverable::Signature = signing_key.sign_digest(digest);

    let r2: FieldBytes<Secp256k1> = sig2.r().into();
    let s2: FieldBytes<Secp256k1> = sig2.s().into();
    println!("r2 {:?}", hex::encode(r2));
    println!("s2 {:?}", hex::encode(s2));

    assert_eq!(r1, hex::encode(r2));
    assert_eq!(s1, hex::encode(s2));
}
