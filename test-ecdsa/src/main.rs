use k256::ecdsa::{signature::DigestVerifier, Signature};
use k256::ecdsa::{SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use std::str::FromStr;

fn sk_to_pk(sk: &str) -> anyhow::Result<String> {
    let sk_bytes = hex::decode(sk)?;
    let sk = SigningKey::from_slice(&sk_bytes)?;
    let pk_bytes = sk.verifying_key().to_sec1_bytes();
    Ok(hex::encode(&pk_bytes))
}

fn sign(sk: &str, msg: &[u8]) -> anyhow::Result<String> {
    let sk_bytes = hex::decode(sk)?;
    let sk = SigningKey::from_slice(&sk_bytes)?;
    let digest = Keccak256::new_with_prefix(msg);
    let (sig, _) = sk.sign_digest_recoverable(digest)?;
    Ok(hex::encode(sig.to_bytes()))
}

fn verify(pk: &str, msg: &[u8], sig: &str) -> anyhow::Result<()> {
    let pk_bytes = hex::decode(pk)?;
    let pk = VerifyingKey::from_sec1_bytes(&pk_bytes)?;
    let digest = Keccak256::new_with_prefix(msg);
    let sig = Signature::from_str(sig)?;
    pk.verify_digest(digest, &sig)?;
    Ok(())
}

fn main() {
    let sk = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
    let pk = &sk_to_pk(sk).unwrap();
    let msg = b"hello";
    let sig = sign(sk, msg).unwrap();
    verify(pk, msg, &sig).unwrap();
}
