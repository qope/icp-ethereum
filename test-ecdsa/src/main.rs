use ethers::prelude::k256::elliptic_curve::weierstrass::add;
use ethers::types::transaction::eip2718::TypedTransaction::Legacy;
use ethers::{
    core::{types::TransactionRequest, utils::Anvil},
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{transaction::eip2718::TypedTransaction, Signature as EthersSignature, U256},
};
use eyre::Result;
use k256::{
    ecdsa::{signature::DigestVerifier, Signature},
    elliptic_curve::sec1::ToEncodedPoint,
};
use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::FieldBytes,
};
use k256::{PublicKey, Secp256k1};
use sha3::{Digest, Keccak256};
use std::str::FromStr;

pub fn sk_to_pk(sk: &str) -> anyhow::Result<String> {
    let sk_bytes = hex::decode(sk)?;
    let sk = SigningKey::from_slice(&sk_bytes)?;
    let pk_bytes = sk.verifying_key().to_sec1_bytes();
    Ok(hex::encode(&pk_bytes))
}

pub fn pk_to_address(pk: &str) -> anyhow::Result<String> {
    let pk = hex::decode(&pk)?;
    let pk = PublicKey::from_sec1_bytes(&pk)?;
    let pk = pk.to_encoded_point(false);
    let pk = pk.as_bytes();

    let digest = Keccak256::new_with_prefix(&pk[1..]);
    let final_digest = digest.finalize();
    let hashed_pk_bytes = final_digest.as_slice();
    let hashed_pk = hex::encode(hashed_pk_bytes);
    Ok(hashed_pk[24..].to_string())
}

pub fn sign(sk: &str, msg: &[u8]) -> anyhow::Result<String> {
    let sk_bytes = hex::decode(sk)?;
    let sk = SigningKey::from_slice(&sk_bytes)?;
    let digest = Keccak256::new_with_prefix(msg);
    let (sig, _) = sk.sign_digest_recoverable(digest)?;
    Ok(hex::encode(sig.to_bytes()))
}

pub fn sign_with_v(sk: &str, msg: &[u8]) -> anyhow::Result<String> {
    let sk_bytes = hex::decode(sk)?;
    let sk = SigningKey::from_slice(&sk_bytes)?;
    let digest = Keccak256::new_with_prefix(msg);
    let (sig, rec_id) = sk.sign_digest_recoverable(digest)?;
    let v = u8::from(rec_id) as u64 + 27;
    let v_bytes: Vec<u8> = v.to_le_bytes().into();
    let sig_with_v = hex::encode(sig.to_bytes()) + &hex::encode(&v_bytes[..1]);
    Ok(sig_with_v)
}

pub fn verify(pk: &str, msg: &[u8], sig: &str) -> anyhow::Result<()> {
    let pk_bytes = hex::decode(pk)?;
    let pk = VerifyingKey::from_sec1_bytes(&pk_bytes)?;
    let digest = Keccak256::new_with_prefix(msg);
    let sig = Signature::from_str(sig)?;
    pk.verify_digest(digest, &sig)?;
    Ok(())
}

pub fn format_message(message: &[u8]) -> Vec<u8> {
    const PREFIX: &str = "\x19Ethereum Signed Message:\n";

    let len = message.len();
    let len_string = len.to_string();

    let mut eth_message = Vec::with_capacity(PREFIX.len() + len_string.len() + len);
    eth_message.extend_from_slice(PREFIX.as_bytes());
    eth_message.extend_from_slice(len_string.as_bytes());
    eth_message.extend_from_slice(message);

    eth_message
}

const SK: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

#[tokio::main]
async fn main() -> Result<()> {
    // let sk = hex::decode(SK)?;
    // let wallet = LocalWallet::from_bytes(&sk).unwrap();
    // let address = wallet.address();
    // let chain_id = wallet.chain_id();
    // let value = 1;
    // let from = address;
    // let to = address;

    let anvil = Anvil::new().spawn();

    // connect to the network
    let provider = Provider::<Http>::try_from(anvil.endpoint())?;
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let accounts = provider.get_accounts().await?;
    let from = accounts[0];
    let to = accounts[1];
    let chain_id = provider.get_chainid().await?;
    let value = 1000;
    let gas = 1_000_000;
    let gas_price = U256::from_dec_str("1000000000").unwrap();
    let nonce = 0;
    dbg!(chain_id);

    let balance_before = provider.get_balance(from, None).await?;
    let tx: TypedTransaction = Legacy(
        TransactionRequest::new()
            .to(to)
            .value(value)
            .from(from)
            .nonce(nonce)
            .chain_id(chain_id.as_u64())
            .gas(gas)
            .gas_price(gas_price),
    );

    let sign = wallet.sign_transaction(&tx).await?;
    dbg!(sign);

    let tx = tx.rlp_signed(&sign);
    dbg!(&tx);

    let pending_tx = provider.send_raw_transaction(tx).await?;
    let receipt = pending_tx
        .await?
        .ok_or_else(|| eyre::format_err!("tx dropped from mempool"))?;
    let tx = provider.get_transaction(receipt.transaction_hash).await?;

    println!("Sent tx: {}\n", serde_json::to_string(&tx)?);
    println!("Tx receipt: {}", serde_json::to_string(&receipt)?);

    let balance_after = provider.get_balance(from, None).await?;
    println!("Balance before {balance_before}");
    println!("Balance after {balance_after}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() -> anyhow::Result<()> {
        let sk = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let pk = &sk_to_pk(sk)?;
        let msg = b"hello";
        let sig = sign(sk, msg)?;
        verify(pk, msg, &sig)?;
        Ok(())
    }

    #[test]
    fn test_derive_address() -> anyhow::Result<()> {
        let sk = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let pk = &sk_to_pk(sk)?;
        let address = pk_to_address(pk)?;
        anyhow::ensure!(address == "2c7536e3605d9c16a7a3d7b1898e529396a65c23");
        Ok(())
    }

    #[test]
    fn test_sign_ethereum_message() -> anyhow::Result<()> {
        let sk = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let msg = "Some data";
        let format_msg = format_message(msg.as_bytes());
        let sig = sign(sk, &format_msg)?;
        anyhow::ensure!(sig == "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a029");

        let sig_with_v = sign_with_v(sk, &format_msg)?;
        let sig = EthersSignature::from_str(&sig_with_v)?;
        let sk_bytes = hex::decode(sk)?;
        let wallet = LocalWallet::from_bytes(&sk_bytes)?;
        sig.verify(msg, wallet.address())?;
        Ok(())
    }
}
