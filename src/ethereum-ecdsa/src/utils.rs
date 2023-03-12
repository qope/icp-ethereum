use std::convert::TryFrom;

use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey,
};
use tiny_keccak::{Hasher, Keccak};

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(&input);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    hash
}

pub fn pk_to_address(pk: &[u8]) -> anyhow::Result<String> {
    let pk = PublicKey::from_sec1_bytes(&pk)?;
    let pk = pk.to_encoded_point(false);
    let pk = pk.as_bytes();
    let hashed_pk_bytes = keccak256(&pk[1..]);
    let hashed_pk = hex::encode(hashed_pk_bytes);
    Ok(hashed_pk[24..].to_string())
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

pub fn format_sig(pk: &[u8], msg: &[u8], icp_sig: &[u8]) -> anyhow::Result<String> {
    let pk = VerifyingKey::from_sec1_bytes(pk)?;
    let hashed_msg = keccak256(msg);
    let sig = Signature::try_from(icp_sig)?;
    let recid = RecoveryId::trial_recovery_from_prehash(&pk, &hashed_msg, &sig)?;
    let v = u8::from(recid) as u64 + 27;
    let v_bytes: Vec<u8> = v.to_le_bytes().into();
    let sig_with_v = hex::encode(sig.to_bytes()) + &hex::encode(&v_bytes[..1]);
    Ok(sig_with_v)
}

// #[cfg(test)]
// mod tests {
//     use ethers::{
//         providers::{Http, Middleware, Provider},
//         signers::{LocalWallet, Signer},
//         types::{transaction::eip2718::TypedTransaction::Legacy, TransactionRequest},
//         utils::Anvil,
//     };

//     use super::*;

//     #[tokio::test]
//     async fn test_tx() -> anyhow::Result<()> {
//         let anvil = Anvil::new().spawn();
//         let provider = Provider::<Http>::try_from(anvil.endpoint())?;
//         let sk = hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")?;
//         let pk = sk_to_pk(&sk)?;
//         let address = pk_to_address(&pk)?;

//         let wallet = LocalWallet::from_bytes(&sk).unwrap();

//         assert_eq!(wallet.address().as_bytes(), hex::decode(address).unwrap());

//         let accounts = provider.get_accounts().await?;
//         let from = accounts[0];
//         let to = accounts[1];
//         let chain_id = provider.get_chainid().await?;
//         let value = 1000;
//         let gas = 1_000_000;
//         let gas_price = U256::from_dec_str("1000000000").unwrap();
//         let nonce = 0;

//         let tx: TypedTransaction = Legacy(
//             TransactionRequest::new()
//                 .to(to)
//                 .value(value)
//                 .from(from)
//                 .nonce(nonce)
//                 .chain_id(chain_id.as_u64())
//                 .gas(gas)
//                 .gas_price(gas_price),
//         );

//         let encoded_tx = tx.rlp();

//         // here we use icp api
//         let sig_native = sign(&sk, &encoded_tx)?;

//         let mut sig = format_sig(&pk, &encoded_tx, &sig_native)?;
//         sig.v = to_eip155_v(sig.v as u8 - 27, chain_id.as_u64());

//         let sined_tx = tx.rlp_signed(&sig);

//         let sign_expected = wallet.sign_transaction(&tx).await?;
//         let singed_tx_expected = tx.rlp_signed(&sign_expected);

//         assert_eq!(sined_tx, singed_tx_expected);

//         Ok(())
//     }

//     #[test]
//     fn test_message() -> anyhow::Result<()> {
//         let sk = hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")?;
//         let pk = sk_to_pk(&sk)?;

//         let msg = "Some data";
//         let format_msg = format_message(msg.as_bytes());

//         // icp call
//         let sig_native = sign(&sk, &format_msg)?;

//         let sig = format_sig(&pk, &format_msg, &sig_native)?;

//         let wallet = LocalWallet::from_bytes(&sk)?;
//         sig.verify(msg, wallet.address())?;

//         Ok(())
//     }
// }
