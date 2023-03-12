pub mod ecdsa_api;
mod ethereum_wallet;
pub mod types;
pub mod utils;

use ethereum_wallet::{get_address, sign_message as inner_sign_message, sign_transaction};
use ic_cdk::export::{
    candid::CandidType,
    serde::{Deserialize, Serialize},
    Principal,
};
use ic_cdk::{query, update};

#[derive(CandidType, Serialize, Debug)]
struct PublicKeyReply {
    pub public_key_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct AddressReply {
    pub address_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureReply {
    pub signature_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct MessageSignatureReply {
    pub signature_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct TxReply {
    pub tx_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureVerificationReply {
    pub is_signature_valid: bool,
}

type CanisterId = Principal;

#[derive(CandidType, Serialize, Debug)]
struct ECDSAPublicKey {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

#[update]
async fn address() -> Result<AddressReply, String> {
    let address = get_address("dfx_test_key".to_string(), vec![]).await;
    Ok(AddressReply {
        address_hex: address,
    })
}

#[update]
async fn sign_message(message: String) -> Result<MessageSignatureReply, String> {
    let sined_message = inner_sign_message(message, "dfx_test_key".to_string(), vec![]).await;
    Ok(MessageSignatureReply {
        signature_hex: sined_message,
    })
}

#[update]
async fn sign_tx(
    to: String,
    value: String,
    nonce: String,
    chain_id: String,
    gas: String,
    gas_price: String,
) -> Result<TxReply, String> {
    let tx_hex = sign_transaction(
        to,
        value,
        nonce,
        chain_id,
        gas,
        gas_price,
        "dfx_test_key".to_string(),
        vec![],
    )
    .await;
    Ok(TxReply { tx_hex })
}



// #[query]
// async fn verify(
//     signature_hex: String,
//     message: String,
//     public_key_hex: String,
// ) -> Result<SignatureVerificationReply, String> {
//     use k256::ecdsa::signature::DigestVerifier;
//     use sha3::{Digest, Keccak256};

//     let signature_bytes = hex::decode(&signature_hex).expect("failed to hex-decode signature");
//     let pubkey_bytes = hex::decode(&public_key_hex).expect("failed to hex-decode public key");

//     let public_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes).expect("failed parse public key");
//     let message_bytes = message.as_bytes();
//     let digest = Keccak256::new_with_prefix(message_bytes);

//     let signature = k256::ecdsa::Signature::try_from(signature_bytes.as_slice())
//         .expect("failed to deserialize signature");
//     let is_signature_valid = public_key.verify_digest(digest, &signature).is_ok();

//     Ok(SignatureVerificationReply { is_signature_valid })
// }

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
