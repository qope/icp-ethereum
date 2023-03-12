use crate::{
    ecdsa_api::{self, sign_with_ecdsa},
    utils::{format_message, format_sig, keccak256, pk_to_address},
};

pub async fn get_address(key_name: String, derivation_path: Vec<Vec<u8>>) -> String {
    // Fetch the public key of the given derivation path.
    let public_key = ecdsa_api::ecdsa_public_key(key_name, derivation_path).await;

    let address = pk_to_address(&public_key).expect("address calc error");

    "0x".to_string() + &address
}

pub async fn sign_message(msg: String, key_name: String, derivation_path: Vec<Vec<u8>>) -> String {
    let format_msg = format_message(msg.as_bytes());
    let hashed_msg = keccak256(&format_msg);
    let sig_native = sign_with_ecdsa(
        key_name.clone(),
        derivation_path.clone(),
        hashed_msg.to_vec(),
    )
    .await;
    let pk = ecdsa_api::ecdsa_public_key(key_name, derivation_path).await;
    let sig = format_sig(&pk, &format_msg, &sig_native).expect("format sig error");
    "0x".to_string() + &sig
}

// pub async fn sign_transaction(
//     to: String,
//     value: String,
//     nonce: String,
//     chain_id: String,
//     gas: String,
//     gas_price: String,
//     key_name: String,
//     derivation_path: Vec<Vec<u8>>,
// ) -> String {
//     let public_key = ecdsa_api::ecdsa_public_key(key_name.clone(), derivation_path.clone()).await;
//     let mut address = pk_to_address(&public_key).expect("address calc error");
//     address = "0x".to_string() + &address;

//     let from = H160::from_str(&address).expect("from parse error");
//     let to = H160::from_str(&to).expect("to parse error");
//     let nonce = u64::from_str(&nonce).expect("nonce parse error");
//     let chain_id = u64::from_str(&chain_id).expect("chain_id parse error");
//     let value = U256::from_dec_str(&value).expect("value parse error");
//     let gas = U256::from_dec_str(&gas).expect("gas parse error");
//     let gas_price = U256::from_dec_str(&gas_price).expect("gas_price parse error");

//     let tx: TypedTransaction = Legacy(
//         TransactionRequest::new()
//             .to(to)
//             .value(value)
//             .from(from)
//             .nonce(nonce)
//             .chain_id(chain_id)
//             .gas(gas)
//             .gas_price(gas_price),
//     );
//     let encoded_tx = tx.rlp();
//     let hashed_tx = keccak256(&encoded_tx);

//     let sig_native = sign_with_ecdsa(
//         key_name.clone(),
//         derivation_path.clone(),
//         hashed_tx.to_vec(),
//     )
//     .await;

//     let mut sig = format_sig(&public_key, &encoded_tx, &sig_native).expect("format sig error");
//     sig.v = to_eip155_v(sig.v as u8 - 27, chain_id);

//     let sined_tx = tx.rlp_signed(&sig);

//     hex::encode(sined_tx)
// }
