mod ecdsa_api;
mod ethereum_wallet;
mod types;
mod utils;

use ethereum_wallet::{get_address, sign_message as inner_sign_message};
use ic_cdk::update;
use types::*;

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

// #[update]
// async fn sign_tx(
//     to: String,
//     value: String,
//     nonce: String,
//     chain_id: String,
//     gas: String,
//     gas_price: String,
// ) -> Result<TxReply, String> {
//     let tx_hex = sign_transaction(
//         to,
//         value,
//         nonce,
//         chain_id,
//         gas,
//         gas_price,
//         "dfx_test_key".to_string(),
//         vec![],
//     )
//     .await;
//     Ok(TxReply { tx_hex })
// }

getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
