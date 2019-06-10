mod utils;

use pairing::bls12_381::Bls12;
use sapling_crypto::primitives::{Note, PaymentAddress};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zcash_client_backend::{
    constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS, encoding::encode_payment_address,
};
use zcash_primitives::{
    merkle_tree::IncrementalWitness,
    sapling::Node,
    transaction::TxId,
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    JUBJUB,
};

use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

struct SaplingNoteData {
    account: usize,
    note: Note<Bls12>,
    witnesses: Vec<IncrementalWitness<Node>>,
    nullifier: [u8; 32],
    spent: Option<TxId>,
}

impl SaplingNoteData {
    fn new(
        extfvk: &ExtendedFullViewingKey,
        output: zcash_client_backend::wallet::WalletShieldedOutput,
        witness: IncrementalWitness<Node>,
    ) -> Self {
        let nf = {
            let mut nf = [0; 32];
            nf.copy_from_slice(
                &output
                    .note
                    .nf(&extfvk.fvk.vk, witness.position() as u64, &JUBJUB),
            );
            nf
        };

        SaplingNoteData {
            account: output.account,
            note: output.note,
            witnesses: vec![],
            nullifier: nf,
            spent: None,
        }
    }
}

struct WalletTx {
    block: i32,
    notes: Vec<SaplingNoteData>,
}

#[wasm_bindgen]
pub struct Client {
    extsks: [ExtendedSpendingKey; 1],
    extfvks: [ExtendedFullViewingKey; 1],
    address: PaymentAddress<Bls12>,
    txs: Arc<RwLock<HashMap<TxId, WalletTx>>>,
}

/// Public methods, exported to JavaScript.
#[wasm_bindgen]
impl Client {
    pub fn new() -> Self {
        utils::set_panic_hook();

        let extsk = ExtendedSpendingKey::master(&[0; 32]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let address = extfvk.default_address().unwrap().1;

        Client {
            extsks: [extsk],
            extfvks: [extfvk],
            address,
            txs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn address(&self) -> String {
        encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &self.address)
    }

    // TODO: This will be inaccurate if the balance exceeds a u32, but u64 -> JavaScript
    // requires BigUint64Array which has limited support across browsers, and is not
    // implemented in the LTS version of Node.js. For now, let's assume that no one is
    // going to use a web wallet with more than ~21 TAZ.
    pub fn balance(&self) -> u32 {
        self.txs
            .read()
            .unwrap()
            .values()
            .map(|tx| {
                tx.notes
                    .iter()
                    .map(|nd| if nd.spent.is_none() { nd.note.value } else { 0 })
                    .sum::<u64>()
            })
            .sum::<u64>() as u32
    }
}
