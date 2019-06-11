macro_rules! error {
    ( $( $t:tt )* ) => {
        web_sys::console::error_1(&format!( $( $t )* ).into());
    };
}

mod utils;

use pairing::bls12_381::Bls12;
use protobuf::parse_from_bytes;
use sapling_crypto::primitives::{Note, PaymentAddress};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zcash_client_backend::{
    constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS, encoding::encode_payment_address,
    proto::compact_formats::CompactBlock, welding_rig::scan_block,
};
use zcash_primitives::{
    block::BlockHash,
    merkle_tree::{CommitmentTree, IncrementalWitness},
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

const SAPLING_ACTIVATION_HEIGHT: i32 = 280_000;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

struct BlockData {
    height: i32,
    hash: BlockHash,
    tree: CommitmentTree<Node>,
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
    blocks: Arc<RwLock<Vec<BlockData>>>,
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
            blocks: Arc::new(RwLock::new(vec![])),
            txs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn set_initial_block(&self, height: i32, hash: &str, sapling_tree: &str) -> bool {
        let mut blocks = self.blocks.write().unwrap();
        if !blocks.is_empty() {
            return false;
        }

        let hash = match hex::decode(hash) {
            Ok(hash) => BlockHash::from_slice(&hash),
            Err(e) => {
                error!("{}", e);
                return false;
            }
        };

        let sapling_tree = match hex::decode(sapling_tree) {
            Ok(tree) => tree,
            Err(e) => {
                error!("{}", e);
                return false;
            }
        };

        if let Ok(tree) = CommitmentTree::read(&sapling_tree[..]) {
            blocks.push(BlockData { height, hash, tree });
            true
        } else {
            false
        }
    }

    pub fn last_scanned_height(&self) -> i32 {
        self.blocks
            .read()
            .unwrap()
            .last()
            .map(|block| block.height)
            .unwrap_or(SAPLING_ACTIVATION_HEIGHT - 1)
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

    pub fn scan_block(&self, block: &[u8]) -> bool {
        let block: CompactBlock = match parse_from_bytes(block) {
            Ok(block) => block,
            Err(e) => {
                error!("Could not parse CompactBlock from bytes: {}", e);
                return false;
            }
        };

        // Scanned blocks MUST be height-sequential.
        let height = block.get_height() as i32;
        if height == self.last_scanned_height() {
            // If the last scanned block is rescanned, check it still matches.
            if let Some(hash) = self.blocks.read().unwrap().last().map(|block| block.hash) {
                if block.hash() != hash {
                    error!("Block hash does not match");
                    return false;
                }
            }
            return true;
        } else if height != (self.last_scanned_height() + 1) {
            error!(
                "Block is not height-sequential (expected {}, found {})",
                self.last_scanned_height() + 1,
                height
            );
            return false;
        }

        // Get the most recent scanned data.
        let mut block_data = BlockData {
            height,
            hash: block.hash(),
            tree: self
                .blocks
                .read()
                .unwrap()
                .last()
                .map(|block| block.tree.clone())
                .unwrap_or(CommitmentTree::new()),
        };
        let mut txs = self.txs.write().unwrap();

        // Create a Vec containing all unspent nullifiers.
        let nfs: Vec<_> = txs
            .iter()
            .map(|(txid, tx)| {
                let txid = *txid;
                tx.notes.iter().filter_map(move |nd| {
                    if nd.spent.is_none() {
                        Some((nd.nullifier, nd.account, txid))
                    } else {
                        None
                    }
                })
            })
            .flatten()
            .collect();

        // Prepare the note witnesses for updating
        for tx in txs.values_mut() {
            for nd in tx.notes.iter_mut() {
                // Duplicate the most recent witness
                if let Some(witness) = nd.witnesses.last() {
                    nd.witnesses.push(witness.clone());
                }
                // Trim the oldest witnesses
                nd.witnesses = nd
                    .witnesses
                    .split_off(nd.witnesses.len().saturating_sub(100));
            }
        }

        let new_txs = {
            let nf_refs: Vec<_> = nfs.iter().map(|(nf, acc, _)| (&nf[..], *acc)).collect();

            // Create a single mutable slice of all the newly-added witnesses.
            let mut witness_refs: Vec<_> = txs
                .values_mut()
                .map(|tx| tx.notes.iter_mut().filter_map(|nd| nd.witnesses.last_mut()))
                .flatten()
                .collect();

            scan_block(
                block,
                &self.extfvks,
                &nf_refs[..],
                &mut block_data.tree,
                &mut witness_refs[..],
            )
        };

        for (tx, new_witnesses) in new_txs {
            // Mark notes as spent.
            for spend in &tx.shielded_spends {
                let txid = nfs
                    .iter()
                    .find(|(nf, _, _)| &nf[..] == &spend.nf[..])
                    .unwrap()
                    .2;
                let mut spent_note = txs
                    .get_mut(&txid)
                    .unwrap()
                    .notes
                    .iter_mut()
                    .find(|nd| &nd.nullifier[..] == &spend.nf[..])
                    .unwrap();
                spent_note.spent = Some(tx.txid);
            }

            // Find the existing transaction entry, or create a new one.
            if !txs.contains_key(&tx.txid) {
                let tx_entry = WalletTx {
                    block: block_data.height,
                    notes: vec![],
                };
                txs.insert(tx.txid, tx_entry);
            }
            let tx_entry = txs.get_mut(&tx.txid).unwrap();

            // Save notes.
            for (output, witness) in tx
                .shielded_outputs
                .into_iter()
                .zip(new_witnesses.into_iter())
            {
                tx_entry.notes.push(SaplingNoteData::new(
                    &self.extfvks[output.account],
                    output,
                    witness,
                ));
            }
        }

        // Store scanned data for this block.
        self.blocks.write().unwrap().push(block_data);

        true
    }
}
