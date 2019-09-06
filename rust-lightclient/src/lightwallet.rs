use std::time::SystemTime;
use std::io::{self, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use pairing::bls12_381::Bls12;
use zcash_primitives::primitives::{Diversifier, Note, PaymentAddress};
use std::cmp;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use protobuf::*;
use zcash_client_backend::{
    constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS, encoding::encode_payment_address,
    proto::compact_formats::CompactBlock, welding_rig::scan_block,
};
use zcash_primitives::{
    block::BlockHash,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::Node,
    transaction::{
        builder::{Builder},
        components::Amount, components::amount::DEFAULT_FEE,
        TxId, Transaction
    },
    note_encryption::{Memo, try_sapling_note_decryption},
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    JUBJUB,
};

use crate::address;
use crate::prover;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const ANCHOR_OFFSET: u32 = 10;

const SAPLING_ACTIVATION_HEIGHT: i32 = 280_000;


fn now() -> f64 {
    // web_sys::window()
    //     .expect("should have a Window")
    //     .performance()
    //     .expect("should have a Performance")
    //     .now()
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as f64 
}

struct BlockData {
    height: i32,
    hash: BlockHash,
    tree: CommitmentTree<Node>,
}

impl BlockData {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let height = reader.read_i32::<LittleEndian>()?;
        
        let mut hash_bytes = [0; 32];
        reader.read_exact(&mut hash_bytes)?;

        let tree = CommitmentTree::<Node>::read(&mut reader)?;

        Ok(BlockData{
            height, 
            hash: BlockHash{ 0: hash_bytes }, 
            tree
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_i32::<LittleEndian>(self.height)?;
        writer.write_all(&self.hash.0)?;
        self.tree.write(writer)
    }
}

pub struct SaplingNoteData {
    account: usize,
    diversifier: Diversifier,
    note: Note<Bls12>,
    witnesses: Vec<IncrementalWitness<Node>>,
    nullifier: [u8; 32],
    spent: Option<TxId>,
    pub memo:  Option<Memo>
}

impl SaplingNoteData {
    fn new(
        extfvk: &ExtendedFullViewingKey,
        output: zcash_client_backend::wallet::WalletShieldedOutput
    ) -> Self {
        let witness = output.witness;
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
            diversifier: output.to.diversifier,
            note: output.note,
            witnesses: vec![witness],
            nullifier: nf,
            spent: None,
            memo: None
        }
    }

    fn print_note(&self) {
        
    }

pub struct WalletTx {
    block: i32,
    pub notes: Vec<SaplingNoteData>,
}

struct SpendableNote {
    txid: TxId,
    nullifier: [u8; 32],
    diversifier: Diversifier,
    note: Note<Bls12>,
    witness: IncrementalWitness<Node>,
}

impl SpendableNote {
    fn from(txid: TxId, nd: &SaplingNoteData, anchor_offset: usize) -> Option<Self> {
        if nd.spent.is_none() {
            let witness = nd.witnesses.get(nd.witnesses.len() - anchor_offset - 1);

            witness.map(|w| SpendableNote {
                txid,
                nullifier: nd.nullifier,
                diversifier: nd.diversifier,
                note: nd.note.clone(),
                witness: w.clone(),
            })
        } else {
            None
        }
    }
}

pub struct LightWallet {
    extsks: [ExtendedSpendingKey; 1],
    extfvks: [ExtendedFullViewingKey; 1],
    address: PaymentAddress<Bls12>,
    blocks: Arc<RwLock<Vec<BlockData>>>,
    pub txs: Arc<RwLock<HashMap<TxId, WalletTx>>>,
}

impl LightWallet {
    pub fn new() -> Self {

        let extsk = ExtendedSpendingKey::master(&[1; 32]);  // New key
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let address = extfvk.default_address().unwrap().1;

        LightWallet {
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
            Ok(hash) => {
                let mut r = hash;
                r.reverse();
                BlockHash::from_slice(&r)
            },
            Err(e) => {
                eprintln!("{}", e);
                return false;
            }
        };

        let sapling_tree = match hex::decode(sapling_tree) {
            Ok(tree) => tree,
            Err(e) => {
                eprintln!("{}", e);
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

    /// Determines the target height for a transaction, and the offset from which to
    /// select anchors, based on the current synchronised block chain.
    fn get_target_height_and_anchor_offset(&self) -> Option<(u32, usize)> {
        match {
            let blocks = self.blocks.read().unwrap();
            (
                blocks.first().map(|block| block.height as u32),
                blocks.last().map(|block| block.height as u32),
            )
        } {
            (Some(min_height), Some(max_height)) => {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height =
                    cmp::max(target_height.saturating_sub(ANCHOR_OFFSET), min_height);

                Some((target_height, (target_height - anchor_height) as usize))
            }
            _ => None,
        }
    }

    pub fn address(&self) -> String {
        encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &self.address)
    }

    pub fn balance(&self) -> u64 {
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
            .sum::<u64>()
    }

    pub fn verified_balance(&self) -> u64 {
        let anchor_height = match self.get_target_height_and_anchor_offset() {
            Some((height, anchor_offset)) => height - anchor_offset as u32,
            None => return 0,
        };

        self.txs
            .read()
            .unwrap()
            .values()
            .map(|tx| {
                if tx.block as u32 <= anchor_height {
                    tx.notes
                        .iter()
                        .map(|nd| if nd.spent.is_none() { nd.note.value } else { 0 })
                        .sum::<u64>()
                } else {
                    0
                }
            })
            .sum::<u64>()
    }

    pub fn scan_full_tx(&self, tx: &Transaction) {
        for output in tx.shielded_outputs.iter() {

            let ivks: Vec<_> = self.extfvks.iter().map(|extfvk| extfvk.fvk.vk.ivk()).collect();

            let cmu = output.cmu;
            let ct  = output.enc_ciphertext;

            for (_account, ivk) in ivks.iter().enumerate() {
                let epk_prime = output.ephemeral_key.as_prime_order(&JUBJUB).unwrap();

                let (note, _to, memo) = match try_sapling_note_decryption(ivk, &epk_prime, &cmu, &ct) {
                    Some(ret) => ret,
                    None => continue,
                };

                {
                    // Update the WalletTx 
                    // Do it in a short scope because of the write lock.
                    let mut txs = self.txs.write().unwrap();
                    txs.get_mut(&tx.txid()).unwrap()
                        .notes.iter_mut()
                        .find(|nd| nd.note == note).unwrap()
                        .memo = Some(memo);
                }
            }
        }
    }

    pub fn scan_block(&self, block: &[u8]) -> bool {
        let block: CompactBlock = match parse_from_bytes(block) {
            Ok(block) => block,
            Err(e) => {
                eprintln!("Could not parse CompactBlock from bytes: {}", e);
                return false;
            }
        };

        // Scanned blocks MUST be height-sequential.
        let height = block.get_height() as i32;
        if height == self.last_scanned_height() {
            // If the last scanned block is rescanned, check it still matches.
            if let Some(hash) = self.blocks.read().unwrap().last().map(|block| block.hash) {
                if block.hash() != hash {
                    eprintln!("Block hash does not match for block {}. {} vs {}", height, block.hash(), hash);
                    return false;
                }
            }
            return true;
        } else if height != (self.last_scanned_height() + 1) {
            eprintln!(
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
                    let clone = witness.clone();
                    nd.witnesses.push(clone);
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

        for tx in new_txs {
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
            for output in tx
                .shielded_outputs
                .into_iter()
            {
                tx_entry.notes.push(SaplingNoteData::new(
                    &self.extfvks[output.account],
                    output
                ));
            }
        }

        // Store scanned data for this block.
        self.blocks.write().unwrap().push(block_data);

        true
    }

    pub fn send_to_address(
        &self,
        consensus_branch_id: u32,
        spend_params: &[u8],
        output_params: &[u8],
        to: &str,
        value: u64,
        memo: Option<String>,
    ) -> Option<Box<[u8]>> {
        let start_time = now();
        println!(
            "0: Creating transaction sending {} tazoshis to {}",
            value,
            to
        );

        let extsk = &self.extsks[0];
        let extfvk = &self.extfvks[0];
        let ovk = extfvk.fvk.ovk;

        let to = match address::RecipientAddress::from_str(to) {
            Some(to) => to,
            None => {
                eprintln!("Invalid recipient address");
                return None;
            }
        };
        let value = Amount::from_u64(value).unwrap();

        // Target the next block, assuming we are up-to-date.
        let (height, anchor_offset) = match self.get_target_height_and_anchor_offset() {
            Some(res) => res,
            None => {
                eprintln!("Cannot send funds before scanning any blocks");
                return None;
            }
        };

        // Select notes to cover the target value
        println!("{}: Selecting notes", now() - start_time);
        let target_value = value + DEFAULT_FEE ;
        let notes: Vec<_> = self
            .txs
            .read()
            .unwrap()
            .iter()
            .map(|(txid, tx)| tx.notes.iter().map(move |note| (*txid, note)))
            .flatten()
            .filter_map(|(txid, note)| SpendableNote::from(txid, note, anchor_offset))
            .scan(0, |running_total, spendable| {
                let value = spendable.note.value;
                let ret = if *running_total < u64::from(target_value) {
                    Some(spendable)
                } else {
                    None
                };
                *running_total = *running_total + value;
                ret
            })
            .collect();

        // Confirm we were able to select sufficient value
        let selected_value = notes
            .iter()
            .map(|selected| selected.note.value)
            .sum::<u64>();
        if selected_value < u64::from(target_value) {
            eprintln!(
                "Insufficient funds (have {}, need {:?})",
                selected_value, target_value
            );
            return None;
        }

        // Create the transaction
        println!("{}: Adding {} inputs", now() - start_time, notes.len());
        let mut builder = Builder::new(height);
        for selected in notes.iter() {
            if let Err(e) = builder.add_sapling_spend(
                extsk.clone(),
                selected.diversifier,
                selected.note.clone(),
                selected.witness.clone(),
            ) {
                eprintln!("Error adding note: {:?}", e);
                return None;
            }
        }

        // Compute memo if it exists
        let encoded_memo = memo.map(|s| Memo::from_str(&s).unwrap() );

        println!("{}: Adding output", now() - start_time);
        if let Err(e) = match to {
            address::RecipientAddress::Shielded(to) => {
                builder.add_sapling_output(ovk, to.clone(), value, encoded_memo)
            }
            address::RecipientAddress::Transparent(to) => {
                builder.add_transparent_output(&to, value)
            }
        } {
            eprintln!("Error adding output: {:?}", e);
            return None;
        }
        println!("{}: Building transaction", now() - start_time);
        let (tx, _) = match builder.build(
            consensus_branch_id,
            prover::InMemTxProver::new(spend_params, output_params),
        ) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Error creating transaction: {:?}", e);
                return None;
            }
        };
        println!("{}: Transaction created", now() - start_time);
        println!("Transaction ID: {}", tx.txid());

        // Mark notes as spent.
        let mut txs = self.txs.write().unwrap();
        for selected in notes {
            let mut spent_note = txs
                .get_mut(&selected.txid)
                .unwrap()
                .notes
                .iter_mut()
                .find(|nd| &nd.nullifier[..] == &selected.nullifier[..])
                .unwrap();
            spent_note.spent = Some(tx.txid());
        }

        // Return the encoded transaction, so the caller can send it.
        let mut raw_tx = vec![];
        tx.write(&mut raw_tx).unwrap();
        Some(raw_tx.into_boxed_slice())
    }
}
