use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log::error;
use zcash_primitives::{
    consensus::BlockHeight,
    memo::Memo,
    merkle_tree::IncrementalWitness,
    primitives::{Note, Nullifier, PaymentAddress},
    sapling::Node,
    serialize::Vector,
    transaction::{components::TxOut, TxId},
    zip32::ExtendedFullViewingKey,
};

use super::data::{OutgoingTxMetadata, SaplingNoteData, Utxo, WalletTx, WalletZecPriceInfo, WitnessCache};

/// List of all transactions in a wallet.
/// Note that the parent is expected to hold a RwLock, so we will assume that all accesses to
/// this struct are threadsafe/locked properly.
pub struct WalletTxns {
    pub(crate) current: HashMap<TxId, WalletTx>,
    pub(crate) mempool: HashMap<TxId, WalletTx>,
}

impl WalletTxns {
    pub fn serialized_version() -> u64 {
        return 20;
    }

    pub fn new() -> Self {
        Self {
            current: HashMap::new(),
            mempool: HashMap::new(),
        }
    }

    pub fn read_old<R: Read>(mut reader: R) -> io::Result<Self> {
        let txs_tuples = Vector::read(&mut reader, |r| {
            let mut txid_bytes = [0u8; 32];
            r.read_exact(&mut txid_bytes)?;

            Ok((TxId { 0: txid_bytes }, WalletTx::read(r).unwrap()))
        })?;

        let txs = txs_tuples.into_iter().collect::<HashMap<TxId, WalletTx>>();

        Ok(Self {
            current: txs,
            mempool: HashMap::new(),
        })
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        if version > Self::serialized_version() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Can't read wallettxns because of incorrect version",
            ));
        }

        let txs_tuples = Vector::read(&mut reader, |r| {
            let mut txid_bytes = [0u8; 32];
            r.read_exact(&mut txid_bytes)?;

            Ok((TxId { 0: txid_bytes }, WalletTx::read(r).unwrap()))
        })?;

        let current = txs_tuples.into_iter().collect::<HashMap<TxId, WalletTx>>();

        let mempool = Vector::read(&mut reader, |r| {
            let mut txid_bytes = [0u8; 32];
            r.read_exact(&mut txid_bytes)?;
            let wtx = WalletTx::read(r)?;

            Ok((TxId { 0: txid_bytes }, wtx))
        })?
        .into_iter()
        .collect();

        Ok(Self { current, mempool })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write the version
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        // The hashmap, write as a set of tuples. Store them sorted so that wallets are
        // deterministically saved
        {
            let mut txns = self.current.iter().collect::<Vec<(&TxId, &WalletTx)>>();
            txns.sort_by(|a, b| a.0.partial_cmp(b.0).unwrap());

            Vector::write(&mut writer, &txns, |w, (k, v)| {
                w.write_all(&k.0)?;
                v.write(w)
            })?;
        }

        // Write out the mempool txns as well
        {
            let mut mempool = self.mempool.iter().collect::<Vec<(&TxId, &WalletTx)>>();
            mempool.sort_by(|a, b| a.0.partial_cmp(b.0).unwrap());

            Vector::write(&mut writer, &mempool, |w, (txid, wtx)| {
                w.write_all(&txid.0)?;
                wtx.write(w)
            })?;
        }

        Ok(())
    }

    pub fn clear(&mut self) {
        self.current.clear();
        self.mempool.clear();
    }

    pub fn add_mempool(&mut self, mem_tx: WalletTx) {
        self.mempool.insert(mem_tx.txid, mem_tx);
    }

    pub fn remove_mempool(&mut self, txid: &TxId) {
        self.mempool.remove(txid);
    }

    pub fn adjust_spendable_status(&mut self, spendable_keys: Vec<ExtendedFullViewingKey>) {
        self.current.values_mut().for_each(|tx| {
            tx.notes.iter_mut().for_each(|nd| {
                nd.have_spending_key = spendable_keys.contains(&nd.extfvk);
                if !nd.have_spending_key {
                    nd.witnesses.clear();
                }
            })
        });
    }

    // During reorgs, we need to remove all txns at a given height, and all spends that refer to any removed txns.
    pub fn remove_txns_at_height(&mut self, reorg_height: u64) {
        let reorg_height = BlockHeight::from_u32(reorg_height as u32);

        // First, emove entire transactions
        let txids_to_remove = self
            .current
            .values()
            .filter_map(|wtx| {
                if wtx.block >= reorg_height {
                    Some(wtx.txid.clone())
                } else {
                    None
                }
            })
            .collect::<HashSet<TxId>>();

        for txid in &txids_to_remove {
            self.current.remove(&txid);
        }

        // We also need to update any sapling note data and utxos in existing transactions that
        // were spent in any of the txids that were removed
        self.current.values_mut().for_each(|wtx| {
            // Update notes to rollback any spent notes
            wtx.notes.iter_mut().for_each(|nd| {
                if nd.spent.is_some() && txids_to_remove.contains(&nd.spent.unwrap().0) {
                    nd.spent = None;
                }

                // This is not going to happen, but do it for completeness.
                if nd.unconfirmed_spent.is_some() && txids_to_remove.contains(&nd.spent.unwrap().0) {
                    nd.unconfirmed_spent = None;
                }
            });

            // Update UTXOs to rollback any spent utxos
            wtx.utxos.iter_mut().for_each(|utxo| {
                if utxo.spent.is_some() && txids_to_remove.contains(&utxo.spent.unwrap()) {
                    utxo.spent = None;
                    utxo.spent_at_height = None;
                }

                if utxo.unconfirmed_spent.is_some() && txids_to_remove.contains(&utxo.unconfirmed_spent.unwrap().0) {
                    utxo.unconfirmed_spent = None;
                }
            })
        });

        // Of the notes that still remain, unroll the witness.
        // Trim all witnesses for the invalidated blocks
        for tx in self.current.values_mut() {
            // We only want to trim the witness for "existing" notes, i.e., notes that were created before the block that is being removed
            if tx.block < reorg_height {
                for nd in tx.notes.iter_mut() {
                    // The latest witness is at the last() position, so just pop() it.
                    // We should be checking if there is a witness at all, but if there is none, it is an
                    // empty vector, for which pop() is a no-op.
                    let _discard = nd.witnesses.pop(u64::from(reorg_height));
                }
            }
        }
    }

    pub fn get_notes_for_updating(&self, before_block: u64) -> Vec<(TxId, Nullifier)> {
        let before_block = BlockHeight::from_u32(before_block as u32);

        self.current
            .iter()
            .flat_map(|(txid, wtx)| {
                // Fetch notes that are before the before_block.
                wtx.notes.iter().filter_map(move |snd| {
                    if wtx.block <= before_block && snd.have_spending_key && snd.witnesses.len() > 0 {
                        Some((txid.clone(), snd.nullifier.clone()))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    pub fn total_funds_spent_in(&self, txid: &TxId) -> u64 {
        self.current
            .get(&txid)
            .map(|t| t.total_sapling_value_spent + t.total_transparent_value_spent)
            .unwrap_or(0)
    }

    pub fn get_nullifiers(&self, txid: &TxId) -> Vec<Nullifier> {
        self.current
            .get(&txid)
            .unwrap()
            .notes
            .iter()
            .map(|nd| nd.nullifier.clone())
            .collect()
    }

    pub(crate) fn get_note_witness(&self, txid: &TxId, nullifier: &Nullifier) -> Option<(WitnessCache, BlockHeight)> {
        self.current.get(txid).map(|wtx| {
            wtx.notes
                .iter()
                .find(|nd| nd.nullifier == *nullifier)
                .map(|nd| (nd.witnesses.clone(), wtx.block))
        })?
    }

    pub(crate) fn set_note_witnesses(&mut self, txid: &TxId, nullifier: &Nullifier, witnesses: WitnessCache) {
        self.current
            .get_mut(txid)
            .unwrap()
            .notes
            .iter_mut()
            .find(|nd| nd.nullifier == *nullifier)
            .unwrap()
            .witnesses = witnesses;
    }

    // Will mark the nullifier of the given txid as spent. Returns the amount of the nullifier
    pub fn mark_txid_nf_spent(
        &mut self,
        txid: TxId,
        nullifier: &Nullifier,
        spent_txid: &TxId,
        spent_at_height: BlockHeight,
    ) -> u64 {
        let mut note_data = self
            .current
            .get_mut(&txid)
            .unwrap()
            .notes
            .iter_mut()
            .find(|n| n.nullifier == *nullifier)
            .unwrap();

        note_data.spent = Some((spent_txid.clone(), spent_at_height.into()));
        note_data.unconfirmed_spent = None;
        note_data.witnesses = WitnessCache::empty();
        note_data.note.value
    }

    // Check this transaction to see if it is an outgoing transaction, and if it is, mark all recieved notes in this
    // transction as change. i.e., If any funds were spent in this transaction, all recieved notes are change notes.
    pub fn check_notes_mark_change(&mut self, txid: &TxId) {
        if self.total_funds_spent_in(txid) > 0 {
            self.current.get_mut(txid).map(|wtx| {
                wtx.notes.iter_mut().for_each(|n| {
                    n.is_change = true;
                })
            });
        }
    }

    // Records a TxId as having spent some nullifiers from the wallet.
    pub fn add_new_spent(
        &mut self,
        txid: TxId,
        height: BlockHeight,
        timestamp: u32,
        nullifier: Nullifier,
        value: u64,
        source_txid: TxId,
        price: &WalletZecPriceInfo,
    ) {
        if !self.current.contains_key(&txid) {
            self.current
                .insert(txid, WalletTx::new(height.into(), timestamp as u64, &txid, price));
        }

        // Record this Tx as having spent some funds
        {
            let wtx = self.current.get_mut(&txid).expect("Txid should be present");

            // Mark the height correctly, in case this was previously a mempool or unconfirmed tx.
            wtx.block = height;

            if wtx.spent_nullifiers.iter().find(|nf| **nf == nullifier).is_none() {
                wtx.spent_nullifiers.push(nullifier);
                wtx.total_sapling_value_spent += value;
            }
        }

        // Since this Txid has spent some funds, output notes in this Tx that are sent to us are actually change.
        self.check_notes_mark_change(&txid);

        // Mark the source note's nullifier as spent
        {
            let wtx = self.current.get_mut(&source_txid).expect("Txid should be present");

            wtx.notes.iter_mut().find(|n| n.nullifier == nullifier).map(|nd| {
                // Record the spent height
                nd.spent = Some((txid, height.into()));

                // Remove witnesses, because it is now spent
                nd.witnesses.clear();
            });
        }
    }

    pub fn add_taddr_spent(
        &mut self,
        txid: TxId,
        height: BlockHeight,
        timestamp: u64,
        price: &WalletZecPriceInfo,
        total_transparent_value_spent: u64,
    ) {
        if !self.current.contains_key(&txid) {
            self.current
                .insert(txid, WalletTx::new(height, timestamp, &txid, price));
        }
        let wtx = self.current.get_mut(&txid).expect("Txid should be present");
        wtx.total_transparent_value_spent = total_transparent_value_spent;

        self.check_notes_mark_change(&txid);
    }

    pub fn mark_txid_utxo_spent(
        &mut self,
        spent_txid: TxId,
        output_num: u32,
        source_txid: TxId,
        source_height: u32,
    ) -> u64 {
        // Find the UTXO
        let value = if let Some(utxo_wtx) = self.current.get_mut(&spent_txid) {
            if let Some(spent_utxo) = utxo_wtx
                .utxos
                .iter_mut()
                .find(|u| u.txid == spent_txid && u.output_index == output_num as u64)
            {
                // Mark this one as spent
                spent_utxo.spent = Some(source_txid.clone());
                spent_utxo.spent_at_height = Some(source_height as i32);
                spent_utxo.unconfirmed_spent = None;

                spent_utxo.value
            } else {
                panic!("Couldn't find UTXO that was spent");
            }
        } else {
            panic!("Couldn't find TxID that was spent!");
        };

        // Return the value of the note that was spent.
        value
    }

    pub fn add_new_taddr_output(
        &mut self,
        txid: TxId,
        taddr: String,
        height: u32,
        timestamp: u64,
        price: &WalletZecPriceInfo,
        vout: &TxOut,
        output_num: u32,
    ) {
        // Read or create the current TxId
        if !self.current.contains_key(&txid) {
            self.current
                .insert(txid, WalletTx::new(BlockHeight::from(height), timestamp, &txid, price));
        }
        let wtx = self.current.get_mut(&txid).expect("Txid should be present");

        // Add this UTXO if it doesn't already exist
        if wtx
            .utxos
            .iter()
            .find(|utxo| utxo.txid == txid && utxo.output_index == output_num as u64)
            .is_none()
        {
            wtx.utxos.push(Utxo {
                address: taddr,
                txid: txid.clone(),
                output_index: output_num as u64,
                script: vout.script_pubkey.0.clone(),
                value: vout.value.into(),
                height: height as i32,
                spent_at_height: None,
                spent: None,
                unconfirmed_spent: None,
            });
        }
    }

    pub fn add_new_note(
        &mut self,
        txid: TxId,
        height: BlockHeight,
        timestamp: u64,
        note: Note,
        to: PaymentAddress,
        extfvk: &ExtendedFullViewingKey,
        have_spending_key: bool,
        witness: IncrementalWitness<Node>,
        price: &WalletZecPriceInfo,
    ) {
        if !self.current.contains_key(&txid) {
            self.current
                .insert(txid, WalletTx::new(height.into(), timestamp, &txid, price));
        }

        // Check if this is a change note
        let is_change = self.total_funds_spent_in(&txid) > 0;

        {
            let wtx = self.current.get_mut(&txid).expect("Txid should be present");
            // Update the block height, in case this was a mempool or unconfirmed tx.
            wtx.block = height;

            let nullifier = note.nf(&extfvk.fvk.vk, witness.position() as u64);
            let witnesses = if have_spending_key {
                WitnessCache::new(vec![witness], u64::from(height))
            } else {
                WitnessCache::empty()
            };

            match wtx.notes.iter_mut().find(|n| n.nullifier == nullifier) {
                None => {
                    let nd = SaplingNoteData {
                        extfvk: extfvk.clone(),
                        diversifier: *to.diversifier(),
                        note,
                        witnesses,
                        nullifier,
                        spent: None,
                        unconfirmed_spent: None,
                        memo: None,
                        is_change,
                        have_spending_key,
                    };

                    wtx.notes.push(nd);
                }
                Some(n) => {
                    // If this note already exists, then just reset the witnesses, because we'll start scanning the witnesses
                    // again after this.
                    // This is likely to happen if the previous wallet wasn't synced properly or was aborted in the middle of a sync,
                    // and has some dangling witnesses
                    n.witnesses = witnesses;
                }
            }
        }
    }

    // Update the memo for a note if it already exists. If the note doesn't exist, then nothing happens.
    pub fn add_memo_to_note(&mut self, txid: &TxId, note: Note, memo: Memo) {
        self.current.get_mut(txid).map(|wtx| {
            wtx.notes
                .iter_mut()
                .find(|n| n.note == note)
                .map(|n| n.memo = Some(memo));
        });
    }

    pub fn add_outgoing_metadata(&mut self, txid: &TxId, outgoing_metadata: Vec<OutgoingTxMetadata>) {
        let wtx = self.current.get_mut(txid);

        if let Some(wtx) = wtx {
            // This is n^2 search, but this is likely very small struct, limited by the protocol, so...
            let new_omd: Vec<_> = outgoing_metadata
                .into_iter()
                .filter(|om| wtx.outgoing_metadata.iter().find(|o| **o == *om).is_none())
                .collect();

            wtx.outgoing_metadata.extend(new_omd);
        } else {
            error!("TxId {} should be present while adding metadata, but wasn't", txid);
        }
    }
}
