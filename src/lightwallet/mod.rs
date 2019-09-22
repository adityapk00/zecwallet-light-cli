use std::time::SystemTime;
use std::io::{self, Read, Write};
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use log::{info, warn, error};

use protobuf::parse_from_bytes;

use bip39::{Mnemonic, Language};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use pairing::bls12_381::{Bls12};

use zcash_client_backend::{
    encoding::encode_payment_address,
    proto::compact_formats::CompactBlock, welding_rig::scan_block,
};

use zcash_primitives::{
    block::BlockHash,
    merkle_tree::{CommitmentTree},
    serialize::{Vector},
    transaction::{
        builder::{Builder},
        components::{Amount, OutPoint, TxOut}, components::amount::DEFAULT_FEE,
        TxId, Transaction, 
    },
     legacy::{Script, TransparentAddress},
    note_encryption::{Memo, try_sapling_note_decryption, try_sapling_output_recovery},
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey, ChildIndex},
    JUBJUB,
    primitives::{PaymentAddress},
};

use data::{BlockData, WalletTx, Utxo, SaplingNoteData, SpendableNote, OutgoingTxMetadata};

use crate::address;
use crate::prover;
use crate::LightClientConfig;

use sha2::{Sha256, Digest};

pub mod data;
pub mod extended_key;

use extended_key::{KeyIndex, ExtendedPrivKey};

const ANCHOR_OFFSET: u32 = 1;
pub const MAX_REORG: usize = 100;

fn now() -> f64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as f64
}


/// Sha256(Sha256(value))
pub fn double_sha256(payload: &[u8]) -> Vec<u8> {
    let h1 = Sha256::digest(&payload);
    let h2 = Sha256::digest(&h1);
    h2.to_vec()
}

use base58::{ToBase58, FromBase58};

/// A trait for converting a [u8] to base58 encoded string.
pub trait ToBase58Check {
    /// Converts a value of `self` to a base58 value, returning the owned string.
    /// The version is a coin-specific prefix that is added.
    /// The suffix is any bytes that we want to add at the end (like the "iscompressed" flag for
    /// Secret key encoding)
    fn to_base58check(&self, version: &[u8], suffix: &[u8]) -> String;
}

impl ToBase58Check for [u8] {
    fn to_base58check(&self, version: &[u8], suffix: &[u8]) -> String {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(version);
        payload.extend_from_slice(self);
        payload.extend_from_slice(suffix);

        let mut checksum = double_sha256(&payload);
        payload.append(&mut checksum[..4].to_vec());
        payload.to_base58()
    }
}

pub trait FromBase58Check {
    fn from_base58check(&self, version: &[u8], suffix: &[u8]) -> Vec<u8>;
}


impl FromBase58Check for str {
    fn from_base58check(&self, version: &[u8], suffix: &[u8]) -> Vec<u8> {
        let mut payload: Vec<u8> = Vec::new();
        let bytes = self.from_base58().unwrap();

        let start = version.len();
        let end = bytes.len() - (4 + suffix.len());

        payload.extend(&bytes[start..end]);

        payload
    }
}


pub struct LightWallet {
    seed: [u8; 32], // Seed phrase for this wallet. 

    // List of keys, actually in this wallet. This may include more
    // than keys derived from the seed, for example, if user imports 
    // a private key
    extsks:  Vec<ExtendedSpendingKey>,
    extfvks: Vec<ExtendedFullViewingKey>,
    pub address: Vec<PaymentAddress<Bls12>>,
    
    // Transparent keys. TODO: Make it not pubic
    pub tkeys: Vec<secp256k1::SecretKey>,

    blocks: Arc<RwLock<Vec<BlockData>>>,
    pub txs: Arc<RwLock<HashMap<TxId, WalletTx>>>,

    // Non-serialized fields
    config: LightClientConfig,
}

impl LightWallet {
    pub fn serialized_version() -> u64 {
        return 1;
    }

    fn get_pk_from_bip39seed(bip39seed: &[u8]) ->
            (ExtendedSpendingKey, ExtendedFullViewingKey, PaymentAddress<Bls12>) {
        let extsk: ExtendedSpendingKey = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(bip39seed),
            &[
                ChildIndex::Hardened(32),
                ChildIndex::Hardened(1),    // TODO: Cointype should be 133 for mainnet
                ChildIndex::Hardened(0)
            ],
        );
        let extfvk  = ExtendedFullViewingKey::from(&extsk);
        let address = extfvk.default_address().unwrap().1;

        (extsk, extfvk, address)
    }

    pub fn new(seed_phrase: Option<String>, config: &LightClientConfig) -> io::Result<Self> {
        use rand::{FromEntropy, ChaChaRng, Rng};

        // This is the source entropy that corresponds to the 24-word seed phrase
        let mut seed_bytes = [0u8; 32];

        if seed_phrase.is_none() {
            // Create a random seed. 
            let mut system_rng = ChaChaRng::from_entropy();
            system_rng.fill(&mut seed_bytes);
        } else {
            seed_bytes.copy_from_slice(&Mnemonic::from_phrase(seed_phrase.expect("should have a seed phrase"), 
                    Language::English).unwrap().entropy());
        }

        // The seed bytes is the raw entropy. To pass it to HD wallet generation, 
        // we need to get the 64 byte bip39 entropy
        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&seed_bytes, Language::English).unwrap(), "");

        // TODO: This only reads one key for now
        let ext_t_key = ExtendedPrivKey::with_seed(&bip39_seed.as_bytes()).unwrap();
        let tpk = ext_t_key
            .derive_private_key(KeyIndex::hardened_from_normalize_index(44).unwrap()).unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(1).unwrap()).unwrap() // TODO: Cointype
            .derive_private_key(KeyIndex::hardened_from_normalize_index(0).unwrap()).unwrap()
            .derive_private_key(KeyIndex::Normal(0)).unwrap()
            .derive_private_key(KeyIndex::Normal(0)).unwrap()
            .private_key;

        // Derive only the first address
        // TODO: We need to monitor addresses, and always keep 1 "free" address, so 
        // users can import a seed phrase and automatically get all used addresses
        let (extsk, extfvk, address) = LightWallet::get_pk_from_bip39seed(&bip39_seed.as_bytes());

        Ok(LightWallet {
            seed:    seed_bytes,
            extsks:  vec![extsk],
            extfvks: vec![extfvk],
            address: vec![address],
            tkeys:   vec![tpk],
            blocks:  Arc::new(RwLock::new(vec![])),
            txs:     Arc::new(RwLock::new(HashMap::new())),
            config:  config.clone(),
        })
    }

    pub fn read<R: Read>(mut reader: R, config: &LightClientConfig) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        assert!(version <= LightWallet::serialized_version());
        info!("Reading wallet version {}", version);

        // Seed
        let mut seed_bytes = [0u8; 32];
        reader.read_exact(&mut seed_bytes)?;

        // Read the spending keys
        let extsks = Vector::read(&mut reader, |r| ExtendedSpendingKey::read(r))?;

        // Calculate the viewing keys
        let extfvks = extsks.iter().map(|sk| ExtendedFullViewingKey::from(sk))
            .collect::<Vec<ExtendedFullViewingKey>>();

        // Calculate the addresses
        let addresses = extfvks.iter().map( |fvk| fvk.default_address().unwrap().1 )
            .collect::<Vec<PaymentAddress<Bls12>>>();

        let mut tpk_bytes = [0u8; 32];
        reader.read_exact(&mut tpk_bytes)?;
        let tpk = secp256k1::SecretKey::from_slice(&tpk_bytes).unwrap();

        let blocks = Vector::read(&mut reader, |r| BlockData::read(r))?;

        let txs_tuples = Vector::read(&mut reader, |r| {
            let mut txid_bytes = [0u8; 32];
            r.read_exact(&mut txid_bytes)?;

            Ok((TxId{0: txid_bytes}, WalletTx::read(r).unwrap()))
        })?;
        let txs = txs_tuples.into_iter().collect::<HashMap<TxId, WalletTx>>();

        Ok(LightWallet{
            seed:    seed_bytes,
            extsks:  extsks,
            extfvks: extfvks,
            address: addresses,
            tkeys:   vec![tpk],
            blocks:  Arc::new(RwLock::new(blocks)),
            txs:     Arc::new(RwLock::new(txs)),
            config:  config.clone(),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write the version
        writer.write_u64::<LittleEndian>(LightWallet::serialized_version())?;

        // Write the seed
        writer.write_all(&self.seed)?;

        // Write all the spending keys
        Vector::write(&mut writer, &self.extsks, 
             |w, sk| sk.write(w)
        )?;

        // Write the transparent private key
        // TODO: This only writes the first key for now
        writer.write_all(&self.tkeys[0][..])?;

        Vector::write(&mut writer, &self.blocks.read().unwrap(), |w, b| b.write(w))?;
                
        // The hashmap, write as a set of tuples
        Vector::write(&mut writer, &self.txs.read().unwrap().iter().collect::<Vec<(&TxId, &WalletTx)>>(),
                        |w, (k, v)| {
                            w.write_all(&k.0)?;
                            v.write(w)
                        })?;
        Ok(())
    }

    pub fn note_address(&self, note: &SaplingNoteData) -> Option<String> {
        match note.extfvk.fvk.vk.into_payment_address(note.diversifier, &JUBJUB) {
            Some(pa) => Some(encode_payment_address(self.config.hrp_sapling_address(), &pa)),
            None     => None
        }
    }

    // Clears all the downloaded blocks and resets the state back to the inital block.
    // After this, the wallet's initial state will need to be set
    // and the wallet will need to be rescanned
    pub fn clear_blocks(&self) {
        self.blocks.write().unwrap().clear();
        self.txs.write().unwrap().clear();
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

    // Get the latest sapling commitment tree. It will return the height and the hex-encoded sapling commitment tree at that height
    pub fn get_sapling_tree(&self) -> Result<(i32, String, String), String> {
        let blocks = self.blocks.read().unwrap();

        let block = match blocks.last() {
            Some(block) => block,
            None => return Err("Couldn't get a block height!".to_string())
        };

        let mut write_buf = vec![];
        block.tree.write(&mut write_buf).map_err(|e| format!("Error writing commitment tree {}", e))?;

        let mut blockhash = vec![];
        blockhash.extend_from_slice(&block.hash.0);
        blockhash.reverse();

        Ok((block.height, hex::encode(blockhash), hex::encode(write_buf)))
    }

    pub fn last_scanned_height(&self) -> i32 {
        self.blocks.read().unwrap()
            .last()
            .map(|block| block.height)
            .unwrap_or(self.config.sapling_activation_height as i32 - 1)
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

    pub fn memo_str(memo: &Option<Memo>) -> Option<String> {
        match memo {
            Some(memo) => {
                match memo.to_utf8() {
                    Some(Ok(memo_str)) => Some(memo_str),
                    _ => None
                }
            }
            _ => None
        }
    }

    pub fn address_from_sk(&self, sk: &secp256k1::SecretKey) -> String {
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        // Encode into t address
        let mut hash160 = ripemd160::Ripemd160::new();
        hash160.input(Sha256::digest(&pk.serialize()[..].to_vec()));

        hash160.result().to_base58check(&self.config.base58_pubkey_address(), &[])
    }
    
    pub fn address_from_pubkeyhash(&self, ta: Option<TransparentAddress>) -> Option<String> {
        match ta {
            Some(TransparentAddress::PublicKey(hash)) => {
                Some(hash.to_base58check(&self.config.base58_pubkey_address(), &[]))
            },
            _ => None
        }
    }

    pub fn get_seed_phrase(&self) -> String {
        Mnemonic::from_entropy(&self.seed, 
                                Language::English,
        ).unwrap().phrase().to_string()
    }

    pub fn zbalance(&self, addr: Option<String>) -> u64 {
        self.txs.read().unwrap()
            .values()
            .map(|tx| {
                tx.notes.iter()
                    .filter(|nd| {  // TODO, this whole section is shared with verified_balance. Refactor it. 
                        match addr.clone() {
                            Some(a) => a == encode_payment_address(
                                                self.config.hrp_sapling_address(),
                                                &nd.extfvk.fvk.vk
                                                    .into_payment_address(nd.diversifier, &JUBJUB).unwrap()
                                            ),
                            None    => true
                        }
                    })
                    .map(|nd| if nd.spent.is_none() { nd.note.value } else { 0 })
                    .sum::<u64>()
            })
            .sum::<u64>()
    }

    // Get all (unspent) utxos. Unconfirmed spent utxos are included
    pub fn get_utxos(&self) -> Vec<Utxo> {
        let txs = self.txs.read().unwrap();

        txs.values()
            .flat_map(|tx| {
                tx.utxos.iter().filter(|utxo| utxo.spent.is_none())
            })
            .map(|utxo| utxo.clone())
            .collect::<Vec<Utxo>>()
    }

    pub fn tbalance(&self, addr: Option<String>) -> u64 {
        self.get_utxos().iter()
            .filter(|utxo| {
                match addr.clone() {
                    Some(a) => utxo.address == a,
                    None    => true,
                }
            })
            .map(|utxo| utxo.value )
            .sum::<u64>()
    }

    pub fn verified_zbalance(&self, addr: Option<String>) -> u64 {
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
                        .filter(|nd| {  // TODO, this whole section is shared with verified_balance. Refactor it. 
                            match addr.clone() {
                                Some(a) => a == encode_payment_address(
                                                    self.config.hrp_sapling_address(),
                                                    &nd.extfvk.fvk.vk
                                                        .into_payment_address(nd.diversifier, &JUBJUB).unwrap()
                                                ),
                                None    => true
                            }
                        })
                        .map(|nd| if nd.spent.is_none() && nd.unconfirmed_spent.is_none() { nd.note.value } else { 0 })
                        .sum::<u64>()
                } else {
                    0
                }
            })
            .sum::<u64>()
    }

    fn add_toutput_to_wtx(&self, height: i32, txid: &TxId, vout: &TxOut, n: u64) {
        let mut txs = self.txs.write().unwrap();

        // Find the existing transaction entry, or create a new one.
        if !txs.contains_key(&txid) {
            let tx_entry = WalletTx::new(height, &txid);
            txs.insert(txid.clone(), tx_entry);
        }
        let tx_entry = txs.get_mut(&txid).unwrap();

        // Make sure the vout isn't already there.
        match tx_entry.utxos.iter().find(|utxo| {
            utxo.txid == *txid && utxo.output_index == n && Amount::from_u64(utxo.value).unwrap() == vout.value
        }) {
            Some(utxo) => { 
                info!("Already have {}:{}", utxo.txid, utxo.output_index);
            }
            None => {
                let address = self.address_from_pubkeyhash(vout.script_pubkey.address());
                if address.is_none() {
                    println!("Couldn't determine address for output!");
                }
                info!("Added to wallet {}:{}", txid, n);
                // Add the utxo     
                tx_entry.utxos.push(Utxo{
                    address: address.unwrap(),
                    txid: txid.clone(),
                    output_index: n,
                    script: vout.script_pubkey.0.clone(),
                    value: vout.value.into(),
                    height,
                    spent: None,
                    unconfirmed_spent: None,
                });
            }
        }
    }

    // Scan the full Tx and update memos for incoming shielded transactions
    pub fn scan_full_tx(&self, tx: &Transaction, height: i32) {
        // Scan all the inputs to see if we spent any transparent funds in this tx
        
        // TODO: Save this object
        let secp = secp256k1::Secp256k1::new();

        // TODO: Iterate over all transparent addresses. This is currently looking only at 
        // the first one.
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &self.tkeys[0]).serialize();

        let mut total_transparent_spend: u64 = 0;

        for vin in tx.vin.iter() {    
            // Find the txid in the list of utxos that we have.
            let txid = TxId {0: vin.prevout.hash};
            match self.txs.write().unwrap().get_mut(&txid) {
                Some(wtx) => {
                    //println!("Looking for {}, {}", txid, vin.prevout.n);

                    // One of the tx outputs is a match
                    let spent_utxo = wtx.utxos.iter_mut()
                        .find(|u| u.txid == txid && u.output_index == (vin.prevout.n as u64));

                    match spent_utxo {
                        Some(su) => {
                            info!("Spent utxo from {} was spent in {}", txid, tx.txid());
                            su.spent = Some(txid.clone());
                            su.unconfirmed_spent = None;

                            total_transparent_spend += su.value;
                        },
                        _ => {}
                    }
                },
                _ => {}
            };
        }

        if total_transparent_spend > 0 {
            // Update the WalletTx. Do it in a short scope because of the write lock.
            let mut txs = self.txs.write().unwrap();

            if !txs.contains_key(&tx.txid()) {
                let tx_entry = WalletTx::new(height, &tx.txid());
                txs.insert(tx.txid().clone(), tx_entry);
            }
            
            txs.get_mut(&tx.txid()).unwrap()
                .total_transparent_value_spent = total_transparent_spend;
        }

        // Scan for t outputs
        for (n, vout) in tx.vout.iter().enumerate() {
            match vout.script_pubkey.address() {
                Some(TransparentAddress::PublicKey(hash)) => {
                    if hash[..] == ripemd160::Ripemd160::digest(&Sha256::digest(&pubkey))[..] {
                        // This is out address. Add this as an output to the txid
                        self.add_toutput_to_wtx(height, &tx.txid(), &vout, n as u64);
                    }
                },
                _ => {}
            }
        }

        // Scan shielded sapling outputs to see if anyone of them is us, and if it is, extract the memo
        for output in tx.shielded_outputs.iter() {
            let ivks: Vec<_> = self.extfvks.iter().map(|extfvk| extfvk.fvk.vk.ivk()).collect();

            let cmu = output.cmu;
            let ct  = output.enc_ciphertext;

            // Search all of our keys
            for (_account, ivk) in ivks.iter().enumerate() {
                let epk_prime = output.ephemeral_key.as_prime_order(&JUBJUB).unwrap();

                let (note, _to, memo) = match try_sapling_note_decryption(ivk, &epk_prime, &cmu, &ct) {
                    Some(ret) => ret,
                    None => continue,
                };

                {
                    info!("A sapling note was spent in {}", tx.txid());
                    // Update the WalletTx 
                    // Do it in a short scope because of the write lock.
                    let mut txs = self.txs.write().unwrap();
                    txs.get_mut(&tx.txid()).unwrap()
                        .notes.iter_mut()
                        .find(|nd| nd.note == note).unwrap()
                        .memo = Some(memo);
                }
            }

            // Also scan the output to see if it can be decoded with our OutgoingViewKey
            // If it can, then we sent this transaction, so we should be able to get
            // the memo and value for our records

            // First, collect all our z addresses, to check for change
            // Collect z addresses
            let z_addresses = self.address.iter().map( |ad| {
                encode_payment_address(self.config.hrp_sapling_address(), &ad)
            }).collect::<HashSet<String>>();

            // Search all ovks that we have
            let ovks: Vec<_> = self.extfvks.iter().map(|extfvk| extfvk.fvk.ovk).collect();
            for (_account, ovk) in ovks.iter().enumerate() {
                match try_sapling_output_recovery(ovk,
                    &output.cv, 
                    &output.cmu, 
                    &output.ephemeral_key.as_prime_order(&JUBJUB).unwrap(), 
                    &output.enc_ciphertext,
                    &output.out_ciphertext) {
                        Some((note, payment_address, memo)) => {
                            let address = encode_payment_address(self.config.hrp_sapling_address(), 
                                            &payment_address);

                            // Check if this is a change address
                            if z_addresses.contains(&address) {
                                continue;
                            }

                            // Update the WalletTx 
                            info!("A sapling output was sent in {}", tx.txid());
                            {
                                // Do it in a short scope because of the write lock.
                                
                                let mut txs = self.txs.write().unwrap();
                                if txs.get(&tx.txid()).unwrap().outgoing_metadata.iter()
                                        .find(|om| om.address == address && om.value == note.value)
                                        .is_some() {
                                    warn!("Duplicate outgoing metadata");
                                    continue;
                                }
                                
                                // Write the outgoing metadata
                                txs.get_mut(&tx.txid()).unwrap()
                                    .outgoing_metadata
                                    .push(OutgoingTxMetadata{
                                        address, value: note.value, memo,
                                    });
                            }
                        },
                        None => {}
                };
                
            }
        }
    }

    // Invalidate all blocks including and after "at_height".
    // Returns the number of blocks invalidated
    pub fn invalidate_block(&self, at_height: i32) -> u64 {
        let mut num_invalidated = 0;

        // First remove the blocks
        { 
            let mut blks = self.blocks.write().unwrap();
            
            while blks.last().unwrap().height >= at_height {
                blks.pop();
                num_invalidated += 1;
            }
        }

        // Next, remove transactions
        {
            let mut txs = self.txs.write().unwrap();
            let txids_to_remove = txs.values()
                .filter_map(|wtx| if wtx.block >= at_height {Some(wtx.txid.clone())} else {None})
                .collect::<HashSet<TxId>>();

            for txid in &txids_to_remove {
                txs.remove(&txid);
            }

            // We also need to update any sapling note data and utxos in existing transactions that
            // were spent in any of the txids that were removed
            txs.values_mut()
                .for_each(|wtx| {
                    wtx.notes.iter_mut()
                        .for_each(|nd| {
                            if nd.spent.is_some() && txids_to_remove.contains(&nd.spent.unwrap()) {
                                nd.spent = None;
                            }

                            if nd.unconfirmed_spent.is_some() && txids_to_remove.contains(&nd.spent.unwrap()) {
                                nd.unconfirmed_spent = None;
                            }
                        })
                })
        }
        
        num_invalidated
    }

    // Scan a block. Will return an error with the block height that failed to scan
    pub fn scan_block(&self, block: &[u8]) -> Result<(), i32> {
        let block: CompactBlock = match parse_from_bytes(block) {
            Ok(block) => block,
            Err(e) => {
                eprintln!("Could not parse CompactBlock from bytes: {}", e);
                return Err(-1);
            }
        };

        // Scanned blocks MUST be height-sequential.
        let height = block.get_height() as i32;
        if height == self.last_scanned_height() {
            // If the last scanned block is rescanned, check it still matches.
            if let Some(hash) = self.blocks.read().unwrap().last().map(|block| block.hash) {
                if block.hash() != hash {
                    warn!("Likely reorg. Block hash does not match for block {}. {} vs {}", height, block.hash(), hash);
                    return Err(height);
                }
            }
            return Ok(())
        } else if height != (self.last_scanned_height() + 1) {
            error!(
                "Block is not height-sequential (expected {}, found {})",
                self.last_scanned_height() + 1,
                height
            );
            return Err(self.last_scanned_height());
        }

        // Check to see that the previous block hash matches
        if let Some(hash) = self.blocks.read().unwrap().last().map(|block| block.hash) {
            if block.prev_hash() != hash {
                warn!("Likely reorg. Prev block hash does not match for block {}. {} vs {}", height, block.prev_hash(), hash);
                return Err(height-1);
            }
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

        // Create a write lock that will last for the rest of the function.
        let mut txs = self.txs.write().unwrap();

        // Create a Vec containing all unspent nullifiers.
        // Include only the confirmed spent nullifiers, since unconfirmed ones still need to be included
        // during scan_block below.
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
            let mut total_shielded_value_spent: u64 = 0;

            info!("Txid {} belongs to wallet", tx.txid);

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
                
                // Mark the note as spent, and remove the unconfirmed part of it
                info!("Marked a note as spent");
                spent_note.spent = Some(tx.txid);
                spent_note.unconfirmed_spent = None::<TxId>;

                total_shielded_value_spent += spent_note.note.value;
            }

            // Find the existing transaction entry, or create a new one.
            if !txs.contains_key(&tx.txid) {
                let tx_entry = WalletTx::new(block_data.height as i32, &tx.txid);
                txs.insert(tx.txid, tx_entry);
            }
            let tx_entry = txs.get_mut(&tx.txid).unwrap();
            tx_entry.total_shielded_value_spent = total_shielded_value_spent;

            // Save notes.
            for output in tx
                .shielded_outputs
                .into_iter()
            {
                info!("Received sapling output");

                let new_note = SaplingNoteData::new(&self.extfvks[output.account], output);
                match tx_entry.notes.iter().find(|nd| nd.nullifier == new_note.nullifier) {
                    None => tx_entry.notes.push(new_note),
                    Some(_) => warn!("Tried to insert duplicate note for Tx {}", tx.txid)
                };                
            }
        }

        {
            let mut blks = self.blocks.write().unwrap();
            
            // Store scanned data for this block.
            blks.push(block_data);

            // Trim the old blocks, keeping only as many as needed for a worst-case reorg (i.e. 101 blocks)
            let len = blks.len();
            if len > MAX_REORG + 1 {
                blks.drain(..(len-MAX_REORG+1));
            }
        }
        
        // Print info about the block every 10,000 blocks
        if height % 10_000 == 0 {
            match self.get_sapling_tree() {
                Ok((h, hash, stree)) => info!("Sapling tree at height {}/{} - {}", h, hash, stree),
                Err(e) => error!("Couldn't determine sapling tree: {}", e)
            }
        }

        Ok(())
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

        // TODO: This only spends from the first address right now.
        let extsk = &self.extsks[0];
        let extfvk = &self.extfvks[0];
        let ovk = extfvk.fvk.ovk;

        let to = match address::RecipientAddress::from_str(to, 
                        self.config.hrp_sapling_address(), 
                        self.config.base58_pubkey_address(), 
                        self.config.base58_script_address()) {
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
        let notes: Vec<_> = self.txs.read().unwrap().iter()
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

        let mut builder = Builder::new(height);

        // A note on t addresses
        // Funds recieved by t-addresses can't be explicitly spent in ZecWallet. 
        // ZecWallet will lazily consolidate all t address funds into your shielded addresses. 
        // Specifically, if you send an outgoing transaction that is sent to a shielded address,
        // ZecWallet will add all your t-address funds into that transaction, and send them to your shielded
        // address as change.
        let tinputs = self.get_utxos().iter()
            .filter(|utxo| utxo.unconfirmed_spent.is_none()) // Remove any unconfirmed spends
            .map(|utxo| utxo.clone())
            .collect::<Vec<Utxo>>();

        if let Err(e) = match to {
            address::RecipientAddress::Shielded(_) => {
                // The destination is a sapling address, so add all transparent inputs
                // TODO: This only spends from the first address right now.
                let sk = self.tkeys[0];

                // Add all tinputs
                tinputs.iter()
                    .map(|utxo| {
                        let outpoint: OutPoint = utxo.to_outpoint();
                
                        let coin = TxOut {
                            value: Amount::from_u64(utxo.value).unwrap(),
                            script_pubkey: Script { 0: utxo.script.clone() },
                        };

                        builder.add_transparent_input(sk, outpoint.clone(), coin.clone())
                    })
                    .collect::<Result<Vec<_>, _>>()
            },            
            _ => Ok(vec![])
        } { 
            eprintln!("Error adding transparent inputs: {:?}", e);
            return None;
        }

        // Confirm we were able to select sufficient value
        let selected_value = notes.iter().map(|selected| selected.note.value).sum::<u64>() 
                             + tinputs.iter().map::<u64, _>(|utxo| utxo.value.into()).sum::<u64>();

        if selected_value < u64::from(target_value) {
            eprintln!(
                "Insufficient funds (have {}, need {:?})",
                selected_value, target_value
            );
            return None;
        }

        // Create the transaction
        println!("{}: Adding {} notes and {} utxos", now() - start_time, notes.len(), tinputs.len());

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
        {
            // Mark sapling notes as unconfirmed spent
            let mut txs = self.txs.write().unwrap();
            for selected in notes {
                let mut spent_note = txs.get_mut(&selected.txid).unwrap()
                                        .notes.iter_mut()
                                        .find(|nd| &nd.nullifier[..] == &selected.nullifier[..])
                                        .unwrap();
                spent_note.unconfirmed_spent = Some(tx.txid());
            }

            // Mark this utxo as unconfirmed spent
            for utxo in tinputs {
                let mut spent_utxo = txs.get_mut(&utxo.txid).unwrap().utxos.iter_mut()
                                        .find(|u| utxo.txid == u.txid && utxo.output_index == u.output_index)
                                        .unwrap();
                spent_utxo.unconfirmed_spent = Some(tx.txid());
            }
        }

        // Return the encoded transaction, so the caller can send it.
        let mut raw_tx = vec![];
        tx.write(&mut raw_tx).unwrap();
        Some(raw_tx.into_boxed_slice())
    }
}



#[cfg(test)]
pub mod tests {
    use std::convert::TryInto;
    use ff::{Field, PrimeField, PrimeFieldRepr};
    use pairing::bls12_381::Bls12;
    use rand_core::{RngCore, OsRng};
    use protobuf::Message;
    use zcash_client_backend::{encoding::encode_payment_address,
        proto::compact_formats::{
            CompactBlock, CompactOutput, CompactSpend, CompactTx,
        }
    };
    use zcash_primitives::{
        block::BlockHash,
        jubjub::fs::Fs,
        note_encryption::{Memo, SaplingNoteEncryption},
        primitives::{Note, PaymentAddress},
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
        JUBJUB,
    };

    use crate::lightwallet::LightWallet;
    use crate::LightClientConfig;

    /// Create a fake CompactBlock at the given height, containing a single output paying
    /// the given address. Returns the CompactBlock and the nullifier for the new note.
    pub(crate) fn fake_compact_block(
        height: i32,
        prev_hash: BlockHash,
        extfvk: ExtendedFullViewingKey,
        value: Amount,
    ) -> (CompactBlock, Vec<u8>) {
        let to = extfvk.default_address().unwrap().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let note = Note {
            g_d: to.diversifier.g_d::<Bls12>(&JUBJUB).unwrap(),
            pk_d: to.pk_d.clone(),
            value: value.into(),
            r: Fs::random(&mut rng),
        };
        let encryptor = SaplingNoteEncryption::new(
            extfvk.fvk.ovk,
            note.clone(),
            to.clone(),
            Memo::default(),
            &mut rng,
        );
        let mut cmu = vec![];
        note.cm(&JUBJUB).into_repr().write_le(&mut cmu).unwrap();
        let mut epk = vec![];
        encryptor.epk().write(&mut epk).unwrap();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cout = CompactOutput::new();
        cout.set_cmu(cmu);
        cout.set_epk(epk);
        cout.set_ciphertext(enc_ciphertext[..52].to_vec());
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.outputs.push(cout);
        let mut cb = CompactBlock::new();
        cb.set_height(height as u64);
        cb.hash.resize(32, 0);
        rng.fill_bytes(&mut cb.hash);
        cb.prevHash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        (cb, note.nf(&extfvk.fvk.vk, 0, &JUBJUB))
    }

    /// Create a fake CompactBlock at the given height, spending a single note from the
    /// given address.
    pub(crate) fn fake_compact_block_spending(
        height: i32,
        prev_hash: BlockHash,
        (nf, in_value): (Vec<u8>, Amount),
        extfvk: ExtendedFullViewingKey,
        to: PaymentAddress<Bls12>,
        value: Amount,
    ) -> CompactBlock {
        let mut rng = OsRng;

        // Create a fake CompactBlock containing the note
        let mut cspend = CompactSpend::new();
        cspend.set_nf(nf);
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.spends.push(cspend);

        // Create a fake Note for the payment
        ctx.outputs.push({
            let note = Note {
                g_d: to.diversifier.g_d::<Bls12>(&JUBJUB).unwrap(),
                pk_d: to.pk_d.clone(),
                value: value.into(),
                r: Fs::random(&mut rng),
            };
            let encryptor = SaplingNoteEncryption::new(
                extfvk.fvk.ovk,
                note.clone(),
                to,
                Memo::default(),
                &mut rng,
            );
            let mut cmu = vec![];
            note.cm(&JUBJUB).into_repr().write_le(&mut cmu).unwrap();
            let mut epk = vec![];
            encryptor.epk().write(&mut epk).unwrap();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let mut cout = CompactOutput::new();
            cout.set_cmu(cmu);
            cout.set_epk(epk);
            cout.set_ciphertext(enc_ciphertext[..52].to_vec());
            cout
        });

        // Create a fake Note for the change
        ctx.outputs.push({
            let change_addr = extfvk.default_address().unwrap().1;
            let note = Note {
                g_d: change_addr.diversifier.g_d::<Bls12>(&JUBJUB).unwrap(),
                pk_d: change_addr.pk_d.clone(),
                value: (in_value - value).into(),
                r: Fs::random(&mut rng),
            };
            let encryptor = SaplingNoteEncryption::new(
                extfvk.fvk.ovk,
                note.clone(),
                change_addr,
                Memo::default(),
                &mut rng,
            );
            let mut cmu = vec![];
            note.cm(&JUBJUB).into_repr().write_le(&mut cmu).unwrap();
            let mut epk = vec![];
            encryptor.epk().write(&mut epk).unwrap();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let mut cout = CompactOutput::new();
            cout.set_cmu(cmu);
            cout.set_epk(epk);
            cout.set_ciphertext(enc_ciphertext[..52].to_vec());
            cout
        });

        let mut cb = CompactBlock::new();
        cb.set_height(height as u64);
        cb.hash.resize(32, 0);
        rng.fill_bytes(&mut cb.hash);
        cb.prevHash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        cb
    }

    #[test]
    fn z_balances() {
        let wallet = LightWallet::new(None, &LightClientConfig {
            server: "0.0.0.0:0".to_string(),
            chain_name: "test".to_string(),
            sapling_activation_height: 0
        }).unwrap();

        const AMOUNT1:u64 = 5;
        // Address is encoded in bech32
        let address = Some(encode_payment_address(wallet.config.hrp_sapling_address(), 
                                            &wallet.extfvks[0].default_address().unwrap().1));

        let (cb1, _) = fake_compact_block(
            0,
            BlockHash([0; 32]),
            wallet.extfvks[0].clone(),
            Amount::from_u64(AMOUNT1).unwrap(),
        );
        

        // Make sure that the intial state is empty
        assert_eq!(wallet.txs.read().unwrap().len(), 0);
        assert_eq!(wallet.blocks.read().unwrap().len(), 0);
        assert_eq!(wallet.zbalance(None), 0);
        assert_eq!(wallet.zbalance(address.clone()), 0);

        wallet.scan_block(&cb1.write_to_bytes().unwrap()).unwrap();
        
        assert_eq!(wallet.txs.read().unwrap().len(), 1);
        assert_eq!(wallet.blocks.read().unwrap().len(), 1);
        assert_eq!(wallet.zbalance(None), AMOUNT1);
        assert_eq!(wallet.zbalance(address.clone()), AMOUNT1);

        const AMOUNT2:u64 = 10;

        // Add a second block
        let (cb2, _) = fake_compact_block(
            1,  // Block number 1
            BlockHash{0: cb1.hash[..].try_into().unwrap()},
            wallet.extfvks[0].clone(),
            Amount::from_u64(AMOUNT2).unwrap(),
        );

        wallet.scan_block(&cb2.write_to_bytes().unwrap()).unwrap();
        
        assert_eq!(wallet.txs.read().unwrap().len(), 2);
        assert_eq!(wallet.blocks.read().unwrap().len(), 2);
        assert_eq!(wallet.zbalance(None), AMOUNT1 + AMOUNT2);
        assert_eq!(wallet.zbalance(address.clone()), AMOUNT1 + AMOUNT2);
    }
}