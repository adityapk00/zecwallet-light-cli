use std::time::SystemTime;
use std::io::{self, Read, Write};
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::io::{Error, ErrorKind};

use log::{info, warn, error};

use protobuf::parse_from_bytes;

use secp256k1::SecretKey;
use bip39::{Mnemonic, Language};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use pairing::bls12_381::{Bls12};
use sha2::{Sha256, Digest};

use zcash_client_backend::{
    encoding::{encode_payment_address, encode_extended_spending_key},
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


use crate::{LightClientConfig};

mod data;
mod extended_key;
mod utils;
mod address;
mod prover;

use data::{BlockData, WalletTx, Utxo, SaplingNoteData, SpendableNote, OutgoingTxMetadata};
use extended_key::{KeyIndex, ExtendedPrivKey};

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

use base58::{ToBase58};

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
//
//pub trait FromBase58Check {
//    fn from_base58check(&self, version: &[u8], suffix: &[u8]) -> Vec<u8>;
//}
//
//
//impl FromBase58Check for str {
//    fn from_base58check(&self, version: &[u8], suffix: &[u8]) -> Vec<u8> {
//        let mut payload: Vec<u8> = Vec::new();
//        let bytes = self.from_base58().unwrap();
//
//        let start = version.len();
//        let end = bytes.len() - (4 + suffix.len());
//
//        payload.extend(&bytes[start..end]);
//
//        payload
//    }
//}


pub struct LightWallet {
    seed: [u8; 32], // Seed phrase for this wallet. 

    // List of keys, actually in this wallet. This may include more
    // than keys derived from the seed, for example, if user imports 
    // a private key
    extsks:  Arc<RwLock<Vec<ExtendedSpendingKey>>>,
    extfvks: Arc<RwLock<Vec<ExtendedFullViewingKey>>>,
    pub address: Arc<RwLock<Vec<PaymentAddress<Bls12>>>>,
    
    // Transparent keys. TODO: Make it not pubic
    pub tkeys: Arc<RwLock<Vec<secp256k1::SecretKey>>>,

    blocks: Arc<RwLock<Vec<BlockData>>>,
    pub txs: Arc<RwLock<HashMap<TxId, WalletTx>>>,

    // The block at which this wallet was born. Rescans
    // will start from here.
    birthday: u64,

    // Non-serialized fields
    config: LightClientConfig,
}

impl LightWallet {
    pub fn serialized_version() -> u64 {
        return 3;
    }

    fn get_taddr_from_bip39seed(config: &LightClientConfig, bip39_seed: &[u8], pos: u32) -> SecretKey {
        let ext_t_key = ExtendedPrivKey::with_seed(bip39_seed).unwrap();
        ext_t_key
            .derive_private_key(KeyIndex::hardened_from_normalize_index(44).unwrap()).unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(config.get_coin_type()).unwrap()).unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(0).unwrap()).unwrap()
            .derive_private_key(KeyIndex::Normal(0)).unwrap()
            .derive_private_key(KeyIndex::Normal(pos)).unwrap()
            .private_key
    }


    fn get_zaddr_from_bip39seed(config: &LightClientConfig, bip39seed: &[u8], pos: u32) ->
            (ExtendedSpendingKey, ExtendedFullViewingKey, PaymentAddress<Bls12>) {
        let extsk: ExtendedSpendingKey = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(bip39seed),
            &[
                ChildIndex::Hardened(32),
                ChildIndex::Hardened(config.get_coin_type()),
                ChildIndex::Hardened(pos)
            ],
        );
        let extfvk  = ExtendedFullViewingKey::from(&extsk);
        let address = extfvk.default_address().unwrap().1;

        (extsk, extfvk, address)
    }

    pub fn new(seed_phrase: Option<String>, config: &LightClientConfig, latest_block: u64) -> io::Result<Self> {
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

        // Derive only the first address
        let tpk = LightWallet::get_taddr_from_bip39seed(&config, &bip39_seed.as_bytes(), 0);

        // TODO: We need to monitor addresses, and always keep 1 "free" address, so 
        // users can import a seed phrase and automatically get all used addresses
        let (extsk, extfvk, address)
            = LightWallet::get_zaddr_from_bip39seed(&config, &bip39_seed.as_bytes(), 0);

        Ok(LightWallet {
            seed:     seed_bytes,
            extsks:   Arc::new(RwLock::new(vec![extsk])),
            extfvks:  Arc::new(RwLock::new(vec![extfvk])),
            address:  Arc::new(RwLock::new(vec![address])),
            tkeys:    Arc::new(RwLock::new(vec![tpk])),
            blocks:   Arc::new(RwLock::new(vec![])),
            txs:      Arc::new(RwLock::new(HashMap::new())),
            config:   config.clone(),
            birthday: latest_block,
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

        let tkeys = Vector::read(&mut reader, |r| {
            let mut tpk_bytes = [0u8; 32];
            r.read_exact(&mut tpk_bytes)?;
            secp256k1::SecretKey::from_slice(&tpk_bytes).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
        })?;      

        let blocks = Vector::read(&mut reader, |r| BlockData::read(r))?;

        let txs_tuples = Vector::read(&mut reader, |r| {
            let mut txid_bytes = [0u8; 32];
            r.read_exact(&mut txid_bytes)?;

            Ok((TxId{0: txid_bytes}, WalletTx::read(r).unwrap()))
        })?;
        let txs = txs_tuples.into_iter().collect::<HashMap<TxId, WalletTx>>();

        let chain_name = utils::read_string(&mut reader)?;

        if chain_name != config.chain_name {
            return Err(Error::new(ErrorKind::InvalidData,
                                    format!("Wallet chain name {} doesn't match expected {}", chain_name, config.chain_name)));
        }

        let birthday = reader.read_u64::<LittleEndian>()?;

        Ok(LightWallet{
            seed:    seed_bytes,
            extsks:  Arc::new(RwLock::new(extsks)),
            extfvks: Arc::new(RwLock::new(extfvks)),
            address: Arc::new(RwLock::new(addresses)),
            tkeys:   Arc::new(RwLock::new(tkeys)),
            blocks:  Arc::new(RwLock::new(blocks)),
            txs:     Arc::new(RwLock::new(txs)),
            config:  config.clone(),
            birthday,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write the version
        writer.write_u64::<LittleEndian>(LightWallet::serialized_version())?;

        // Write the seed
        writer.write_all(&self.seed)?;

        // Write all the spending keys
        Vector::write(&mut writer, &self.extsks.read().unwrap(),
             |w, sk| sk.write(w)
        )?;

        // Write the transparent private key
        Vector::write(&mut writer, &self.tkeys.read().unwrap(),
            |w, pk| w.write_all(&pk[..])
        )?;

        Vector::write(&mut writer, &self.blocks.read().unwrap(), |w, b| b.write(w))?;
                
        // The hashmap, write as a set of tuples
        Vector::write(&mut writer, &self.txs.read().unwrap().iter().collect::<Vec<(&TxId, &WalletTx)>>(),
                        |w, (k, v)| {
                            w.write_all(&k.0)?;
                            v.write(w)
                        })?;
        utils::write_string(&mut writer, &self.config.chain_name)?;

        // While writing the birthday, be sure that we're right, and that we don't
        // have a tx that is before the current birthday
        writer.write_u64::<LittleEndian>(self.get_birthday())?;

        Ok(())
    }

    pub fn note_address(&self, note: &SaplingNoteData) -> Option<String> {
        match note.extfvk.fvk.vk.into_payment_address(note.diversifier, &JUBJUB) {
            Some(pa) => Some(encode_payment_address(self.config.hrp_sapling_address(), &pa)),
            None     => None
        }
    }

    pub fn get_birthday(&self) -> u64 {
        cmp::min(self.get_first_tx_block(), self.birthday)
    }

    // Get the first block that this wallet has a tx in. This is often used as the wallet's "birthday"
    // If there are no Txns, then the actual birthday (which is recorder at wallet creation) is returned
    // If no birthday was recorded, return the sapling activation height
    pub fn get_first_tx_block(&self) -> u64 {
        // Find the first transaction
        let mut blocks = self.txs.read().unwrap().values()
            .map(|wtx| wtx.block as u64)
            .collect::<Vec<u64>>();
        blocks.sort();

        *blocks.first() // Returns optional
            .unwrap_or(&cmp::max(self.birthday, self.config.sapling_activation_height))
    }

    // Get all z-address private keys. Returns a Vector of (address, privatekey)
    pub fn get_z_private_keys(&self) -> Vec<(String, String)> {
        self.extsks.read().unwrap().iter().map(|sk| {
            (encode_payment_address(self.config.hrp_sapling_address(),
                                    &ExtendedFullViewingKey::from(sk).default_address().unwrap().1),
             encode_extended_spending_key(self.config.hrp_sapling_private_key(), &sk)
            )
        }).collect::<Vec<(String, String)>>()
    }

    /// Get all t-address private keys. Returns a Vector of (address, secretkey)
    pub fn get_t_secret_keys(&self) -> Vec<(String, String)> {
        self.tkeys.read().unwrap().iter().map(|sk| {
            (self.address_from_sk(sk), sk[..].to_base58check(&self.config.base58_secretkey_prefix(), &[0x01]))
        }).collect::<Vec<(String, String)>>()
    }

    /// Adds a new z address to the wallet. This will derive a new address from the seed
    /// at the next position and add it to the wallet.
    /// NOTE: This does NOT rescan
    pub fn add_zaddr(&self) -> String {
        let pos = self.extsks.read().unwrap().len() as u32;
        let (extsk, extfvk, address) =
            LightWallet::get_zaddr_from_bip39seed(&self.config, &self.seed, pos);

        let zaddr = encode_payment_address(self.config.hrp_sapling_address(), &address);
        self.extsks.write().unwrap().push(extsk);
        self.extfvks.write().unwrap().push(extfvk);
        self.address.write().unwrap().push(address);

        zaddr
    }

    /// Add a new t address to the wallet. This will derive a new address from the seed
    /// at the next position.
    /// NOTE: This is not rescan the wallet
    pub fn add_taddr(&self) -> String {
        let pos = self.tkeys.read().unwrap().len() as u32;
        let sk = LightWallet::get_taddr_from_bip39seed(&self.config, &self.seed, pos);

        self.tkeys.write().unwrap().push(sk);

        self.address_from_sk(&sk)
    }

    /// Clears all the downloaded blocks and resets the state back to the initial block.
    /// After this, the wallet's initial state will need to be set
    /// and the wallet will need to be rescanned
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
                    cmp::max(target_height.saturating_sub(self.config.anchor_offset), min_height);

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
            Some(TransparentAddress::Script(hash)) => {
                Some(hash.to_base58check(&self.config.base58_script_address(), &[]))
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
                    error!("Couldn't determine address for output!");
                } else {
                    info!("Added to wallet {}:{}", txid, n);
                    // Add the utxo
                    tx_entry.utxos.push(Utxo {
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
    }

    // Scan the full Tx and update memos for incoming shielded transactions
    pub fn scan_full_tx(&self, tx: &Transaction, height: i32) {
        // Scan all the inputs to see if we spent any transparent funds in this tx
        
        // TODO: Save this object
        let secp = secp256k1::Secp256k1::new();

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
                            su.spent = Some(tx.txid().clone());
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

        // TODO: Iterate over all transparent addresses. This is currently looking only at
        // the first one.
        // Scan for t outputs
        let all_pubkeys = self.tkeys.read().unwrap().iter()
                                .map(|sk| 
                                    secp256k1::PublicKey::from_secret_key(&secp, sk).serialize()
                                )
                                .collect::<Vec<[u8; secp256k1::constants::PUBLIC_KEY_SIZE]>>();
        for pubkey in all_pubkeys {
            for (n, vout) in tx.vout.iter().enumerate() {
                match vout.script_pubkey.address() {
                    Some(TransparentAddress::PublicKey(hash)) => {
                        if hash[..] == ripemd160::Ripemd160::digest(&Sha256::digest(&pubkey))[..] {
                            // This is our address. Add this as an output to the txid
                            self.add_toutput_to_wtx(height, &tx.txid(), &vout, n as u64);
                        }
                    },
                    _ => {}
                }
            }
        }

        {
            let total_shielded_value_spent = self.txs.read().unwrap().get(&tx.txid()).map_or(0, |wtx| wtx.total_shielded_value_spent);
            if total_transparent_spend + total_shielded_value_spent > 0 {
                // We spent money in this Tx, so grab all the transparent outputs (except ours) and add them to the
                // outgoing metadata

                // Collect our t-addresses
                let wallet_taddrs = self.tkeys.read().unwrap().iter()
                        .map(|sk| self.address_from_sk(sk))
                        .collect::<HashSet<String>>();

                for vout in tx.vout.iter() {
                    let taddr = self.address_from_pubkeyhash(vout.script_pubkey.address());

                    if taddr.is_some() && !wallet_taddrs.contains(&taddr.clone().unwrap()) {
                        let taddr = taddr.unwrap();

                        // Add it to outgoing metadata
                        let mut txs = self.txs.write().unwrap();
                        if txs.get(&tx.txid()).unwrap().outgoing_metadata.iter()
                            .find(|om|
                                om.address == taddr && Amount::from_u64(om.value).unwrap() == vout.value)
                            .is_some() {
                            warn!("Duplicate outgoing metadata");
                            continue;
                        }

                        // Write the outgoing metadata
                        txs.get_mut(&tx.txid()).unwrap()
                            .outgoing_metadata
                            .push(OutgoingTxMetadata{
                                address: taddr,
                                value: vout.value.into(),
                                memo: Memo::default(),
                            });
                    }
                }
            }
        }

        // Scan shielded sapling outputs to see if anyone of them is us, and if it is, extract the memo
        for output in tx.shielded_outputs.iter() {
            let ivks: Vec<_> = self.extfvks.read().unwrap().iter().map(
                |extfvk| extfvk.fvk.vk.ivk().clone()
            ).collect();

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
            let z_addresses = self.address.read().unwrap().iter().map( |ad| {
                encode_payment_address(self.config.hrp_sapling_address(), &ad)
            }).collect::<HashSet<String>>();

            // Search all ovks that we have
            let ovks: Vec<_> = self.extfvks.read().unwrap().iter().map(
                |extfvk| extfvk.fvk.ovk.clone()
            ).collect();

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
                            // Do it in a short scope because of the write lock.
                            {
                                info!("A sapling output was sent in {}", tx.txid());

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

        // Mark this Tx as scanned
        {
            let mut txs = self.txs.write().unwrap();
            let mut wtx =  txs.get_mut(&tx.txid()).unwrap();
            wtx.full_tx_scanned = true;
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
                error!("Could not parse CompactBlock from bytes: {}", e);
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
                &self.extfvks.read().unwrap(),
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

                let new_note = SaplingNoteData::new(&self.extfvks.read().unwrap()[output.account], output);
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
                let drain_first = len - (MAX_REORG+1);
                blks.drain(..drain_first);
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
            .filter_map(|(txid, note)|
                SpendableNote::from(txid, note, anchor_offset, &self.extsks.read().unwrap()[note.account])
            )
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
        // Funds received by t-addresses can't be explicitly spent in ZecWallet. 
        // ZecWallet will lazily consolidate all t address funds into your shielded addresses. 
        // Specifically, if you send an outgoing transaction that is sent to a shielded address,
        // ZecWallet will add all your t-address funds into that transaction, and send them to your shielded
        // address as change.
        let mut tinputs = vec![];
        
        if let Err(e) = match to {
            address::RecipientAddress::Shielded(_) => {
                // The destination is a sapling address, so add all transparent inputs
                tinputs.extend(self.get_utxos().iter()
                                .filter(|utxo| utxo.unconfirmed_spent.is_none()) // Remove any unconfirmed spends
                                .map(|utxo| utxo.clone()));
                
                // Create a map from address -> sk for all taddrs, so we can spend from the 
                // right address
                let address_to_sk: HashMap<_, _> = self.tkeys.read().unwrap().iter().map(|sk|
                                                        (self.address_from_sk(&sk), sk.clone())
                                                    ).collect();

                // Add all tinputs
                tinputs.iter()
                    .map(|utxo| {
                        let outpoint: OutPoint = utxo.to_outpoint();
                
                        let coin = TxOut {
                            value: Amount::from_u64(utxo.value).unwrap(),
                            script_pubkey: Script { 0: utxo.script.clone() },
                        };

                        match address_to_sk.get(&utxo.address) {
                            Some(sk) => builder.add_transparent_input(*sk, outpoint.clone(), coin.clone()),
                            None     => {
                                // Something is very wrong
                                let e = format!("Couldn't find the secreykey for taddr {}", utxo.address);
                                error!("{}", e);
                                eprintln!("{}", e);

                                Err(zcash_primitives::transaction::builder::Error::InvalidAddress)
                            }
                        }
                        
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
                "Insufficient verified funds (have {}, need {:?}).\n Note, funds need {} confirmations before they can be spent",
                selected_value, target_value, self.config.anchor_offset
            );
            return None;
        }

        // Create the transaction
        println!("{}: Adding {} notes and {} utxos", now() - start_time, notes.len(), tinputs.len());

        for selected in notes.iter() {
            if let Err(e) = builder.add_sapling_spend(
                selected.extsk.clone(),
                selected.diversifier,
                selected.note.clone(),
                selected.witness.clone(),
            ) {
                eprintln!("Error adding note: {:?}", e);
                return None;
            }
        }

        // If no Sapling notes were added, add the change address manually. That is,
        // send the change to our sapling address manually. Note that if a sapling note was spent,
        // the builder will automatically send change to that address
        if notes.len() == 0 {
            builder.send_change_to(
                ExtendedFullViewingKey::from(&self.extsks.read().unwrap()[0]).fvk.ovk,
                self.extsks.read().unwrap()[0].default_address().unwrap().1);
        }

        // Compute memo if it exists
        let encoded_memo = memo.map(|s| Memo::from_str(&s).unwrap() );

        println!("{}: Adding output", now() - start_time);

        // TODO: We're using the first ovk to encrypt outgoing Txns. Is that Ok?
        let ovk = self.extfvks.read().unwrap()[0].fvk.ovk;

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
    use std::io::{Error};
    use ff::{Field, PrimeField, PrimeFieldRepr};
    use pairing::bls12_381::Bls12;
    use rand_core::{RngCore, OsRng};
    use protobuf::{Message, UnknownFields, CachedSize, RepeatedField};
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
        legacy::{Script, TransparentAddress,},
        transaction::{
            TxId, Transaction, TransactionData,
            components::{TxOut, TxIn, OutPoint, Amount,},
            components::amount::DEFAULT_FEE,
        },
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
        JUBJUB,
    };

    use sha2::{Sha256, Digest};

    use super::LightWallet;
    use crate::LightClientConfig;
    use secp256k1::{Secp256k1, key::PublicKey, key::SecretKey};
    use crate::SaplingParams;

    fn get_sapling_params() -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Read Sapling Params
        let mut sapling_output = vec![];
        sapling_output.extend_from_slice(SaplingParams::get("sapling-output.params").unwrap().as_ref());
        println!("Read output {}", sapling_output.len());

        let mut sapling_spend = vec![];
        sapling_spend.extend_from_slice(SaplingParams::get("sapling-spend.params").unwrap().as_ref());
        println!("Read output {}", sapling_spend.len());

        Ok((sapling_spend, sapling_output))
    }

    struct FakeCompactBlock {
        block: CompactBlock,
    }

    impl FakeCompactBlock {
        fn new(height: i32, prev_hash: BlockHash) -> Self {
            // Create a fake Note for the account
            let mut rng = OsRng;
            
            let mut cb = CompactBlock::new();

            cb.set_height(height as u64);
            cb.hash.resize(32, 0);
            rng.fill_bytes(&mut cb.hash);

            cb.prevHash.extend_from_slice(&prev_hash.0);
            
            FakeCompactBlock { block: cb }
        }

        fn as_bytes(&self) -> Vec<u8> {
            self.block.write_to_bytes().unwrap()
        }

        fn hash(&self) -> BlockHash {
            BlockHash(self.block.hash[..].try_into().unwrap())
        }

        fn tx_to_compact_tx(tx: &Transaction, index: u64) -> CompactTx {
            let spends = tx.shielded_spends.iter().map(|s| {
                let mut c_spend = CompactSpend::default();
                c_spend.set_nf(s.nullifier.to_vec());

                c_spend
            }).collect::<Vec<CompactSpend>>();

            let outputs = tx.shielded_outputs.iter().map(|o| {
                let mut c_out = CompactOutput::default();

                let mut cmu_bytes = vec![];
                o.cmu.into_repr().write_le(&mut cmu_bytes).unwrap();

                let mut epk_bytes = vec![];
                o.ephemeral_key.write(&mut epk_bytes).unwrap();

                c_out.set_cmu(cmu_bytes);
                c_out.set_epk(epk_bytes);
                c_out.set_ciphertext(o.enc_ciphertext[0..52].to_vec());

                c_out
            }).collect::<Vec<CompactOutput>>();

            CompactTx {
                index,
                hash: tx.txid().0.to_vec(),
                fee: 0, // TODO: Get Fee
                spends: RepeatedField::from_vec(spends),
                outputs: RepeatedField::from_vec(outputs),
                unknown_fields: UnknownFields::default(),
                cached_size: CachedSize::default(),
            }
        }

        // Convert the transaction into a CompactTx and add it to this block
        fn add_tx(&mut self, tx: &Transaction) {
            let ctx = FakeCompactBlock::tx_to_compact_tx(&tx, self.block.vtx.len() as u64);
            self.block.vtx.push(ctx);
        }

        // Add a new tx into the block, paying the given address the amount. 
        // Returns the nullifier of the new note.
        fn add_tx_paying(&mut self, extfvk: ExtendedFullViewingKey, value: u64) 
                -> (Vec<u8>, TxId) {
            let to = extfvk.default_address().unwrap().1;
            let value = Amount::from_u64(value).unwrap();

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
            ctx.set_hash(txid.clone());
            ctx.outputs.push(cout);
            
            self.block.vtx.push(ctx);
            (note.nf(&extfvk.fvk.vk, 0, &JUBJUB), TxId(txid[..].try_into().unwrap()))
        }

        fn add_tx_spending(&mut self, 
                            (nf, in_value): (Vec<u8>, u64),
                            extfvk: ExtendedFullViewingKey,
                            to: PaymentAddress<Bls12>,
                            value: u64) -> TxId {
            let mut rng = OsRng;

            let in_value = Amount::from_u64(in_value).unwrap();
            let value = Amount::from_u64(value).unwrap();

            // Create a fake CompactBlock containing the note
            let mut cspend = CompactSpend::new();
            cspend.set_nf(nf);
            let mut ctx = CompactTx::new();
            let mut txid = vec![0; 32];
            rng.fill_bytes(&mut txid);
            ctx.set_hash(txid.clone());
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
            
            self.block.vtx.push(ctx);         

            TxId(txid[..].try_into().unwrap())
        }
    }

    struct FakeTransaction {
        tx: Transaction,
    }

    impl FakeTransaction {
        // New FakeTransaction with random txid
        fn new<R: RngCore>(rng: &mut R) -> Self {
            let mut txid = [0u8; 32];
            rng.fill_bytes(&mut txid);
            FakeTransaction::new_with_txid(TxId(txid))
        }

        fn new_with_txid(txid: TxId) -> Self {
            FakeTransaction {
                tx: Transaction {
                    txid,
                    data: TransactionData::new()
                }
            }
        }

        fn get_tx(&self) -> &Transaction {
            &self.tx
        }

        fn add_t_output(&mut self, pk: &PublicKey, value: u64) {
            let mut hash160 = ripemd160::Ripemd160::new();
            hash160.input(Sha256::digest(&pk.serialize()[..].to_vec()));

            let taddr_bytes = hash160.result();

            self.tx.data.vout.push(TxOut {
                value: Amount::from_u64(value).unwrap(),
                script_pubkey: TransparentAddress::PublicKey(taddr_bytes.try_into().unwrap()).script(),
            });
        }

        fn add_t_input(&mut self, txid: TxId, n: u32) {
            self.tx.data.vin.push(TxIn {
                prevout: OutPoint{
                    hash: txid.0,
                    n
                },
                script_sig: Script{0: vec![]},
                sequence: 0,
            });
        }
    }

    #[test]
    fn test_z_balances() {
        let wallet = LightWallet::new(None, &get_test_config(), 0).unwrap();

        const AMOUNT1:u64 = 5;
        // Address is encoded in bech32
        let address = Some(encode_payment_address(wallet.config.hrp_sapling_address(), 
                                            &wallet.extfvks.read().unwrap()[0].default_address().unwrap().1));

        let mut cb1 = FakeCompactBlock::new(0, BlockHash([0; 32]));
        cb1.add_tx_paying(wallet.extfvks.read().unwrap()[0].clone(), AMOUNT1);
        
        // Make sure that the intial state is empty
        assert_eq!(wallet.txs.read().unwrap().len(), 0);
        assert_eq!(wallet.blocks.read().unwrap().len(), 0);
        assert_eq!(wallet.zbalance(None), 0);
        assert_eq!(wallet.zbalance(address.clone()), 0);

        wallet.scan_block(&cb1.as_bytes()).unwrap();
        
        assert_eq!(wallet.txs.read().unwrap().len(), 1);
        assert_eq!(wallet.blocks.read().unwrap().len(), 1);
        assert_eq!(wallet.zbalance(None), AMOUNT1);
        assert_eq!(wallet.zbalance(address.clone()), AMOUNT1);

        const AMOUNT2:u64 = 10;

        // Add a second block
        let mut cb2 = FakeCompactBlock::new(1, cb1.hash());
        cb2.add_tx_paying(wallet.extfvks.read().unwrap()[0].clone(), AMOUNT2);

        wallet.scan_block(&cb2.as_bytes()).unwrap();
        
        assert_eq!(wallet.txs.read().unwrap().len(), 2);
        assert_eq!(wallet.blocks.read().unwrap().len(), 2);
        assert_eq!(wallet.zbalance(None), AMOUNT1 + AMOUNT2);
        assert_eq!(wallet.zbalance(address.clone()), AMOUNT1 + AMOUNT2);
    }

    #[test]
    fn test_z_change_balances() {
        let wallet = LightWallet::new(None, &get_test_config(), 0).unwrap();

        // First, add an incoming transaction
        const AMOUNT1:u64 = 5;

        let mut cb1 = FakeCompactBlock::new(0, BlockHash([0; 32]));
        let (nf1, txid1) = cb1.add_tx_paying(wallet.extfvks.read().unwrap()[0].clone(), AMOUNT1);

        wallet.scan_block(&cb1.as_bytes()).unwrap();
        
        assert_eq!(wallet.txs.read().unwrap().len(), 1);
        assert_eq!(wallet.blocks.read().unwrap().len(), 1);
        assert_eq!(wallet.zbalance(None), AMOUNT1);

        const AMOUNT2:u64 = 2;

        // Add a second block, spending the first note 
        let addr2 = ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(&[0u8; 32]))
                        .default_address().unwrap().1;
        let mut cb2 = FakeCompactBlock::new(1, cb1.hash());
        let txid2 = cb2.add_tx_spending((nf1, AMOUNT1), wallet.extfvks.read().unwrap()[0].clone(), addr2, AMOUNT2);
        wallet.scan_block(&cb2.as_bytes()).unwrap();

        // Now, the original note should be spent and there should be a change
        assert_eq!(wallet.zbalance(None), AMOUNT1 - AMOUNT2);
        
        let txs = wallet.txs.read().unwrap();

        // Old note was spent
        assert_eq!(txs[&txid1].txid, txid1);
        assert_eq!(txs[&txid1].notes.len(), 1);
        assert_eq!(txs[&txid1].notes[0].spent.unwrap(), txid2);
        assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT1);
        assert_eq!(txs[&txid1].notes[0].is_change, false);
        
        // new note is not spent
        assert_eq!(txs[&txid2].txid, txid2);
        assert_eq!(txs[&txid2].notes.len(), 1);
        assert_eq!(txs[&txid2].notes[0].spent, None);
        assert_eq!(txs[&txid2].notes[0].note.value, AMOUNT1 - AMOUNT2);
        assert_eq!(txs[&txid2].notes[0].is_change, true);
        assert_eq!(txs[&txid2].total_shielded_value_spent, AMOUNT1);
    }

    #[test]
    fn test_t_receive_spend() {
        let mut rng = OsRng;
        let secp = Secp256k1::new();

        let wallet = LightWallet::new(None, &get_test_config(), 0).unwrap();

        let pk = PublicKey::from_secret_key(&secp, &wallet.tkeys.read().unwrap()[0]);
        let taddr = wallet.address_from_sk(&wallet.tkeys.read().unwrap()[0]);

        const AMOUNT1: u64 = 20;

        let mut tx = FakeTransaction::new(&mut rng);
        tx.add_t_output(&pk, AMOUNT1);
        let txid1 = tx.get_tx().txid();

        wallet.scan_full_tx(&tx.get_tx(), 100);  // Pretend it is at height 100

        {
            let txs = wallet.txs.read().unwrap();

            // Now make sure the t addr was recieved
            assert_eq!(txs.len(), 1);
            assert_eq!(txs[&txid1].utxos.len(), 1);
            assert_eq!(txs[&txid1].utxos[0].address, taddr);
            assert_eq!(txs[&txid1].utxos[0].txid, txid1);
            assert_eq!(txs[&txid1].utxos[0].output_index, 0);
            assert_eq!(txs[&txid1].utxos[0].value, AMOUNT1);
            assert_eq!(txs[&txid1].utxos[0].height, 100);
            assert_eq!(txs[&txid1].utxos[0].spent, None);
            assert_eq!(txs[&txid1].utxos[0].unconfirmed_spent, None);

            assert_eq!(wallet.tbalance(None), AMOUNT1);
            assert_eq!(wallet.tbalance(Some(taddr)), AMOUNT1);
        }

        // Create a new Tx, spending this taddr
        let mut tx = FakeTransaction::new(&mut rng);
        tx.add_t_input(txid1, 0);
        let txid2 = tx.get_tx().txid();

        wallet.scan_full_tx(&tx.get_tx(), 101);  // Pretent it is at height 101

        {
            // Make sure the txid was spent
            let txs = wallet.txs.read().unwrap();

            // Old utxo, that should be spent now
            assert_eq!(txs.len(), 2);
            assert_eq!(txs[&txid1].utxos.len(), 1);
            assert_eq!(txs[&txid1].utxos[0].value, AMOUNT1);
            assert_eq!(txs[&txid1].utxos[0].spent, Some(txid2));
            assert_eq!(txs[&txid1].utxos[0].unconfirmed_spent, None);

            assert_eq!(txs[&txid2].block, 101); // The second TxId is at block 101
            assert_eq!(txs[&txid2].utxos.len(), 0); // The second TxId has no UTXOs
            assert_eq!(txs[&txid2].total_transparent_value_spent, AMOUNT1); 

            // Make sure there is no t-ZEC left
            assert_eq!(wallet.tbalance(None), 0);
        }
    }


    #[test]
    /// This test spends and receives t addresses among non-wallet t addresses to make sure that
    /// we're detecting and spending only our t addrs.
    fn test_t_receive_spend_among_tadds() {
        let mut rng = OsRng;
        let secp = Secp256k1::new();

        let wallet = LightWallet::new(None, &get_test_config(), 0).unwrap();

        let pk = PublicKey::from_secret_key(&secp, &wallet.tkeys.read().unwrap()[0]);
        let taddr = wallet.address_from_sk(&wallet.tkeys.read().unwrap()[0]);

        let non_wallet_sk = &SecretKey::from_slice(&[1u8; 32]).unwrap();
        let non_wallet_pk = PublicKey::from_secret_key(&secp, &non_wallet_sk);

        const AMOUNT1: u64 = 30;

        let mut tx = FakeTransaction::new(&mut rng);
        // Add a non-wallet output
        tx.add_t_output(&non_wallet_pk, 20);
        tx.add_t_output(&pk, AMOUNT1);  // Our wallet t output
        tx.add_t_output(&non_wallet_pk, 25);
        let txid1 = tx.get_tx().txid();

        wallet.scan_full_tx(&tx.get_tx(), 100);  // Pretend it is at height 100

        {
            let txs = wallet.txs.read().unwrap();

            // Now make sure the t addr was received
            assert_eq!(txs.len(), 1);
            assert_eq!(txs[&txid1].utxos.len(), 1);
            assert_eq!(txs[&txid1].utxos[0].address, taddr);
            assert_eq!(txs[&txid1].utxos[0].txid, txid1);
            assert_eq!(txs[&txid1].utxos[0].output_index, 1);
            assert_eq!(txs[&txid1].utxos[0].value, AMOUNT1);
            assert_eq!(txs[&txid1].utxos[0].height, 100);
            assert_eq!(txs[&txid1].utxos[0].spent, None);
            assert_eq!(txs[&txid1].utxos[0].unconfirmed_spent, None);

            assert_eq!(wallet.tbalance(None), AMOUNT1);
            assert_eq!(wallet.tbalance(Some(taddr)), AMOUNT1);
        }

        // Create a new Tx, spending this taddr
        let mut tx = FakeTransaction::new(&mut rng);
        tx.add_t_input(txid1, 1);   // Ours was at position 1 in the input tx
        let txid2 = tx.get_tx().txid();

        wallet.scan_full_tx(&tx.get_tx(), 101);  // Pretent it is at height 101

        {
            // Make sure the txid was spent
            let txs = wallet.txs.read().unwrap();

            // Old utxo, that should be spent now
            assert_eq!(txs.len(), 2);
            assert_eq!(txs[&txid1].utxos.len(), 1);
            assert_eq!(txs[&txid1].utxos[0].value, AMOUNT1);
            assert_eq!(txs[&txid1].utxos[0].spent, Some(txid2));
            assert_eq!(txs[&txid1].utxos[0].unconfirmed_spent, None);

            assert_eq!(txs[&txid2].block, 101); // The second TxId is at block 101
            assert_eq!(txs[&txid2].utxos.len(), 0); // The second TxId has no UTXOs
            assert_eq!(txs[&txid2].total_transparent_value_spent, AMOUNT1);

            // Make sure there is no t-ZEC left
            assert_eq!(wallet.tbalance(None), 0);
        }
    }

    #[test]
    fn test_serialization() {
        let secp = Secp256k1::new();
        let config = get_test_config();

        let wallet = LightWallet::new(None, &config, 0).unwrap();

        // First, add an incoming transaction
        const AMOUNT1:u64 = 5;

        let mut cb1 = FakeCompactBlock::new(0, BlockHash([0; 32]));
        let (nf1, txid1) = cb1.add_tx_paying(wallet.extfvks.read().unwrap()[0].clone(), AMOUNT1);

        wallet.scan_block(&cb1.as_bytes()).unwrap();

        assert_eq!(wallet.txs.read().unwrap().len(), 1);
        assert_eq!(wallet.blocks.read().unwrap().len(), 1);
        assert_eq!(wallet.zbalance(None), AMOUNT1);

        // Add a t input at the Tx
        let pk = PublicKey::from_secret_key(&secp, &wallet.tkeys.read().unwrap()[0]);
        let taddr = wallet.address_from_sk(&wallet.tkeys.read().unwrap()[0]);

        const TAMOUNT1: u64 = 20;

        let mut tx = FakeTransaction::new_with_txid(txid1);
        tx.add_t_output(&pk, TAMOUNT1);
        wallet.scan_full_tx(&tx.get_tx(), 0);  // Height 0

        const AMOUNT2:u64 = 2;

        // Add a second block, spending the first note
        let addr2 = ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(&[0u8; 32]))
            .default_address().unwrap().1;
        let mut cb2 = FakeCompactBlock::new(1, cb1.hash());
        let txid2 = cb2.add_tx_spending((nf1, AMOUNT1), wallet.extfvks.read().unwrap()[0].clone(), addr2, AMOUNT2);
        wallet.scan_block(&cb2.as_bytes()).unwrap();

        let mut tx = FakeTransaction::new_with_txid(txid2);
        tx.add_t_input(txid1, 0);
        wallet.scan_full_tx(&tx.get_tx(), 1);  // Height 1

        // Now, the original note should be spent and there should be a change
        assert_eq!(wallet.zbalance(None), AMOUNT1 - AMOUNT2 ); // The t addr amount is received + spent, so it cancels out

        // Now, serialize the wallet and read it back again
        let mut serialized_data = vec![];
        wallet.write(&mut serialized_data).expect("Serialize wallet");
        let wallet2 = LightWallet::read(&serialized_data[..], &config).unwrap();

        assert_eq!(wallet2.zbalance(None), AMOUNT1 - AMOUNT2);

        // Test the keys were serialized correctly
        {
            assert_eq!(wallet.seed, wallet2.seed);

            assert_eq!(wallet.extsks.read().unwrap().len(), wallet2.extsks.read().unwrap().len());
            assert_eq!(wallet.extsks.read().unwrap()[0], wallet2.extsks.read().unwrap()[0]);
            assert_eq!(wallet.extfvks.read().unwrap()[0], wallet2.extfvks.read().unwrap()[0]);
            assert_eq!(wallet.address.read().unwrap()[0], wallet2.address.read().unwrap()[0]);

            assert_eq!(wallet.tkeys.read().unwrap().len(), wallet2.tkeys.read().unwrap().len());
            assert_eq!(wallet.tkeys.read().unwrap()[0], wallet2.tkeys.read().unwrap()[0]);
        }

        // Test blocks were serialized properly
        {
            let blks = wallet2.blocks.read().unwrap();

            assert_eq!(blks.len(), 2);
            assert_eq!(blks[0].height, 0);
            assert_eq!(blks[1].height, 1);
        }

        // Test txns were serialized properly.
        {
            let txs = wallet2.txs.read().unwrap();

            // Old note was spent
            assert_eq!(txs[&txid1].txid, txid1);
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].spent.unwrap(), txid2);
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT1);
            assert_eq!(txs[&txid1].notes[0].is_change, false);

            // Old UTXO was spent
            assert_eq!(txs[&txid1].utxos.len(), 1);
            assert_eq!(txs[&txid1].utxos[0].address, taddr);
            assert_eq!(txs[&txid1].utxos[0].txid, txid1);
            assert_eq!(txs[&txid1].utxos[0].output_index, 0);
            assert_eq!(txs[&txid1].utxos[0].value, TAMOUNT1);
            assert_eq!(txs[&txid1].utxos[0].height, 0);
            assert_eq!(txs[&txid1].utxos[0].spent, Some(txid2));
            assert_eq!(txs[&txid1].utxos[0].unconfirmed_spent, None);

            // new note is not spent
            assert_eq!(txs[&txid2].txid, txid2);
            assert_eq!(txs[&txid2].notes.len(), 1);
            assert_eq!(txs[&txid2].notes[0].spent, None);
            assert_eq!(txs[&txid2].notes[0].note.value, AMOUNT1 - AMOUNT2);
            assert_eq!(txs[&txid2].notes[0].is_change, true);
            assert_eq!(txs[&txid2].total_shielded_value_spent, AMOUNT1);

            // The UTXO was spent in txid2
            assert_eq!(txs[&txid2].utxos.len(), 0); // The second TxId has no UTXOs
            assert_eq!(txs[&txid2].total_transparent_value_spent, TAMOUNT1);
        }
    }

    #[test]
    fn test_multi_serialization() {
        let config = get_test_config();

        let wallet = LightWallet::new(None, &config, 0).unwrap();

        let taddr1 = wallet.address_from_sk(&wallet.tkeys.read().unwrap()[0]);
        let taddr2 = wallet.add_taddr();

        let (zaddr1, zpk1) = &wallet.get_z_private_keys()[0];
        let zaddr2 = wallet.add_zaddr();

        let mut serialized_data = vec![];
        wallet.write(&mut serialized_data).expect("Serialize wallet");
        let wallet2 = LightWallet::read(&serialized_data[..], &config).unwrap();

        assert_eq!(wallet2.tkeys.read().unwrap().len(), 2);
        assert_eq!(wallet2.extsks.read().unwrap().len(), 2);
        assert_eq!(wallet2.extfvks.read().unwrap().len(), 2);
        assert_eq!(wallet2.address.read().unwrap().len(), 2);

        assert_eq!(taddr1, wallet.address_from_sk(&wallet.tkeys.read().unwrap()[0]));
        assert_eq!(taddr2, wallet.address_from_sk(&wallet.tkeys.read().unwrap()[1]));

        let (w2_zaddr1, w2_zpk1) = &wallet.get_z_private_keys()[0];
        let (w2_zaddr2, _) = &wallet.get_z_private_keys()[1];
        assert_eq!(zaddr1, w2_zaddr1);
        assert_eq!(zpk1, w2_zpk1);
        assert_eq!(zaddr2, *w2_zaddr2);

    }

    fn get_test_config() -> LightClientConfig {
        LightClientConfig {
            server: "0.0.0.0:0".parse().unwrap(),
            chain_name: "test".to_string(),
            sapling_activation_height: 0,
            consensus_branch_id: "000000".to_string(),
            anchor_offset: 0
        }
    }

    // Get a test wallet already setup with a single note
    fn get_test_wallet(amount: u64) -> (LightWallet, TxId, BlockHash) {
        let config = get_test_config();

        let wallet = LightWallet::new(None, &config, 0).unwrap();

        let mut cb1 = FakeCompactBlock::new(0, BlockHash([0; 32]));
        let (_, txid1) = cb1.add_tx_paying(wallet.extfvks.read().unwrap()[0].clone(), amount);
        wallet.scan_block(&cb1.as_bytes()).unwrap();

        // We have one note
        {
            let txs = wallet.txs.read().unwrap();
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].note.value, amount);
            assert_eq!(txs[&txid1].notes[0].spent, None);
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, None);
        }

        assert_eq!(wallet.verified_zbalance(None), amount);

        // Create a new block so that the note is now verified to be spent
        let cb2 = FakeCompactBlock::new(1, cb1.hash());
        wallet.scan_block(&cb2.as_bytes()).unwrap();

        (wallet, txid1, cb2.hash())
    }

    #[test]
    fn test_z_spend() {
        const AMOUNT1: u64 = 50000;
        let (wallet, txid1, block_hash) = get_test_wallet(AMOUNT1);

        let fvk = ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(&[1u8; 32]));
        let ext_address = encode_payment_address(wallet.config.hrp_sapling_address(),
                            &fvk.default_address().unwrap().1);

        const AMOUNT_SENT: u64 = 20;

        let outgoing_memo = "Outgoing Memo".to_string();
        let fee: u64 = DEFAULT_FEE.try_into().unwrap();

        let branch_id = u32::from_str_radix("2bb40e60", 16).unwrap();
        let (ss, so) =get_sapling_params().unwrap();

        // Create a tx and send to address
        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                &ext_address, AMOUNT_SENT, Some(outgoing_memo.clone())).unwrap();

        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid = sent_tx.txid();

        // Now, the note should be unconfirmed spent
        {
            let txs = wallet.txs.read().unwrap();

            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT1);
            assert_eq!(txs[&txid1].notes[0].is_change, false);
            assert_eq!(txs[&txid1].notes[0].spent, None);
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, Some(sent_txid));
        }

        let mut cb3 = FakeCompactBlock::new(2, block_hash);
        cb3.add_tx(&sent_tx);
        wallet.scan_block(&cb3.as_bytes()).unwrap();

        // Now this new Spent tx should be in, so the note should be marked confirmed spent
        {
            let txs = wallet.txs.read().unwrap();
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT1);
            assert_eq!(txs[&txid1].notes[0].spent, Some(sent_txid));
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, None);

            // The sent tx should generate change
            assert_eq!(txs[&sent_txid].notes.len(), 1);
            assert_eq!(txs[&sent_txid].notes[0].note.value, AMOUNT1 - AMOUNT_SENT - fee);
            assert_eq!(txs[&sent_txid].notes[0].is_change, true);
            assert_eq!(txs[&sent_txid].notes[0].spent, None);
            assert_eq!(txs[&sent_txid].notes[0].unconfirmed_spent, None);
        }

        // Now, full scan the Tx, which should populate the Outgoing Meta data
        wallet.scan_full_tx(&sent_tx, 2);

        // Check Outgoing Metadata
        {
            let txs = wallet.txs.read().unwrap();
            assert_eq!(txs[&sent_txid].total_shielded_value_spent, AMOUNT1);

            assert_eq!(txs[&sent_txid].outgoing_metadata.len(), 1);

            assert_eq!(txs[&sent_txid].outgoing_metadata[0].address, ext_address);
            assert_eq!(txs[&sent_txid].outgoing_metadata[0].value, AMOUNT_SENT);
            assert_eq!(txs[&sent_txid].outgoing_metadata[0].memo.to_utf8().unwrap().unwrap(), outgoing_memo);
        }
    }

    #[test]
    fn test_multi_z() {
        const AMOUNT1: u64 = 50000;
        let (wallet, txid1, block_hash) = get_test_wallet(AMOUNT1);

        let zaddr2 = wallet.add_zaddr();

        const AMOUNT_SENT: u64 = 20;

        let outgoing_memo = "Outgoing Memo".to_string();
        let fee: u64 = DEFAULT_FEE.try_into().unwrap();

        let branch_id = u32::from_str_radix("2bb40e60", 16).unwrap();
        let (ss, so) =get_sapling_params().unwrap();

        // Create a tx and send to address
        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                &zaddr2, AMOUNT_SENT, Some(outgoing_memo.clone())).unwrap();

        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid = sent_tx.txid();

        let mut cb3 = FakeCompactBlock::new(2, block_hash);
        cb3.add_tx(&sent_tx);
        wallet.scan_block(&cb3.as_bytes()).unwrap();
        wallet.scan_full_tx(&sent_tx, 2);

        // Because the builder will randomize notes outputted, we need to find
        // which note number is the change and which is the output note (Because this tx
        // had both outputs in the same Tx)
        let (change_note_number, ext_note_number) = {
            let txs = wallet.txs.read().unwrap();
            if txs[&sent_txid].notes[0].is_change { (0,1) } else { (1,0) }
        };

        // Now this new Spent tx should be in, so the note should be marked confirmed spent
        {
            let txs = wallet.txs.read().unwrap();
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT1);
            assert_eq!(txs[&txid1].notes[0].spent, Some(sent_txid));
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, None);

            // The sent tx should generate change + the new incoming note
            assert_eq!(txs[&sent_txid].notes.len(), 2);

            assert_eq!(txs[&sent_txid].notes[change_note_number].note.value, AMOUNT1 - AMOUNT_SENT - fee);
            assert_eq!(txs[&sent_txid].notes[change_note_number].account, 0);
            assert_eq!(txs[&sent_txid].notes[change_note_number].is_change, true);
            assert_eq!(txs[&sent_txid].notes[change_note_number].spent, None);
            assert_eq!(txs[&sent_txid].notes[change_note_number].unconfirmed_spent, None);
            assert_eq!(LightWallet::memo_str(&txs[&sent_txid].notes[change_note_number].memo), None);

            assert_eq!(txs[&sent_txid].notes[ext_note_number].note.value, AMOUNT_SENT);
            assert_eq!(txs[&sent_txid].notes[ext_note_number].account, 1);
            assert_eq!(txs[&sent_txid].notes[ext_note_number].is_change, false);
            assert_eq!(txs[&sent_txid].notes[ext_note_number].spent, None);
            assert_eq!(txs[&sent_txid].notes[ext_note_number].unconfirmed_spent, None);
            assert_eq!(LightWallet::memo_str(&txs[&sent_txid].notes[ext_note_number].memo), Some(outgoing_memo));

            assert_eq!(txs[&sent_txid].total_shielded_value_spent, AMOUNT1);

            // No Outgoing meta data, since this is a wallet -> wallet tx
            assert_eq!(txs[&sent_txid].outgoing_metadata.len(), 0);
        }

        // Now spend the money, which should pick notes from both addresses
        let amount_all:u64 = (AMOUNT1 - AMOUNT_SENT - fee) + (AMOUNT_SENT) - fee;
        let taddr = wallet.address_from_sk(&SecretKey::from_slice(&[1u8; 32]).unwrap());

        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                            &taddr, amount_all, None).unwrap();
        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_ext_txid = sent_tx.txid();

        let mut cb4 = FakeCompactBlock::new(3, cb3.hash());
        cb4.add_tx(&sent_tx);
        wallet.scan_block(&cb4.as_bytes()).unwrap();
        wallet.scan_full_tx(&sent_tx, 3);

        {
            // Both notes should be spent now.
            let txs = wallet.txs.read().unwrap();

            assert_eq!(txs[&sent_txid].notes[change_note_number].is_change, true);
            assert_eq!(txs[&sent_txid].notes[change_note_number].spent, Some(sent_ext_txid));
            assert_eq!(txs[&sent_txid].notes[change_note_number].unconfirmed_spent, None);

            assert_eq!(txs[&sent_txid].notes[ext_note_number].is_change, false);
            assert_eq!(txs[&sent_txid].notes[ext_note_number].spent, Some(sent_ext_txid));
            assert_eq!(txs[&sent_txid].notes[ext_note_number].unconfirmed_spent, None);

            // Check outgoing metadata for the external sent tx
            assert_eq!(txs[&sent_ext_txid].notes.len(), 0); // No change was generated
            assert_eq!(txs[&sent_ext_txid].outgoing_metadata.len(), 1);
            assert_eq!(txs[&sent_ext_txid].outgoing_metadata[0].address, taddr);
            assert_eq!(txs[&sent_ext_txid].outgoing_metadata[0].value, amount_all);
        }
    }

    #[test]
    fn test_z_spend_to_taddr() {
        const AMOUNT1: u64 = 50000;
        let (wallet, txid1, block_hash) = get_test_wallet(AMOUNT1);

        let branch_id = u32::from_str_radix("2bb40e60", 16).unwrap();
        let (ss, so) =get_sapling_params().unwrap();

        let taddr = wallet.address_from_sk(&SecretKey::from_slice(&[1u8; 32]).unwrap());
        const AMOUNT_SENT: u64 = 30;
        let fee: u64 = DEFAULT_FEE.try_into().unwrap();

        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                            &taddr, AMOUNT_SENT, None).unwrap();
        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid = sent_tx.txid();

        // Now, the note should be unconfirmed spent
        {
            let txs = wallet.txs.read().unwrap();

            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT1);
            assert_eq!(txs[&txid1].notes[0].is_change, false);
            assert_eq!(txs[&txid1].notes[0].spent, None);
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, Some(sent_txid));
        }

        let mut cb3 = FakeCompactBlock::new(2, block_hash);
        cb3.add_tx(&sent_tx);
        wallet.scan_block(&cb3.as_bytes()).unwrap();


        // Now this new Spent tx should be in, so the note should be marked confirmed spent
        {
            let txs = wallet.txs.read().unwrap();
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT1);
            assert_eq!(txs[&txid1].notes[0].spent, Some(sent_txid));
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, None);

            // The sent tx should generate change
            assert_eq!(txs[&sent_txid].notes.len(), 1);
            assert_eq!(txs[&sent_txid].notes[0].note.value, AMOUNT1 - AMOUNT_SENT - fee);
            assert_eq!(txs[&sent_txid].notes[0].is_change, true);
            assert_eq!(txs[&sent_txid].notes[0].spent, None);
            assert_eq!(txs[&sent_txid].notes[0].unconfirmed_spent, None);
        }

        // Now, full scan the Tx, which should populate the Outgoing Meta data
        wallet.scan_full_tx(&sent_tx, 2);

        // Check Outgoing Metadata for t address
        {
            let txs = wallet.txs.read().unwrap();
            assert_eq!(txs[&sent_txid].outgoing_metadata.len(), 1);
            assert_eq!(txs[&sent_txid].outgoing_metadata[0].address, taddr);
            assert_eq!(txs[&sent_txid].outgoing_metadata[0].value, AMOUNT_SENT);
            assert_eq!(txs[&sent_txid].total_shielded_value_spent, AMOUNT1);
        }
    }

    #[test]
    fn test_t_spend_to_z() {
        let mut rng = OsRng;
        let secp = Secp256k1::new();

        const AMOUNT_Z: u64 = 50000;
        const AMOUNT_T: u64 = 40000;
        let (wallet, txid1, block_hash) = get_test_wallet(AMOUNT_Z);

        let pk = PublicKey::from_secret_key(&secp, &wallet.tkeys.read().unwrap()[0]);
        let taddr = wallet.address_from_sk(&wallet.tkeys.read().unwrap()[0]);

        let mut tx = FakeTransaction::new(&mut rng);
        tx.add_t_output(&pk, AMOUNT_T);
        let txid_t = tx.get_tx().txid();

        wallet.scan_full_tx(&tx.get_tx(), 1);  // Pretend it is at height 1

        {
            let txs = wallet.txs.read().unwrap();

            // Now make sure the t addr was recieved
            assert_eq!(txs[&txid_t].utxos.len(), 1);
            assert_eq!(txs[&txid_t].utxos[0].address, taddr);
            assert_eq!(txs[&txid_t].utxos[0].spent, None);
            assert_eq!(txs[&txid_t].utxos[0].unconfirmed_spent, None);

            assert_eq!(wallet.tbalance(None), AMOUNT_T);
        }


        let fvk = ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(&[1u8; 32]));
        let ext_address = encode_payment_address(wallet.config.hrp_sapling_address(),
                            &fvk.default_address().unwrap().1);
        const AMOUNT_SENT: u64 = 20;

        let outgoing_memo = "Outgoing Memo".to_string();
        let fee: u64 = DEFAULT_FEE.try_into().unwrap();

        let branch_id = u32::from_str_radix("2bb40e60", 16).unwrap();
        let (ss, so) =get_sapling_params().unwrap();

        // Create a tx and send to address. This should consume both the UTXO and the note
        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                &ext_address, AMOUNT_SENT, Some(outgoing_memo.clone())).unwrap();

        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid = sent_tx.txid();

        // Verify the sent_tx for sanity
        {
            // The tx has 1 note spent, 1 utxo spent, and (1 note out, 1 note change)
            assert_eq!(sent_tx.shielded_spends.len(), 1);
            assert_eq!(sent_tx.vin.len(), 1);
            assert_eq!(sent_tx.shielded_outputs.len(), 2);
        }

        // Now, the note and utxo should be unconfirmed spent
        {
            let txs = wallet.txs.read().unwrap();

            // UTXO
            assert_eq!(txs[&txid_t].utxos.len(), 1);
            assert_eq!(txs[&txid_t].utxos[0].address, taddr);
            assert_eq!(txs[&txid_t].utxos[0].spent, None);
            assert_eq!(txs[&txid_t].utxos[0].unconfirmed_spent, Some(sent_txid));

            // Note
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT_Z);
            assert_eq!(txs[&txid1].notes[0].spent, None);
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, Some(sent_txid));
        }

        let mut cb3 = FakeCompactBlock::new(2, block_hash);
        cb3.add_tx(&sent_tx);

        // Scan the compact block and the full Tx
        wallet.scan_block(&cb3.as_bytes()).unwrap();
        wallet.scan_full_tx(&sent_tx, 2);

        // Now this new Spent tx should be in, so the note should be marked confirmed spent
        {
            let txs = wallet.txs.read().unwrap();
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT_Z);
            assert_eq!(txs[&txid1].notes[0].spent, Some(sent_txid));
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, None);

            // The UTXO should also be spent
            assert_eq!(txs[&txid_t].utxos[0].address, taddr);
            assert_eq!(txs[&txid_t].utxos[0].spent, Some(sent_txid));
            assert_eq!(txs[&txid_t].utxos[0].unconfirmed_spent, None);

            // The sent tx should generate change
            assert_eq!(txs[&sent_txid].notes.len(), 1);
            assert_eq!(txs[&sent_txid].notes[0].note.value, AMOUNT_Z + AMOUNT_T - AMOUNT_SENT - fee);
            assert_eq!(txs[&sent_txid].notes[0].is_change, true);
            assert_eq!(txs[&sent_txid].notes[0].spent, None);
            assert_eq!(txs[&sent_txid].notes[0].unconfirmed_spent, None);
        }
    }

     #[test]
    fn test_z_incoming_memo() {
        const AMOUNT1: u64 = 50000;
        let (wallet, _txid1, block_hash) = get_test_wallet(AMOUNT1);

        let my_address = encode_payment_address(wallet.config.hrp_sapling_address(),
                            &wallet.extfvks.read().unwrap()[0].default_address().unwrap().1);

        let memo = "Incoming Memo".to_string();
        let fee: u64 = DEFAULT_FEE.try_into().unwrap();

        let branch_id = u32::from_str_radix("2bb40e60", 16).unwrap();
        let (ss, so) =get_sapling_params().unwrap();

        // Create a tx and send to address
        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                &my_address, AMOUNT1 - fee, Some(memo.clone())).unwrap();
        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid = sent_tx.txid();

        // Add it to a block
        let mut cb3 = FakeCompactBlock::new(2, block_hash);
        cb3.add_tx(&sent_tx);
        wallet.scan_block(&cb3.as_bytes()).unwrap();

        // And scan the Full Tx to get the memo
        wallet.scan_full_tx(&sent_tx, 2);

        {
            let txs = wallet.txs.read().unwrap();
            
            assert_eq!(txs[&sent_txid].notes.len(), 1);

            assert_eq!(txs[&sent_txid].notes[0].extfvk, wallet.extfvks.read().unwrap()[0]);
            assert_eq!(txs[&sent_txid].notes[0].note.value, AMOUNT1 - fee);
            assert_eq!(wallet.note_address(&txs[&sent_txid].notes[0]), Some(my_address));
            assert_eq!(LightWallet::memo_str(&txs[&sent_txid].notes[0].memo), Some(memo));
        }
    }

     #[test]
    fn test_z_to_t_withinwallet() {
        const AMOUNT: u64 = 500000;
        const AMOUNT_SENT: u64 = 20000;
        let (wallet, txid1, block_hash) = get_test_wallet(AMOUNT);

        let taddr = wallet.address_from_sk(&wallet.tkeys.read().unwrap()[0]);

        let fee: u64 = DEFAULT_FEE.try_into().unwrap();

        let branch_id = u32::from_str_radix("2bb40e60", 16).unwrap();
        let (ss, so) = get_sapling_params().unwrap();

        // Create a tx and send to address
        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                &taddr, AMOUNT_SENT, None).unwrap();
        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid = sent_tx.txid();

        // Add it to a block
        let mut cb3 = FakeCompactBlock::new(2, block_hash);
        cb3.add_tx(&sent_tx);
        wallet.scan_block(&cb3.as_bytes()).unwrap();

        // And scan the Full Tx to get the memo
        wallet.scan_full_tx(&sent_tx, 2);

        {
            let txs = wallet.txs.read().unwrap();
            
            // We have the original note
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT);
            
            // We have the spent tx
            assert_eq!(txs[&sent_txid].notes.len(), 1);
            assert_eq!(txs[&sent_txid].notes[0].note.value, AMOUNT - AMOUNT_SENT - fee);
            assert_eq!(txs[&sent_txid].notes[0].is_change, true);
            assert_eq!(txs[&sent_txid].notes[0].spent, None);
            assert_eq!(txs[&sent_txid].notes[0].unconfirmed_spent, None);

            // Since we sent the Tx to ourself, there should be no outgoing 
            // metadata
            assert_eq!(txs[&sent_txid].total_shielded_value_spent, AMOUNT);
            assert_eq!(txs[&sent_txid].outgoing_metadata.len(), 0);


            // We have the taddr utxo in the same Tx
            assert_eq!(txs[&sent_txid].utxos.len(), 1);
            assert_eq!(txs[&sent_txid].utxos[0].address, taddr);
            assert_eq!(txs[&sent_txid].utxos[0].value, AMOUNT_SENT);
            assert_eq!(txs[&sent_txid].utxos[0].spent, None);
            assert_eq!(txs[&sent_txid].utxos[0].unconfirmed_spent, None);

        }
    }

     #[test]
    fn test_multi_t() {
        const AMOUNT: u64 = 5000000;
        const AMOUNT_SENT1: u64 = 20000;
        const AMOUNT_SENT2: u64 = 10000;

        let (wallet, txid1, block_hash) = get_test_wallet(AMOUNT);

        // Add a new taddr
        let taddr2 = wallet.add_taddr();

        let fee: u64 = DEFAULT_FEE.try_into().unwrap();

        let branch_id = u32::from_str_radix("2bb40e60", 16).unwrap();
        let (ss, so) = get_sapling_params().unwrap();

        // Create a Tx and send to the second t address
        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                &taddr2, AMOUNT_SENT1, None).unwrap();
        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid1 = sent_tx.txid();

        // Add it to a block
        let mut cb3 = FakeCompactBlock::new(2, block_hash);
        cb3.add_tx(&sent_tx);
        wallet.scan_block(&cb3.as_bytes()).unwrap();
        wallet.scan_full_tx(&sent_tx, 2);

        // Check that the send to the second taddr worked
        {
            let txs = wallet.txs.read().unwrap();
            
            // We have the original note
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT);
            
            // We have the spent tx
            assert_eq!(txs[&sent_txid1].notes.len(), 1);
            assert_eq!(txs[&sent_txid1].notes[0].note.value, AMOUNT - AMOUNT_SENT1 - fee);
            assert_eq!(txs[&sent_txid1].notes[0].is_change, true);
            assert_eq!(txs[&sent_txid1].notes[0].spent, None);
            assert_eq!(txs[&sent_txid1].notes[0].unconfirmed_spent, None);

            // Since we sent the Tx to ourself, there should be no outgoing 
            // metadata
            assert_eq!(txs[&sent_txid1].total_shielded_value_spent, AMOUNT);
            assert_eq!(txs[&sent_txid1].outgoing_metadata.len(), 0);


            // We have the taddr utxo in the same Tx
            assert_eq!(txs[&sent_txid1].utxos.len(), 1);
            assert_eq!(txs[&sent_txid1].utxos[0].address, taddr2);
            assert_eq!(txs[&sent_txid1].utxos[0].value, AMOUNT_SENT1);
            assert_eq!(txs[&sent_txid1].utxos[0].spent, None);
            assert_eq!(txs[&sent_txid1].utxos[0].unconfirmed_spent, None);
        }

        // Send some money to the 3rd t addr
        let taddr3 = wallet.add_taddr();

        // Create a Tx and send to the second t address
        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                &taddr3, AMOUNT_SENT2, None).unwrap();
        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid2 = sent_tx.txid();

        // Add it to a block
        let mut cb4 = FakeCompactBlock::new(3, cb3.hash());
        cb4.add_tx(&sent_tx);
        wallet.scan_block(&cb4.as_bytes()).unwrap();
        wallet.scan_full_tx(&sent_tx, 3);

        // Quickly check we have it
        {
            let txs = wallet.txs.read().unwrap();
            
            // We have the taddr utxo in the same Tx
            assert_eq!(txs[&sent_txid2].utxos.len(), 1);
            assert_eq!(txs[&sent_txid2].utxos[0].address, taddr3);
            assert_eq!(txs[&sent_txid2].utxos[0].value, AMOUNT_SENT2);

            // Old UTXO was NOT spent here, because we sent it to a taddr
            assert_eq!(txs[&sent_txid1].utxos.len(), 1);
            assert_eq!(txs[&sent_txid1].utxos[0].value, AMOUNT_SENT1);
            assert_eq!(txs[&sent_txid1].utxos[0].address, taddr2);
            assert_eq!(txs[&sent_txid1].utxos[0].spent, None);
            assert_eq!(txs[&sent_txid1].utxos[0].unconfirmed_spent, None);
        }

        // Now, spend to an external z address, which will select all the utxos
        let fvk = ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(&[1u8; 32]));
        let ext_address = encode_payment_address(wallet.config.hrp_sapling_address(),
                            &fvk.default_address().unwrap().1);

        const AMOUNT_SENT_EXT: u64 = 45;
        let outgoing_memo = "Outgoing Memo".to_string();

        // Create a tx and send to address
        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                &ext_address, AMOUNT_SENT_EXT, Some(outgoing_memo.clone())).unwrap();

        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid3 = sent_tx.txid();

        let mut cb5 = FakeCompactBlock::new(4, cb4.hash());
        cb5.add_tx(&sent_tx);
        wallet.scan_block(&cb5.as_bytes()).unwrap();
        wallet.scan_full_tx(&sent_tx, 4);

        {
            let txs = wallet.txs.read().unwrap();
            assert_eq!(txs[&sent_txid3].outgoing_metadata.len(), 1);

            assert_eq!(txs[&sent_txid3].outgoing_metadata[0].address, ext_address);
            assert_eq!(txs[&sent_txid3].outgoing_metadata[0].value, AMOUNT_SENT_EXT);
            assert_eq!(txs[&sent_txid3].outgoing_metadata[0].memo.to_utf8().unwrap().unwrap(), outgoing_memo);

            // Test to see both UTXOs were spent.
            // UTXO1
            assert_eq!(txs[&sent_txid1].utxos[0].value, AMOUNT_SENT1);
            assert_eq!(txs[&sent_txid1].utxos[0].address, taddr2);
            assert_eq!(txs[&sent_txid1].utxos[0].spent, Some(sent_txid3));
            assert_eq!(txs[&sent_txid1].utxos[0].unconfirmed_spent, None);

            // UTXO2
            assert_eq!(txs[&sent_txid2].utxos[0].value, AMOUNT_SENT2);
            assert_eq!(txs[&sent_txid2].utxos[0].address, taddr3);
            assert_eq!(txs[&sent_txid2].utxos[0].spent, Some(sent_txid3));
            assert_eq!(txs[&sent_txid2].utxos[0].unconfirmed_spent, None);
        }

    }

    /// Test helper to add blocks
    fn add_blocks(wallet: &LightWallet, start: i32, num: i32, mut prev_hash: BlockHash) -> Result<BlockHash, i32>{
        // Add it to a block
        let mut new_blk = FakeCompactBlock::new(start, prev_hash);
        for i in 0..num {
            new_blk = FakeCompactBlock::new(start+i, prev_hash);
            prev_hash = new_blk.hash();
            match wallet.scan_block(&new_blk.as_bytes()) {
                Ok(_)  => {}, // continue
                Err(e) => return Err(e)
            };
        }


        Ok(new_blk.hash())
    }

    #[test]
    fn test_block_limit() {
        const AMOUNT: u64 = 500000;
        let (wallet, _txid1, block_hash) = get_test_wallet(AMOUNT);       

        let prev_hash = add_blocks(&wallet, 2, 1, block_hash).unwrap();
        assert_eq!(wallet.blocks.read().unwrap().len(), 3);
        
        let prev_hash = add_blocks(&wallet, 3, 47, prev_hash).unwrap();
        assert_eq!(wallet.blocks.read().unwrap().len(), 50);
        
        let prev_hash = add_blocks(&wallet, 50, 51, prev_hash).unwrap();
        assert_eq!(wallet.blocks.read().unwrap().len(), 101);
        
        // Subsequent blocks should start to trim
        let prev_hash = add_blocks(&wallet, 101, 1, prev_hash).unwrap();
        assert_eq!(wallet.blocks.read().unwrap().len(), 101);

        // Add lots
        let _ = add_blocks(&wallet, 102, 10, prev_hash).unwrap();
        assert_eq!(wallet.blocks.read().unwrap().len(), 101);

        // Now clear the blocks
        wallet.clear_blocks();
        assert_eq!(wallet.blocks.read().unwrap().len(), 0);

        let prev_hash = add_blocks(&wallet, 0, 1, BlockHash([0;32])).unwrap();
        assert_eq!(wallet.blocks.read().unwrap().len(), 1);

        let _ = add_blocks(&wallet, 1, 10, prev_hash).unwrap();
        assert_eq!(wallet.blocks.read().unwrap().len(), 11);
    }

    #[test]
    fn test_rollback() {
        const AMOUNT: u64 = 500000;

        let (wallet, txid1, block_hash) = get_test_wallet(AMOUNT);       

        add_blocks(&wallet, 2, 5, block_hash).unwrap();
        
        // Invalidate 2 blocks
        assert_eq!(wallet.last_scanned_height(), 6);
        assert_eq!(wallet.invalidate_block(5), 2);

        let blk3_hash;
        let blk4_hash;
        {
            let blks = wallet.blocks.read().unwrap();
            blk3_hash = blks[3].hash.clone();
            blk4_hash = blks[4].hash.clone();
        }

        // This should result in an exception, because the "prevhash" is wrong
        assert!(add_blocks(&wallet, 5, 2, blk3_hash).is_err(), 
            "Shouldn't be able to add because of invalid prev hash");

        // Add with the proper prev hash
        add_blocks(&wallet, 5, 2, blk4_hash).unwrap();

        let blk6_hash;
        {
            let blks = wallet.blocks.read().unwrap();
            blk6_hash = blks[6].hash.clone();
        }

        // Now do a Tx
        let taddr = wallet.address_from_sk(&SecretKey::from_slice(&[1u8; 32]).unwrap());

        let branch_id = u32::from_str_radix("2bb40e60", 16).unwrap();
        let (ss, so) = get_sapling_params().unwrap();

        // Create a tx and send to address
        const AMOUNT_SENT: u64 = 30000;
        let fee: u64 = DEFAULT_FEE.try_into().unwrap();
        let raw_tx = wallet.send_to_address(branch_id, &ss, &so,
                                &taddr, AMOUNT_SENT, None).unwrap();

        let sent_tx = Transaction::read(&raw_tx[..]).unwrap();
        let sent_txid = sent_tx.txid();
        let mut cb3 = FakeCompactBlock::new(7, blk6_hash);
        cb3.add_tx(&sent_tx);
        wallet.scan_block(&cb3.as_bytes()).unwrap();
        wallet.scan_full_tx(&sent_tx, 7);

        // Make sure the Tx is in.
        {
            let txs = wallet.txs.read().unwrap();
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT);
            assert_eq!(txs[&txid1].notes[0].spent, Some(sent_txid));
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, None);

            // The sent tx should generate change
            assert_eq!(txs[&sent_txid].notes.len(), 1);
            assert_eq!(txs[&sent_txid].notes[0].note.value, AMOUNT - AMOUNT_SENT - fee);
            assert_eq!(txs[&sent_txid].notes[0].is_change, true);
            assert_eq!(txs[&sent_txid].notes[0].spent, None);
            assert_eq!(txs[&sent_txid].notes[0].unconfirmed_spent, None);
        }

        // Invalidate 3 blocks
        assert_eq!(wallet.last_scanned_height(), 7);
        assert_eq!(wallet.invalidate_block(5), 3);
        assert_eq!(wallet.last_scanned_height(), 4);
        
        // Make sure the orig Tx is there, but new Tx has disappeared
        {
            let txs = wallet.txs.read().unwrap();

            // Orig Tx is still there, since this is in block 0
            // But now the spent tx is gone
            assert_eq!(txs[&txid1].notes.len(), 1);
            assert_eq!(txs[&txid1].notes[0].note.value, AMOUNT);
            assert_eq!(txs[&txid1].notes[0].spent, None);
            assert_eq!(txs[&txid1].notes[0].unconfirmed_spent, None);

            // The sent tx is missing
            assert!(txs.get(&sent_txid).is_none());
        }
    }

    #[test]
    fn test_t_derivation() {
        let lc = LightClientConfig {
            server: "0.0.0.0:0".parse().unwrap(),
            chain_name: "main".to_string(),
            sapling_activation_height: 0,
            consensus_branch_id: "000000".to_string(),
            anchor_offset: 1
        };

        let seed_phrase = Some("chimney better bulb horror rebuild whisper improve intact letter giraffe brave rib appear bulk aim burst snap salt hill sad merge tennis phrase raise".to_string());

        let wallet = LightWallet::new(seed_phrase.clone(), &lc, 0).unwrap();

        // Test the addresses against https://iancoleman.io/bip39/
        let (taddr, pk) = &wallet.get_t_secret_keys()[0];
        assert_eq!(taddr, "t1eQ63fwkQ4n4Eo5uCrPGaAV8FWB2tmx7ui");
        assert_eq!(pk, "Kz9ybX4giKag4NtnP1pi8WQF2B2hZDkFU85S7Dciz3UUhM59AnhE");

        let (zaddr, sk) = &wallet.get_z_private_keys()[0];
        assert_eq!(zaddr, "zs1q6xk3q783t5k92kjqt2rkuuww8pdw2euzy5rk6jytw97enx8fhpazdv3th4xe7vsk6e9sfpawfg");
        assert_eq!(sk, "secret-extended-key-main1qvpa0qr8qqqqpqxn4l054nzxpxzp3a8r2djc7sekdek5upce8mc2j2z0arzps4zv940qeg706hd0wq6g5snzvhp332y6vhwyukdn8dhekmmsk7fzvzkqm6ypc99uy63tpesqwxhpre78v06cx8k5xpp9mrhtgqs5dvp68cqx2yrvthflmm2ynl8c0506dekul0f6jkcdmh0292lpphrksyc5z3pxwws97zd5els3l2mjt2s7hntap27mlmt6w0drtfmz36vz8pgu7ec0twfrq");

        assert_eq!(seed_phrase, Some(wallet.get_seed_phrase()));
    }

    #[test]
    fn test_invalid_scan_blocks() {
        const AMOUNT: u64 = 500000;
        let (wallet, _txid1, block_hash) = get_test_wallet(AMOUNT);       

        let prev_hash = add_blocks(&wallet, 2, 1, block_hash).unwrap();
        assert_eq!(wallet.blocks.read().unwrap().len(), 3);
        
        // Block fails to scan for bad encoding
        assert_eq!(wallet.scan_block(&[0; 32]), Err(-1));

        // Block is invalid height
        let new_blk = FakeCompactBlock::new(4, prev_hash);
        assert_eq!(wallet.scan_block(&new_blk.as_bytes()), Err(2));

        // Block is right height, but invalid prev height (for reorgs)
        let new_blk = FakeCompactBlock::new(2, BlockHash([0; 32]));
        assert_eq!(wallet.scan_block(&new_blk.as_bytes()), Err(2));

        // Block is right height, but invalid prev height (for reorgs)
        let new_blk = FakeCompactBlock::new(3, BlockHash([0; 32]));
        assert_eq!(wallet.scan_block(&new_blk.as_bytes()), Err(2));

        // Then the rest add properly
        let _ = add_blocks(&wallet, 3, 2, prev_hash).unwrap();
        assert_eq!(wallet.blocks.read().unwrap().len(), 5);
    }
}