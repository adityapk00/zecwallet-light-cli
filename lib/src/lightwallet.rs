use std::time::{SystemTime, Duration};
use std::io::{self, Read, Write};
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::io::{Error, ErrorKind};
use std::convert::TryFrom;

use threadpool::ThreadPool;
use std::sync::mpsc::{channel};

use rand::{Rng, rngs::OsRng};
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};
use log::{info, warn, error};

use protobuf::parse_from_bytes;

use libflate::gzip::{Decoder};
use secp256k1::SecretKey;
use bip39::{Mnemonic, Language};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use pairing::bls12_381::{Bls12};
use sha2::{Sha256, Digest};

use sodiumoxide::crypto::secretbox;

use zcash_client_backend::{
    encoding::{encode_payment_address, encode_extended_spending_key, encode_extended_full_viewing_key, decode_extended_spending_key, decode_extended_full_viewing_key},
    proto::compact_formats::{CompactBlock, CompactOutput},
    wallet::{WalletShieldedOutput, WalletShieldedSpend}
};

use zcash_primitives::{
    jubjub::fs::Fs,
    block::BlockHash,
    serialize::{Vector},
    consensus::BranchId,
    transaction::{
        builder::{Builder},
        components::{Amount, OutPoint, TxOut}, components::amount::DEFAULT_FEE,
        TxId, Transaction, 
    },
    sapling::Node,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    legacy::{Script, TransparentAddress},
    note_encryption::{Memo, try_sapling_note_decryption, try_sapling_output_recovery, try_sapling_compact_note_decryption},
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey, ChildIndex},
    JUBJUB,
    primitives::{PaymentAddress},
};

use crate::lightclient::{LightClientConfig};

mod data;
mod extended_key;
mod utils;
mod address;
mod prover;
mod walletzkey;

use data::{BlockData, WalletTx, Utxo, SaplingNoteData, SpendableNote, OutgoingTxMetadata};
use extended_key::{KeyIndex, ExtendedPrivKey};
use walletzkey::{WalletZKey, WalletZKeyType};

pub const MAX_REORG: usize = 100;
pub const GAP_RULE_UNUSED_ADDRESSES: usize = 5;

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

pub struct LightWallet {
    // Is the wallet encrypted? If it is, then when writing to disk, the seed is always encrypted 
    // and the individual spending keys are not written    
    encrypted: bool,       

    // In memory only (i.e, this field is not written to disk). Is the wallet unlocked and are
    // the spending keys present to allow spending from this wallet?
    unlocked: bool,

    enc_seed: [u8; 48], // If locked, this contains the encrypted seed
    nonce: Vec<u8>,     // Nonce used to encrypt the wallet. 

    seed: [u8; 32],    // Seed phrase for this wallet. If wallet is locked, this is 0

    // List of keys, actually in this wallet. This is a combination of HD keys derived from the seed,
    // viewing keys and imported spending keys. 
    zkeys: Arc<RwLock<Vec<WalletZKey>>>,

    // Transparent keys. If the wallet is locked, then the secret keys will be encrypted,
    // but the addresses will be present. 
    tkeys: Arc<RwLock<Vec<secp256k1::SecretKey>>>,
    pub taddresses: Arc<RwLock<Vec<String>>>,

    blocks: Arc<RwLock<Vec<BlockData>>>,
    pub txs: Arc<RwLock<HashMap<TxId, WalletTx>>>,

    // Transactions that are only in the mempool, but haven't been confirmed yet. 
    // This is not stored to disk. 
    pub mempool_txs: Arc<RwLock<HashMap<TxId, WalletTx>>>,

    // The block at which this wallet was born. Rescans
    // will start from here.
    birthday: u64,

    // Non-serialized fields
    config: LightClientConfig,

    pub total_scan_duration: Arc<RwLock<Vec<Duration>>>,
}

impl LightWallet {
    pub fn serialized_version() -> u64 {
        return 8;
    }

    fn get_taddr_from_bip39seed(config: &LightClientConfig, bip39_seed: &[u8], pos: u32) -> SecretKey {
        assert_eq!(bip39_seed.len(), 64);

        let ext_t_key = ExtendedPrivKey::with_seed(bip39_seed).unwrap();
        ext_t_key
            .derive_private_key(KeyIndex::hardened_from_normalize_index(44).unwrap()).unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(config.get_coin_type()).unwrap()).unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(0).unwrap()).unwrap()
            .derive_private_key(KeyIndex::Normal(0)).unwrap()
            .derive_private_key(KeyIndex::Normal(pos)).unwrap()
            .private_key
    }


    fn get_zaddr_from_bip39seed(config: &LightClientConfig, bip39_seed: &[u8], pos: u32) ->
            (ExtendedSpendingKey, ExtendedFullViewingKey, PaymentAddress<Bls12>) {
        assert_eq!(bip39_seed.len(), 64);
        
        let extsk: ExtendedSpendingKey = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(bip39_seed),
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

    pub fn is_shielded_address(addr: &String, config: &LightClientConfig) -> bool {
        match address::RecipientAddress::from_str(addr,
                config.hrp_sapling_address(), 
                config.base58_pubkey_address(), 
                config.base58_script_address()) {
            Some(address::RecipientAddress::Shielded(_)) => true,
            _ => false,
        }                                    
    }

    pub fn new(seed_phrase: Option<String>, config: &LightClientConfig, latest_block: u64) -> io::Result<Self> {
        // This is the source entropy that corresponds to the 24-word seed phrase
        let mut seed_bytes = [0u8; 32];

        if seed_phrase.is_none() {
            // Create a random seed. 
            let mut system_rng = OsRng;
            system_rng.fill(&mut seed_bytes);
        } else {
            let phrase = match Mnemonic::from_phrase(seed_phrase.clone().unwrap(), Language::English) {
                Ok(p) => p,
                Err(e) => {
                    let e = format!("Error parsing phrase: {}", e);
                    error!("{}", e);
                    return Err(io::Error::new(ErrorKind::InvalidData, e));
                }
            };
            
            seed_bytes.copy_from_slice(&phrase.entropy());
        }

        // The seed bytes is the raw entropy. To pass it to HD wallet generation, 
        // we need to get the 64 byte bip39 entropy
        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&seed_bytes, Language::English).unwrap(), "");

        // Derive only the first sk and address
        let tpk = LightWallet::get_taddr_from_bip39seed(&config, &bip39_seed.as_bytes(), 0);
        let taddr = LightWallet::address_from_prefix_sk(&config.base58_pubkey_address(), &tpk);

        // TODO: We need to monitor addresses, and always keep 1 "free" address, so 
        // users can import a seed phrase and automatically get all used addresses
        let hdkey_num = 0;
        let (extsk, _, _)
            = LightWallet::get_zaddr_from_bip39seed(&config, &bip39_seed.as_bytes(), hdkey_num);

        let lw = LightWallet {
            encrypted:   false,
            unlocked:    true,
            enc_seed:    [0u8; 48],
            nonce:       vec![],
            seed:        seed_bytes,
            zkeys:       Arc::new(RwLock::new(vec![WalletZKey::new_hdkey(hdkey_num, extsk)])),
            tkeys:       Arc::new(RwLock::new(vec![tpk])),
            taddresses:  Arc::new(RwLock::new(vec![taddr])),
            blocks:      Arc::new(RwLock::new(vec![])),
            txs:         Arc::new(RwLock::new(HashMap::new())),
            mempool_txs: Arc::new(RwLock::new(HashMap::new())),
            config:      config.clone(),
            birthday:    latest_block,
            total_scan_duration: Arc::new(RwLock::new(vec![Duration::new(0, 0)]))
        };

        // If restoring from seed, make sure we are creating 5 addresses for users
        if seed_phrase.is_some() {
            for _i in 0..5 {
                lw.add_taddr();
                lw.add_zaddr();
            }
        }

        Ok(lw)
    }

    pub fn read<R: Read>(mut inp: R, config: &LightClientConfig) -> io::Result<Self> {
        let version = inp.read_u64::<LittleEndian>()?;
        if version > LightWallet::serialized_version() {
            let e = format!("Don't know how to read wallet version {}. Do you have the latest version?", version);
            error!("{}", e);
            return Err(io::Error::new(ErrorKind::InvalidData, e));
        }

        println!("Reading wallet version {}", version);
        info!("Reading wallet version {}", version);
        
        // At version 5, we're writing the rest of the file as a compressed stream (gzip)
        let mut reader: Box<dyn Read> = if version != 5 {
            info!("Reading direct");
            Box::new(inp)
        } else {
            info!("Reading libflat");
            Box::new(Decoder::new(inp).unwrap())
        };

        let encrypted = if version >= 4 {
            reader.read_u8()? > 0
        } else {
            false
        };
        info!("Wallet Encryption {:?}", encrypted);
        
        let mut enc_seed = [0u8; 48];
        if version >= 4 {
            reader.read_exact(&mut enc_seed)?;
        }
        
        let nonce = if version >= 4 {
            Vector::read(&mut reader, |r| r.read_u8())?
        } else {
            vec![]
        };

        // Seed
        let mut seed_bytes = [0u8; 32];
        reader.read_exact(&mut seed_bytes)?;
        
        let zkeys = if version <= 6 {
            // Up until version 6, the wallet keys were written out individually
            // Read the spending keys
            let extsks = Vector::read(&mut reader, |r| ExtendedSpendingKey::read(r))?;
                    
            let extfvks = if version >= 4 {
                // Read the viewing keys
                Vector::read(&mut reader, |r| ExtendedFullViewingKey::read(r))?
            } else {
                // Calculate the viewing keys
                extsks.iter().map(|sk| ExtendedFullViewingKey::from(sk))
                    .collect::<Vec<ExtendedFullViewingKey>>()
            };

            // Calculate the addresses
            let addresses = extfvks.iter().map( |fvk| fvk.default_address().unwrap().1 )
                .collect::<Vec<PaymentAddress<Bls12>>>();
            
            // If extsks is of len 0, then this wallet is locked
            let zkeys_result = if extsks.len() == 0 {
                // Wallet is locked, so read only the viewing keys.
                extfvks.iter().zip(addresses.iter()).enumerate().map(|(i, (extfvk, payment_address))| {
                let zk = WalletZKey::new_locked_hdkey(i as u32, extfvk.clone());
                if zk.zaddress != *payment_address {
                    Err(io::Error::new(ErrorKind::InvalidData, "Payment address didn't match"))
                } else {
                    Ok(zk)
                }
                }).collect::<Vec<io::Result<WalletZKey>>>()
            } else {
                // Wallet is unlocked, read the spending keys as well
                extsks.into_iter().zip(extfvks.into_iter().zip(addresses.iter())).enumerate()
                .map(|(i, (extsk, (extfvk, payment_address)))| {
                    let zk = WalletZKey::new_hdkey(i as u32, extsk);
                    if zk.zaddress != *payment_address {
                    return Err(io::Error::new(ErrorKind::InvalidData, "Payment address didn't match"));
                    } 
                    
                    if zk.extfvk != extfvk {
                    return Err(io::Error::new(ErrorKind::InvalidData, "Full View key didn't match"));
                    }

                    Ok(zk)
                }).collect::<Vec<io::Result<WalletZKey>>>()
            };

            // Convert vector of results into result of vector, returning an error if any one of the keys failed the checks above
            zkeys_result.into_iter().collect::<io::Result<_>>()?
        }  else {
            // After version 6, we read the WalletZKey structs directly
            Vector::read(&mut reader, |r| WalletZKey::read(r))?
        };
        
        let tkeys = Vector::read(&mut reader, |r| {
            let mut tpk_bytes = [0u8; 32];
            r.read_exact(&mut tpk_bytes)?;
            secp256k1::SecretKey::from_slice(&tpk_bytes).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
        })?;      
        
        let taddresses = if version >= 4 {
            // Read the addresses
            Vector::read(&mut reader, |r| utils::read_string(r))?
        } else {
            // Calculate the addresses
            tkeys.iter().map(|sk| LightWallet::address_from_prefix_sk(&config.base58_pubkey_address(), sk)).collect()
        };
        
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

        let lw = LightWallet{
            encrypted:   encrypted,
            unlocked:    !encrypted, // When reading from disk, if wallet is encrypted, it starts off locked. 
            enc_seed:    enc_seed,
            nonce:       nonce,
            seed:        seed_bytes,
            zkeys:       Arc::new(RwLock::new(zkeys)),
            tkeys:       Arc::new(RwLock::new(tkeys)),
            taddresses:  Arc::new(RwLock::new(taddresses)),
            blocks:      Arc::new(RwLock::new(blocks)),
            txs:         Arc::new(RwLock::new(txs)),
            mempool_txs: Arc::new(RwLock::new(HashMap::new())),
            config:      config.clone(),
            birthday,
            total_scan_duration: Arc::new(RwLock::new(vec![Duration::new(0, 0)])),
        };

        // Do a one-time fix of the spent_at_height for older wallets
        if version <= 7 {
            lw.fix_spent_at_height();
        }

        Ok(lw)
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.encrypted && self.unlocked {
            return Err(Error::new(ErrorKind::InvalidInput, 
                        format!("Cannot write while wallet is unlocked while encrypted.")));
        }

        // Write the version
        writer.write_u64::<LittleEndian>(LightWallet::serialized_version())?;

        // Write if it is locked
        writer.write_u8(if self.encrypted {1} else {0})?;

        // Write the encrypted seed bytes
        writer.write_all(&self.enc_seed)?;

        // Write the nonce
        Vector::write(&mut writer, &self.nonce, |w, b| w.write_u8(*b))?;

        // Write the seed
        writer.write_all(&self.seed)?;

        // Flush after writing the seed, so in case of a disaster, we can still recover the seed.
        writer.flush()?;

        // Write all the wallet's keys
        Vector::write(&mut writer, &self.zkeys.read().unwrap(),
             |w, zk| zk.write(w)
        )?;

        // Write the transparent private keys
        Vector::write(&mut writer, &self.tkeys.read().unwrap(),
            |w, pk| w.write_all(&pk[..])
        )?;

        // Write the transparent addresses
        Vector::write(&mut writer, &self.taddresses.read().unwrap(),
            |w, a| utils::write_string(w, a)
        )?;

        Vector::write(&mut writer, &self.blocks.read().unwrap(), |w, b| b.write(w))?;
                
        // The hashmap, write as a set of tuples. Store them sorted so that wallets are
        // deterministically saved
        {
            let txlist = self.txs.read().unwrap();
            let mut txns = txlist.iter().collect::<Vec<(&TxId, &WalletTx)>>();
            txns.sort_by(|a, b| a.0.partial_cmp(b.0).unwrap());

            Vector::write(&mut writer, &txns,
                            |w, (k, v)| {
                                w.write_all(&k.0)?;
                                v.write(w)
                            })?;
        }
        utils::write_string(&mut writer, &self.config.chain_name)?;

        // While writing the birthday, get it from the fn so we recalculate it properly
        // in case of rescans etc...
        writer.write_u64::<LittleEndian>(self.get_birthday())
    }

    pub fn note_address(hrp: &str, note: &SaplingNoteData) -> Option<String> {
        match note.extfvk.fvk.vk.to_payment_address(note.diversifier, &JUBJUB) {
            Some(pa) => Some(encode_payment_address(hrp, &pa)),
            None     => None
        }
    }

    pub fn get_birthday(&self) -> u64 {
        if self.birthday == 0 {
            self.get_first_tx_block()
        } else {
            cmp::min(self.get_first_tx_block(), self.birthday)
        }
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

        *blocks.first() // Returns optional, so if there's no txns, it'll get the activation height
            .unwrap_or(&cmp::max(self.birthday, self.config.sapling_activation_height))
    }

    // Get all z-address private keys. Returns a Vector of (address, privatekey, viewkey)
    pub fn get_z_private_keys(&self) -> Vec<(String, String, String)> {
        let keys = self.zkeys.read().unwrap().iter().map(|k| {
            let pkey = match k.extsk.clone().map(|extsk| encode_extended_spending_key(self.config.hrp_sapling_private_key(), &extsk)) {
                Some(pk) => pk,
                None => "".to_string()
            };

            let vkey = encode_extended_full_viewing_key(self.config.hrp_sapling_viewing_key(), &k.extfvk);

            (encode_payment_address(self.config.hrp_sapling_address(),&k.zaddress), pkey, vkey)
        }).collect::<Vec<(String, String, String)>>();

        keys
    }

    /// Get all t-address private keys. Returns a Vector of (address, secretkey)
    pub fn get_t_secret_keys(&self) -> Vec<(String, String)> {
        self.tkeys.read().unwrap().iter().map(|sk| {
            (self.address_from_sk(sk), 
             sk[..].to_base58check(&self.config.base58_secretkey_prefix(), &[0x01]))
        }).collect::<Vec<(String, String)>>()
    }

    /// Adds a new z address to the wallet. This will derive a new address from the seed
    /// at the next position and add it to the wallet.
    /// NOTE: This does NOT rescan
    pub fn add_zaddr(&self) -> String {
        if !self.unlocked {
            return "Error: Can't add key while wallet is locked".to_string();
        }

        // Find the highest pos we have
        let pos = self.zkeys.read().unwrap().iter()
            .filter(|zk| zk.hdkey_num.is_some())
            .max_by(|zk1, zk2| zk1.hdkey_num.unwrap().cmp(&zk2.hdkey_num.unwrap()))
            .map_or(0, |zk| zk.hdkey_num.unwrap() + 1);

        
        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&self.seed, Language::English).unwrap(), "");

        let (extsk, _, _) =
            LightWallet::get_zaddr_from_bip39seed(&self.config, &bip39_seed.as_bytes(), pos);

        // let zaddr = encode_payment_address(self.config.hrp_sapling_address(), &address);
        let newkey = WalletZKey::new_hdkey(pos, extsk);
        self.zkeys.write().unwrap().push(newkey.clone());

        encode_payment_address(self.config.hrp_sapling_address(), &newkey.zaddress)
    }

    /// Add a new t address to the wallet. This will derive a new address from the seed
    /// at the next position.
    /// NOTE: This will not rescan the wallet
    pub fn add_taddr(&self) -> String {
        if !self.unlocked {
            return "Error: Can't add key while wallet is locked".to_string();
        }

        let pos = self.tkeys.read().unwrap().len() as u32;
        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&self.seed, Language::English).unwrap(), "");
        
        let sk = LightWallet::get_taddr_from_bip39seed(&self.config, &bip39_seed.as_bytes(), pos);
        let address = self.address_from_sk(&sk);

        self.tkeys.write().unwrap().push(sk);
        self.taddresses.write().unwrap().push(address.clone());

        address
    }

    // Add a new imported spending key to the wallet
    /// NOTE: This will not rescan the wallet
    pub fn add_imported_sk(&mut self, sk: String, birthday: u64) -> String {
        if self.encrypted {
            return "Error: Can't import spending key while wallet is encrypted".to_string();
        }

        // First, try to interpret the key
        let extsk = match decode_extended_spending_key(self.config.hrp_sapling_private_key(), &sk) {
            Ok(Some(k)) => k,
            Ok(None) => return format!("Error: Couldn't decode spending key"),
            Err(e) => return format!("Error importing spending key: {}", e)
        };

        // Make sure the key doesn't already exist
        if self.zkeys.read().unwrap().iter().find(|&wk| wk.extsk.is_some() && wk.extsk.as_ref().unwrap() == &extsk.clone()).is_some() {
            return "Error: Key already exists".to_string();
        }
        
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let zaddress = {
            let mut zkeys = self.zkeys.write().unwrap();
            let maybe_existing_zkey = zkeys.iter_mut().find(|wk| wk.extfvk == extfvk);
        
            // If the viewing key exists, and is now being upgraded to the spending key, replace it in-place
            if maybe_existing_zkey.is_some() {
                let mut existing_zkey = maybe_existing_zkey.unwrap();
                existing_zkey.extsk = Some(extsk);
                existing_zkey.keytype = WalletZKeyType::ImportedSpendingKey;
                existing_zkey.zaddress.clone()
            } else {
                let newkey = WalletZKey::new_imported_sk(extsk);
                zkeys.push(newkey.clone());
                newkey.zaddress
            }
        };

        // Adjust wallet birthday
        if birthday < self.birthday {
            self.birthday = if birthday < self.config.sapling_activation_height {self.config.sapling_activation_height} else {birthday};
        }

        encode_payment_address(self.config.hrp_sapling_address(), &zaddress)
    }

    // Add a new imported viewing key to the wallet
    /// NOTE: This will not rescan the wallet
    pub fn add_imported_vk(&mut self, vk: String, birthday: u64) -> String {
        if !self.unlocked {
            return "Error: Can't add key while wallet is locked".to_string();
        }

        // First, try to interpret the key
        let extfvk = match decode_extended_full_viewing_key(self.config.hrp_sapling_viewing_key(), &vk) {
            Ok(Some(k)) => k,
            Ok(None) => return format!("Error: Couldn't decode viewing key"),
            Err(e) => return format!("Error importing viewing key: {}", e)
        };

        // Make sure the key doesn't already exist
        if self.zkeys.read().unwrap().iter().find(|wk| wk.extfvk == extfvk.clone()).is_some() {
            return "Error: Key already exists".to_string();
        }

        let newkey = WalletZKey::new_imported_viewkey(extfvk);
        self.zkeys.write().unwrap().push(newkey.clone());

        // Adjust wallet birthday
        if birthday < self.birthday {
            self.birthday = if birthday < self.config.sapling_activation_height {self.config.sapling_activation_height} else {birthday};
        }

        encode_payment_address(self.config.hrp_sapling_address(), &newkey.zaddress)
    }

    /// Clears all the downloaded blocks and resets the state back to the initial block.
    /// After this, the wallet's initial state will need to be set
    /// and the wallet will need to be rescanned
    pub fn clear_blocks(&self) {
        self.blocks.write().unwrap().clear();
        self.txs.write().unwrap().clear();
        self.mempool_txs.write().unwrap().clear();
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

    /// Get the height of the anchor block
    pub fn get_anchor_height(&self) -> u32 {
        match self.get_target_height_and_anchor_offset() {
            Some((height, anchor_offset)) => height - anchor_offset as u32 - 1,
            None => return 0,
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

    pub fn get_all_zaddresses(&self) -> Vec<String> {
        self.zkeys.read().unwrap().iter().map( |zk| {
            encode_payment_address(self.config.hrp_sapling_address(), &zk.zaddress)
        }).collect()
    }

    pub fn address_from_prefix_sk(prefix: &[u8; 2], sk: &secp256k1::SecretKey) -> String {
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        // Encode into t address
        let mut hash160 = ripemd160::Ripemd160::new();
        hash160.input(Sha256::digest(&pk.serialize()[..].to_vec()));

        hash160.result().to_base58check(prefix, &[])
    }

    pub fn address_from_sk(&self, sk: &secp256k1::SecretKey) -> String {
        LightWallet::address_from_prefix_sk(&self.config.base58_pubkey_address(), sk)
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
        if !self.unlocked {
            return "".to_string();
        }

        Mnemonic::from_entropy(&self.seed, 
                                Language::English,
        ).unwrap().phrase().to_string()
    }

    pub fn encrypt(&mut self, passwd: String) -> io::Result<()> {
        if self.encrypted {
            return Err(io::Error::new(ErrorKind::AlreadyExists, "Wallet is already encrypted"));
        }

        // Get the doublesha256 of the password, which is the right length
        let key = secretbox::Key::from_slice(&double_sha256(passwd.as_bytes())).unwrap();
        let nonce = secretbox::gen_nonce();

        let cipher = secretbox::seal(&self.seed, &nonce, &key);
        
        self.enc_seed.copy_from_slice(&cipher);
        self.nonce = nonce.as_ref().to_vec();

        // Encrypt the individual keys
        self.zkeys.write().unwrap().iter_mut()
            .map(|k| k.encrypt(&key))
            .collect::<io::Result<Vec<()>>>()?;

        self.encrypted = true;
        self.lock()?;

        Ok(())
    }

    pub fn lock(&mut self) -> io::Result<()> {
        if !self.encrypted {
            return Err(io::Error::new(ErrorKind::AlreadyExists, "Wallet is not encrypted"));
        }

        if !self.unlocked {
            return Err(io::Error::new(ErrorKind::AlreadyExists, "Wallet is already locked"));
        }

        // Empty the seed and the secret keys
        self.seed.copy_from_slice(&[0u8; 32]);
        self.tkeys = Arc::new(RwLock::new(vec![]));

        // Remove all the private key from the zkeys
        self.zkeys.write().unwrap().iter_mut().map(|zk| {
            zk.lock()
        }).collect::<io::Result<Vec<_>>>()?;
        
        self.unlocked = false;

        Ok(())
    }

    pub fn unlock(&mut self, passwd: String) -> io::Result<()> {
        if !self.encrypted {
            return Err(Error::new(ErrorKind::AlreadyExists, "Wallet is not encrypted"));
        }

        if self.encrypted && self.unlocked {
            return Err(Error::new(ErrorKind::AlreadyExists, "Wallet is already unlocked"));
        }

        // Get the doublesha256 of the password, which is the right length
        let key = secretbox::Key::from_slice(&double_sha256(passwd.as_bytes())).unwrap();
        let nonce = secretbox::Nonce::from_slice(&self.nonce).unwrap();

        let seed = match secretbox::open(&self.enc_seed, &nonce, &key) {
            Ok(s) => s,
            Err(_) => {return Err(io::Error::new(ErrorKind::InvalidData, "Decryption failed. Is your password correct?"));}
        };

        // Now that we have the seed, we'll generate the extsks and tkeys, and verify the fvks and addresses
        // respectively match

        // The seed bytes is the raw entropy. To pass it to HD wallet generation, 
        // we need to get the 64 byte bip39 entropy
        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&seed, Language::English).unwrap(), "");

        // Transparent keys
        let mut tkeys = vec![];
        for pos in 0..self.taddresses.read().unwrap().len() {
            let sk = LightWallet::get_taddr_from_bip39seed(&self.config, &bip39_seed.as_bytes(), pos as u32);
            let address = self.address_from_sk(&sk);

            if address != self.taddresses.read().unwrap()[pos] {
                return Err(io::Error::new(ErrorKind::InvalidData, 
                    format!("taddress mismatch at {}. {} vs {}", pos, address, self.taddresses.read().unwrap()[pos])));
            }

            tkeys.push(sk);
        }

        // Go over the zkeys, and add the spending keys again
        self.zkeys.write().unwrap().iter_mut().map(|zk| {
            zk.unlock(&self.config, bip39_seed.as_bytes(), &key)
        }).collect::<io::Result<Vec<()>>>()?;
        
        // Everything checks out, so we'll update our wallet with the decrypted values
        self.tkeys = Arc::new(RwLock::new(tkeys));
        self.seed.copy_from_slice(&seed);
                
        self.encrypted = true;
        self.unlocked = true;

        Ok(())
    }

    // Removing encryption means unlocking it and setting the self.encrypted = false,
    // permanantly removing the encryption
    pub fn remove_encryption(&mut self, passwd: String) -> io::Result<()> {        
        if !self.encrypted {
            return Err(Error::new(ErrorKind::AlreadyExists, "Wallet is not encrypted"));
        }

        // Unlock the wallet if it's locked
        if !self.unlocked {
            self.unlock(passwd)?;
        }

        // Remove encryption from individual zkeys
        self.zkeys.write().unwrap().iter_mut().map(|zk| {
            zk.remove_encryption()
        }).collect::<io::Result<Vec<()>>>()?;
          
        // Permanantly remove the encryption
        self.encrypted = false;
        self.nonce = vec![];
        self.enc_seed.copy_from_slice(&[0u8; 48]);

        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        return self.encrypted;
    }

    pub fn is_unlocked_for_spending(&self) -> bool {
        return self.unlocked;
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
                                                    .to_payment_address(nd.diversifier, &JUBJUB).unwrap()
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
            Some((height, anchor_offset)) => height - anchor_offset as u32 - 1,
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
                        .filter(|nd| nd.spent.is_none() && nd.unconfirmed_spent.is_none())
                        .filter(|nd| {  // TODO, this whole section is shared with verified_balance. Refactor it. 
                            match addr.clone() {
                                Some(a) => a == encode_payment_address(
                                                    self.config.hrp_sapling_address(),
                                                    &nd.extfvk.fvk.vk
                                                        .to_payment_address(nd.diversifier, &JUBJUB).unwrap()
                                                ),
                                None    => true
                            }
                        })
                        .map(|nd| nd.note.value)
                        .sum::<u64>()
                } else {
                    0
                }
            })
            .sum::<u64>()
    }

    pub fn spendable_zbalance(&self, addr: Option<String>) -> u64 {
        let anchor_height = self.get_anchor_height();

        self.txs
            .read()
            .unwrap()
            .values()
            .map(|tx| {
                if tx.block as u32 <= anchor_height {
                    tx.notes
                        .iter()
                        .filter(|nd| nd.spent.is_none() && nd.unconfirmed_spent.is_none())
                        .filter(|nd| {
                            // Check to see if we have this note's spending key.
                            match self.zkeys.read().unwrap().iter().find(|zk| zk.extfvk == nd.extfvk) {
                                Some(zk) => zk.keytype == WalletZKeyType::HdKey || zk.keytype == WalletZKeyType::ImportedSpendingKey,
                                _ => false
                            }
                        })
                        .filter(|nd| {  // TODO, this whole section is shared with verified_balance. Refactor it. 
                            match addr.clone() {
                                Some(a) => a == encode_payment_address(
                                                    self.config.hrp_sapling_address(),
                                                    &nd.extfvk.fvk.vk
                                                        .to_payment_address(nd.diversifier, &JUBJUB).unwrap()
                                                ),
                                None    => true
                            }
                        })
                        .map(|nd| nd.note.value)
                        .sum::<u64>()
                } else {
                    0
                }
            })
            .sum::<u64>()
    }

    fn add_toutput_to_wtx(&self, height: i32, timestamp: u64, txid: &TxId, vout: &TxOut, n: u64) {
        let mut txs = self.txs.write().unwrap();

        // Find the existing transaction entry, or create a new one.
        if !txs.contains_key(&txid) {
            let tx_entry = WalletTx::new(height, timestamp, &txid);
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

    // If one of the last 'n' taddress was used, ensure we add the next HD taddress to the wallet. 
    pub fn ensure_hd_taddresses(&self, address: &String) {        
        let last_addresses = {
            self.taddresses.read().unwrap().iter().rev().take(GAP_RULE_UNUSED_ADDRESSES).map(|s| s.clone()).collect::<Vec<String>>()
        };
        
        match last_addresses.iter().position(|s| *s == *address) {
            None => {                
                return;
            },
            Some(pos) => {
                info!("Adding {} new zaddrs", (GAP_RULE_UNUSED_ADDRESSES - pos));
                // If it in the last unused, addresses, create that many more
                for _ in 0..(GAP_RULE_UNUSED_ADDRESSES - pos) {
                    // If the wallet is locked, this is a no-op. That is fine, since we really
                    // need to only add new addresses when restoring a new wallet, when it will not be locked.
                    // Also, if it is locked, the user can't create new addresses anyway. 
                    self.add_taddr();
                }
            }
        }
    }

    // If one of the last 'n' zaddress was used, ensure we add the next HD zaddress to the wallet
    pub fn ensure_hd_zaddresses(&self, address: &String) {
        let last_addresses = {
            self.zkeys.read().unwrap().iter()
                .filter(|zk| zk.keytype == WalletZKeyType::HdKey)
                .rev()
                .take(GAP_RULE_UNUSED_ADDRESSES)
                .map(|s| encode_payment_address(self.config.hrp_sapling_address(), &s.zaddress))
                .collect::<Vec<String>>()
        };
        
        match last_addresses.iter().position(|s| *s == *address) {
            None => {
                return;
            },
            Some(pos) => {
                info!("Adding {} new zaddrs", (GAP_RULE_UNUSED_ADDRESSES - pos));
                // If it in the last unused, addresses, create that many more
                for _ in 0..(GAP_RULE_UNUSED_ADDRESSES - pos) {
                    // If the wallet is locked, this is a no-op. That is fine, since we really
                    // need to only add new addresses when restoring a new wallet, when it will not be locked.
                    // Also, if it is locked, the user can't create new addresses anyway. 
                    self.add_zaddr();
                }
            }
        }
    }

    // Scan the full Tx and update memos for incoming shielded transactions.
    pub fn scan_full_tx(&self, tx: &Transaction, height: i32, datetime: u64) {
        let mut total_transparent_spend: u64 = 0;

        // Scan all the inputs to see if we spent any transparent funds in this tx
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
                let tx_entry = WalletTx::new(height, datetime, &tx.txid());
                txs.insert(tx.txid().clone(), tx_entry);
            }
            
            txs.get_mut(&tx.txid()).unwrap()
                .total_transparent_value_spent = total_transparent_spend;
        }

        // Scan for t outputs
        let all_taddresses = self.taddresses.read().unwrap().iter()
                                .map(|a| a.clone())
                                .collect::<Vec<_>>();
        for address in all_taddresses {
            for (n, vout) in tx.vout.iter().enumerate() {
                match vout.script_pubkey.address() {
                    Some(TransparentAddress::PublicKey(hash)) => {
                        if address == hash.to_base58check(&self.config.base58_pubkey_address(), &[]) {
                            // This is our address. Add this as an output to the txid
                            self.add_toutput_to_wtx(height, datetime, &tx.txid(), &vout, n as u64);

                            // Ensure that we add any new HD addresses
                            self.ensure_hd_taddresses(&address);
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
                let wallet_taddrs = self.taddresses.read().unwrap().iter()
                        .map(|a| a.clone())
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
            let ivks: Vec<_> = self.zkeys.read().unwrap().iter()
                .map(|zk| zk.extfvk.fvk.vk.ivk()
                ).collect();

            let cmu = output.cmu;
            let ct  = output.enc_ciphertext;

            // Search all of our keys
            for ivk in ivks {
                let epk_prime = output.ephemeral_key.as_prime_order(&JUBJUB).unwrap();

                let (note, _to, memo) = match try_sapling_note_decryption(&ivk, &epk_prime, &cmu, &ct) {
                    Some(ret) => ret,
                    None => continue,
                };
   
                info!("A sapling note was sent to wallet in {}", tx.txid());
                
                // Do it in a short scope because of the write lock.   
                let mut txs = self.txs.write().unwrap();

                // Update memo if we have this Tx. 
                match txs.get_mut(&tx.txid())
                    .and_then(|t| {
                        t.notes.iter_mut().find(|nd| nd.note == note)
                    }) {
                        None => {
                            info!("No txid matched for incoming sapling funds while updating memo"); 
                            ()
                        },
                        Some(nd) => {
                            nd.memo = Some(memo)
                        }
                    }
            }

            // Also scan the output to see if it can be decoded with our OutgoingViewKey
            // If it can, then we sent this transaction, so we should be able to get
            // the memo and value for our records

            // First, collect all our z addresses, to check for change
            // Collect z addresses
            let z_addresses = self.zkeys.read().unwrap().iter().map( |zk| {
                encode_payment_address(self.config.hrp_sapling_address(), &zk.zaddress)
            }).collect::<HashSet<String>>();

            // Search all ovks that we have
            let ovks: Vec<_> = self.zkeys.read().unwrap().iter()
                .map(|zk| zk.extfvk.fvk.ovk.clone())
                .collect();

            for ovk in ovks {
                match try_sapling_output_recovery(
                    &ovk,
                    &output.cv, 
                    &output.cmu, 
                    &output.ephemeral_key.as_prime_order(&JUBJUB).unwrap(), 
                    &output.enc_ciphertext,
                    &output.out_ciphertext) {
                        Some((note, payment_address, memo)) => {
                            let address = encode_payment_address(self.config.hrp_sapling_address(), 
                                            &payment_address);

                            // Check if this is change, and if it also doesn't have a memo, don't add 
                            // to the outgoing metadata. 
                            // If this is change (i.e., funds sent to ourself) AND has a memo, then
                            // presumably the users is writing a memo to themself, so we will add it to 
                            // the outgoing metadata, even though it might be confusing in the UI, but hopefully
                            // the user can make sense of it. 
                            if z_addresses.contains(&address) && memo.to_utf8().is_none() {
                                continue;
                            }

                            // Update the WalletTx 
                            // Do it in a short scope because of the write lock.
                            {
                                info!("A sapling output was sent in {}", tx.txid());

                                let mut txs = self.txs.write().unwrap();
                                if txs.get(&tx.txid()).unwrap().outgoing_metadata.iter()
                                        .find(|om| om.address == address && om.value == note.value && om.memo == memo)
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
            match txs.get_mut(&tx.txid()) {
                Some(wtx) => wtx.full_tx_scanned = true,
                None => {},
            };
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

        // Next, remove entire transactions
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

        // Of the notes that still remain, unroll the witness.
        // Remove `num_invalidated` items from the witness
        {
            let mut txs = self.txs.write().unwrap();

            // Trim all witnesses for the invalidated blocks
            for tx in txs.values_mut() {
                for nd in tx.notes.iter_mut() {
                    let _discard = nd.witnesses.split_off(nd.witnesses.len().saturating_sub(num_invalidated));
                }
            }
        }
        
        num_invalidated as u64
    }

    /// Scans a [`CompactOutput`] with a set of [`ExtendedFullViewingKey`]s.
    ///
    /// Returns a [`WalletShieldedOutput`] and corresponding [`IncrementalWitness`] if this
    /// output belongs to any of the given [`ExtendedFullViewingKey`]s.
    ///
    /// The given [`CommitmentTree`] and existing [`IncrementalWitness`]es are incremented
    /// with this output's commitment.
    fn scan_output_internal(
        &self,
        (index, output): (usize, CompactOutput),
        ivks: &[Fs],
        tree: &mut CommitmentTree<Node>,
        existing_witnesses: &mut [&mut IncrementalWitness<Node>],
        block_witnesses: &mut [&mut IncrementalWitness<Node>],
        new_witnesses: &mut [&mut IncrementalWitness<Node>],
        pool: &ThreadPool
    ) -> Option<WalletShieldedOutput> {
        let cmu = output.cmu().ok()?;
        let epk = output.epk().ok()?;
        let ct = output.ciphertext;

        let (tx, rx) = channel();
        ivks.iter().enumerate().for_each(|(account, ivk)| {
            // Clone all values for passing to the closure
            let ivk = ivk.clone();
            let epk = epk.clone();
            let ct = ct.clone();
            let tx = tx.clone();

            pool.execute(move || {
                let m = try_sapling_compact_note_decryption(&ivk, &epk, &cmu, &ct);
                let r = match m {
                    Some((note, to)) => {
                        tx.send(Some(Some((note, to, account))))
                    },
                    None => {
                        tx.send(Some(None))
                    }
                };
                
                match r {
                    Ok(_) => {},
                    Err(e) => println!("Send error {:?}", e)
                }
            });
        });

        // Increment tree and witnesses
        let node = Node::new(cmu.into());
        for witness in existing_witnesses {
            witness.append(node).unwrap();
        }
        for witness in block_witnesses {
            witness.append(node).unwrap();
        }
        for witness in new_witnesses {
            witness.append(node).unwrap();
        }
        tree.append(node).unwrap();

        // Collect all the RXs and fine if there was a valid result somewhere
        let mut wsos =  vec![];
        for _i in 0..ivks.len() {
            let n = rx.recv().unwrap();
            let epk = epk.clone();
            
            let wso = match n {
                None => panic!("Got a none!"),
                Some(None) => None,
                Some(Some((note, to, account))) => {
                    // A note is marked as "change" if the account that received it
                    // also spent notes in the same transaction. This will catch,
                    // for instance:
                    // - Change created by spending fractions of notes.
                    // - Notes created by consolidation transactions.
                    // - Notes sent from one account to itself.
                    //let is_change = spent_from_accounts.contains(&account);
                    
                    Some(WalletShieldedOutput {
                        index, cmu, epk, account, note, to, is_change: false,
                        witness: IncrementalWitness::from_tree(tree),
                    })
                }
            };
            wsos.push(wso);
        }
        
        match wsos.into_iter().find(|wso| wso.is_some()) {
            Some(Some(wso)) => Some(wso),
            _ => None
        }
    }

    /// Scans a [`CompactBlock`] with a set of [`ExtendedFullViewingKey`]s.
    ///
    /// Returns a vector of [`WalletTx`]s belonging to any of the given
    /// [`ExtendedFullViewingKey`]s, and the corresponding new [`IncrementalWitness`]es.
    ///
    /// The given [`CommitmentTree`] and existing [`IncrementalWitness`]es are
    /// incremented appropriately.
    pub fn scan_block_internal(
        &self,
        block: CompactBlock,
        extfvks: &[ExtendedFullViewingKey],
        nullifiers: Vec<(Vec<u8>, usize)>,
        tree: &mut CommitmentTree<Node>,
        existing_witnesses: &mut [&mut IncrementalWitness<Node>],
        pool: &ThreadPool
    ) -> Vec<zcash_client_backend::wallet::WalletTx> {
        let mut wtxs: Vec<zcash_client_backend::wallet::WalletTx> = vec![];
        let ivks = extfvks.iter().map(|extfvk| extfvk.fvk.vk.ivk()).collect::<Vec<_>>();

        for tx in block.vtx.into_iter() {
            let num_spends = tx.spends.len();
            let num_outputs = tx.outputs.len();

            let (ctx, crx) = channel();
            {
                let nullifiers = nullifiers.clone();
                let tx = tx.clone();
                pool.execute(move || {
                    // Check for spent notes
                    // The only step that is not constant-time is the filter() at the end.
                    let shielded_spends: Vec<_> = tx
                        .spends
                        .into_iter()
                        .enumerate()
                        .map(|(index, spend)| {
                            // Find the first tracked nullifier that matches this spend, and produce
                            // a WalletShieldedSpend if there is a match, in constant time.
                            nullifiers
                                .iter()
                                .map(|(nf, account)| CtOption::new(*account as u64, nf.ct_eq(&spend.nf[..])))
                                .fold(CtOption::new(0, 0.into()), |first, next| {
                                    CtOption::conditional_select(&next, &first, first.is_some())
                                })
                                .map(|account| WalletShieldedSpend {
                                    index,
                                    nf: spend.nf,
                                    account: account as usize,
                                })
                        })
                        .filter(|spend| spend.is_some().into())
                        .map(|spend| spend.unwrap())
                        .collect();

                    // Collect the set of accounts that were spent from in this transaction
                    let spent_from_accounts: HashSet<_> =
                        shielded_spends.iter().map(|spend| spend.account).collect();

                    ctx.send((shielded_spends, spent_from_accounts)).unwrap();

                    drop(ctx);
                });
            }


            // Check for incoming notes while incrementing tree and witnesses
            let mut shielded_outputs: Vec<WalletShieldedOutput> = vec![];
            {
                // Grab mutable references to new witnesses from previous transactions
                // in this block so that we can update them. Scoped so we don't hold
                // mutable references to wtxs for too long.
                let mut block_witnesses: Vec<_> = wtxs
                    .iter_mut()
                    .map(|tx| {
                        tx.shielded_outputs
                            .iter_mut()
                            .map(|output| &mut output.witness)
                    })
                    .flatten()
                    .collect();

                for to_scan in tx.outputs.into_iter().enumerate() {
                    // Grab mutable references to new witnesses from previous outputs
                    // in this transaction so that we can update them. Scoped so we
                    // don't hold mutable references to shielded_outputs for too long.
                    let mut new_witnesses: Vec<_> = shielded_outputs
                        .iter_mut()
                        .map(|output| &mut output.witness)
                        .collect();

                    if let Some(output) = self.scan_output_internal(
                        to_scan,
                        &ivks,
                        tree,
                        existing_witnesses,
                        &mut block_witnesses,
                        &mut new_witnesses,
                        pool
                    ) {
                        shielded_outputs.push(output);
                    }
                }
            }

            let (shielded_spends, spent_from_accounts) = crx.recv().unwrap();

            // Identify change outputs
            shielded_outputs.iter_mut().for_each(|output| {
                if spent_from_accounts.contains(&output.account) {
                    output.is_change = true;
                }
            });

            // Update wallet tx
            if !(shielded_spends.is_empty() && shielded_outputs.is_empty()) {
                let mut txid = TxId([0u8; 32]);
                txid.0.copy_from_slice(&tx.hash);
                wtxs.push(zcash_client_backend::wallet::WalletTx {
                    txid,
                    index: tx.index as usize,
                    num_spends,
                    num_outputs,
                    shielded_spends,
                    shielded_outputs,
                });
            }
        }

        wtxs
    }

    pub fn scan_block(&self, block_bytes: &[u8]) -> Result<Vec<TxId>, i32> {
        self.scan_block_with_pool(&block_bytes, &ThreadPool::new(1))
    }

    // Scan a block. Will return an error with the block height that failed to scan
    pub fn scan_block_with_pool(&self, block_bytes: &[u8], pool: &ThreadPool) -> Result<Vec<TxId>, i32> {
        let block: CompactBlock = match parse_from_bytes(block_bytes) {
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
            return Ok(vec![]);
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
        
        // These are filled in inside the block
        let new_txs;
        let nfs: Vec<_>;
        {
            // Create a write lock 
            let mut txs = self.txs.write().unwrap();

            // Trim the older witnesses
            txs.values_mut().for_each(|wtx| {
                wtx.notes
                    .iter_mut()
                    .filter(|nd| nd.spent.is_some() && nd.spent_at_height.is_some() && nd.spent_at_height.unwrap() < height - (MAX_REORG as i32) - 1)
                    .for_each(|nd| {
                        nd.witnesses.clear()
                    })
            });

            // Create a Vec containing all unspent nullifiers.
            // Include only the confirmed spent nullifiers, since unconfirmed ones still need to be included
            // during scan_block below.
            nfs = txs
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

            new_txs = {
                let nf_refs = nfs.iter().map(|(nf, account, _)| (nf.to_vec(), *account)).collect::<Vec<_>>();
                let extfvks: Vec<ExtendedFullViewingKey> = self.zkeys.read().unwrap().iter().map(|zk| zk.extfvk.clone()).collect();

                // Create a single mutable slice of all the wallet's note's witnesses.
                let mut witness_refs: Vec<_> = txs
                    .values_mut()
                    .map(|tx| 
                        tx.notes.iter_mut()
                            .filter_map(|nd| 
                                // Note was not spent 
                                if nd.spent.is_none() && nd.unconfirmed_spent.is_none() {
                                    nd.witnesses.last_mut() 
                                } else if nd.spent.is_some() && nd.spent_at_height.is_some() && nd.spent_at_height.unwrap() < height - (MAX_REORG as i32) - 1 {
                                   // Note was spent in the last 100 blocks
                                    nd.witnesses.last_mut() 
                                } else { 
                                    // If note was old (spent NOT in the last 100 blocks)
                                    None 
                                }))
                    .flatten()
                    .collect();

                self.scan_block_internal(
                    block.clone(),
                    &extfvks,
                    nf_refs,
                    &mut block_data.tree,
                    &mut witness_refs[..],
                    pool
                )
            };
        }
        
        // If this block had any new Txs, return the list of ALL txids in this block, 
        // so the wallet can fetch them all as a decoy.
        let all_txs = if !new_txs.is_empty() {
            block.vtx.iter().map(|vtx| {
                let mut t = [0u8; 32];
                t.copy_from_slice(&vtx.hash[..]);
                TxId{0: t}
            }).collect::<Vec<TxId>>()
        } else {
            vec![]
        };

        for tx in new_txs {
            // Create a write lock 
            let mut txs = self.txs.write().unwrap();

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
                spent_note.spent_at_height = Some(height);
                spent_note.unconfirmed_spent = None::<TxId>;

                total_shielded_value_spent += spent_note.note.value;
            }

            // Find the existing transaction entry, or create a new one.
            if !txs.contains_key(&tx.txid) {
                let tx_entry = WalletTx::new(block_data.height as i32, block.time as u64, &tx.txid);
                txs.insert(tx.txid, tx_entry);
            }
            let tx_entry = txs.get_mut(&tx.txid).unwrap();
            tx_entry.total_shielded_value_spent = total_shielded_value_spent;

            // Save notes.
            for output in tx.shielded_outputs
            {
                let new_note = SaplingNoteData::new(&self.zkeys.read().unwrap()[output.account].extfvk, output);
                match LightWallet::note_address(self.config.hrp_sapling_address(), &new_note) {
                    Some(a) => {
                        info!("Received sapling output to {}", a);
                        self.ensure_hd_zaddresses(&a);
                    },
                    None => {}
                }

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
        
        {
            // Cleanup mempool tx after adding a block, to remove all txns that got mined
            self.cleanup_mempool();
        }

        // Print info about the block every 10,000 blocks
        if height % 10_000 == 0 {
            match self.get_sapling_tree() {
                Ok((h, hash, stree)) => info!("Sapling tree at height\n({}, \"{}\",\"{}\"),", h, hash, stree),
                Err(e) => error!("Couldn't determine sapling tree: {}", e)
            }
        }

        Ok(all_txs)
    }

    // Add the spent_at_height for each sapling note that has been spent. This field was added in wallet version 8, 
    // so for older wallets, it will need to be added
    pub fn fix_spent_at_height(&self) {
        // First, build an index of all the txids and the heights at which they were spent. 
        let spent_txid_map: HashMap<_, _> = self.txs.read().unwrap().iter().map(|(txid, wtx)| (txid.clone(), wtx.block)).collect();
        
        // Go over all the sapling notes that might need updating
        self.txs.write().unwrap().values_mut().for_each(|wtx| {
            wtx.notes.iter_mut()
                .filter(|nd| nd.spent.is_some() && nd.spent_at_height.is_none())
                .for_each(|nd| {
                    nd.spent_at_height = spent_txid_map.get(&nd.spent.unwrap()).map(|b| *b);
                })
        });
    }

    pub fn send_to_address(
        &self,
        consensus_branch_id: u32,
        spend_params: &[u8],
        output_params: &[u8],
        tos: Vec<(&str, u64, Option<String>)>
    ) -> Result<Box<[u8]>, String> {
        if !self.unlocked {
            return Err("Cannot spend while wallet is locked".to_string());
        }

        let start_time = now();
        if tos.len() == 0 {
            return Err("Need at least one destination address".to_string());
        }

        let total_value = tos.iter().map(|to| to.1).sum::<u64>();
        println!(
            "0: Creating transaction sending {} ztoshis to {} addresses",
            total_value, tos.len()
        );

        // Convert address (str) to RecepientAddress and value to Amount
        let recepients = tos.iter().map(|to| {
            let ra = match address::RecipientAddress::from_str(to.0, 
                            self.config.hrp_sapling_address(), 
                            self.config.base58_pubkey_address(), 
                            self.config.base58_script_address()) {
                Some(to) => to,
                None => {
                    let e = format!("Invalid recipient address: '{}'", to.0);
                    error!("{}", e);
                    return Err(e);
                }
            };

            let value = Amount::from_u64(to.1).unwrap();

            Ok((ra, value, to.2.clone()))
        }).collect::<Result<Vec<(address::RecipientAddress, Amount, Option<String>)>, String>>()?;

        // Target the next block, assuming we are up-to-date.
        let (height, anchor_offset) = match self.get_target_height_and_anchor_offset() {
            Some(res) => res,
            None => {
                let e = format!("Cannot send funds before scanning any blocks");
                error!("{}", e);
                return Err(e);
            }
        };

        // Select notes to cover the target value
        println!("{}: Selecting notes", now() - start_time);
        let target_value = Amount::from_u64(total_value).unwrap() + DEFAULT_FEE ;
        let notes: Vec<_> = self.txs.read().unwrap().iter()
            .map(|(txid, tx)| tx.notes.iter().map(move |note| (*txid, note)))
            .flatten()
            .filter_map(|(txid, note)| {
                // Filter out notes that are already spent
                if note.spent.is_some() || note.unconfirmed_spent.is_some() {
                    None
                } else {
                    // Get the spending key for the selected fvk, if we have it
                    let extsk = self.zkeys.read().unwrap().iter()
                        .find(|zk| zk.extfvk == note.extfvk)
                        .and_then(|zk| zk.extsk.clone());
                    SpendableNote::from(txid, note, anchor_offset, &extsk)
                }
            })
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
        let tinputs: Vec<_> = self.get_utxos().iter()
                                .filter(|utxo| utxo.unconfirmed_spent.is_none()) // Remove any unconfirmed spends
                                .map(|utxo| utxo.clone())
                                .collect();
        
        // Create a map from address -> sk for all taddrs, so we can spend from the 
        // right address
        let address_to_sk = self.tkeys.read().unwrap().iter()
                                .map(|sk| (self.address_from_sk(&sk), sk.clone()))
                                .collect::<HashMap<_,_>>();

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

                        Err(zcash_primitives::transaction::builder::Error::InvalidAddress)
                    }
                }
                
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{:?}", e))?;
        

        // Confirm we were able to select sufficient value
        let selected_value = notes.iter().map(|selected| selected.note.value).sum::<u64>() 
                             + tinputs.iter().map::<u64, _>(|utxo| utxo.value.into()).sum::<u64>();

        if selected_value < u64::from(target_value) {
            let e = format!(
                "Insufficient verified funds (have {}, need {:?}). NOTE: funds need {} confirmations before they can be spent.",
                selected_value, target_value, self.config.anchor_offset + 1
            );
            error!("{}", e);
            return Err(e);
        }

        // Create the transaction
        println!("{}: Adding {} notes and {} utxos", now() - start_time, notes.len(), tinputs.len());

        for selected in notes.iter() {
            if let Err(e) = builder.add_sapling_spend(
                selected.extsk.clone(),
                selected.diversifier,
                selected.note.clone(),
                selected.witness.path().unwrap(),
            ) {
                let e = format!("Error adding note: {:?}", e);
                error!("{}", e);
                return Err(e);
            }
        }

        // If no Sapling notes were added, add the change address manually. That is,
        // send the change to our sapling address manually. Note that if a sapling note was spent,
        // the builder will automatically send change to that address
        if notes.len() == 0 {
            builder.send_change_to(
                self.zkeys.read().unwrap()[0].extfvk.fvk.ovk,
                self.zkeys.read().unwrap()[0].zaddress.clone());
        }

        // TODO: We're using the first ovk to encrypt outgoing Txns. Is that Ok?
        let ovk = self.zkeys.read().unwrap()[0].extfvk.fvk.ovk;

        for (to, value, memo) in recepients {
            // Compute memo if it exists
            let encoded_memo = match memo {
                None => None,
                Some(s) => {
                    // If the string starts with an "0x", and contains only hex chars ([a-f0-9]+) then
                    // interpret it as a hex
                    let s_bytes = if s.to_lowercase().starts_with("0x") {
                        match hex::decode(&s[2..s.len()]) {
                            Ok(data) => data,
                            Err(_) => Vec::from(s.as_bytes())
                        }
                    } else {
                        Vec::from(s.as_bytes())
                    };

                    match Memo::from_bytes(&s_bytes) {
                        None => {
                            let e = format!("Error creating output. Memo {:?} is too long", s);
                            error!("{}", e);
                            return Err(e);
                        },
                        Some(m) => Some(m)
                    }
                }
            };
            
            println!("{}: Adding output", now() - start_time);

            if let Err(e) = match to {
                address::RecipientAddress::Shielded(to) => {
                    builder.add_sapling_output(ovk, to.clone(), value, encoded_memo)
                }
                address::RecipientAddress::Transparent(to) => {
                    builder.add_transparent_output(&to, value)
                }
            } {
                let e = format!("Error adding output: {:?}", e);
                error!("{}", e);
                return Err(e);
            }
        }
        

        println!("{}: Building transaction", now() - start_time);
        let (tx, _) = match builder.build(
            BranchId::try_from(consensus_branch_id).unwrap(),
            &prover::InMemTxProver::new(spend_params, output_params),
        ) {
            Ok(res) => res,
            Err(e) => {
                let e = format!("Error creating transaction: {:?}", e);
                error!("{}", e);
                return Err(e);
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

        // Add this Tx to the mempool structure
        {
            let mut mempool_txs = self.mempool_txs.write().unwrap();

            match mempool_txs.get_mut(&tx.txid()) {
                None => {
                    // Collect the outgoing metadata
                    let outgoing_metadata = tos.iter().map(|(addr, amt, maybe_memo)| {
                        OutgoingTxMetadata {
                            address: addr.to_string(),
                            value: *amt,
                            memo: match maybe_memo {
                                None    => Memo::default(),
                                Some(s) => {
                                    // If the address is not a z-address, then drop the memo
                                    if LightWallet::is_shielded_address(&addr.to_string(), &self.config) {
                                            Memo::from_bytes(s.as_bytes()).unwrap()
                                    } else {
                                        Memo::default()
                                    }                                        
                                }
                            },
                        }
                    }).collect::<Vec<_>>();

                    // Create a new WalletTx
                    let mut wtx = WalletTx::new(height as i32, now() as u64, &tx.txid());
                    wtx.outgoing_metadata = outgoing_metadata;

                    // Add it into the mempool 
                    mempool_txs.insert(tx.txid(), wtx);
                },
                Some(_) => {
                    warn!("A newly created Tx was already in the mempool! How's that possible? Txid: {}", tx.txid());
                }
            }
        }

        // Return the encoded transaction, so the caller can send it.
        let mut raw_tx = vec![];
        tx.write(&mut raw_tx).unwrap();
        Ok(raw_tx.into_boxed_slice())
    }

    // After some blocks have been mined, we need to remove the Txns from the mempool_tx structure
    // if they :
    // 1. Have expired
    // 2. The Tx has been added to the wallet via a mined block
    pub fn cleanup_mempool(&self) {
        const DEFAULT_TX_EXPIRY_DELTA: i32 = 20;

        let current_height = self.blocks.read().unwrap().last().map(|b| b.height).unwrap_or(0);

        {
            // Remove all expired Txns
            self.mempool_txs.write().unwrap().retain( | _, wtx| {
                current_height < (wtx.block + DEFAULT_TX_EXPIRY_DELTA)    
            });
        }

        {
            // Remove all txns where the txid is added to the wallet directly
            self.mempool_txs.write().unwrap().retain ( |txid, _| {
                self.txs.read().unwrap().get(txid).is_none()
            });
        }
    }
}

#[cfg(test)]
pub mod tests;