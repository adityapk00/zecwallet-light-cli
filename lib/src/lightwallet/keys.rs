use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind, Read, Write},
};

use base58::ToBase58;
use bip39::{Language, Mnemonic, Seed};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::{rngs::OsRng, Rng};
use ripemd160::Digest;
use secp256k1::SecretKey;
use sha2::Sha256;
use sodiumoxide::crypto::secretbox;
use zcash_client_backend::{
    address,
    encoding::{encode_extended_full_viewing_key, encode_extended_spending_key, encode_payment_address},
};
use zcash_primitives::{
    consensus::MAIN_NETWORK,
    legacy::TransparentAddress,
    primitives::PaymentAddress,
    serialize::Vector,
    zip32::{ChildIndex, ExtendedFullViewingKey, ExtendedSpendingKey},
};

use crate::{
    lightclient::lightclient_config::{LightClientConfig, GAP_RULE_UNUSED_ADDRESSES},
    lightwallet::{
        extended_key::{ExtendedPrivKey, KeyIndex},
        utils,
    },
};

use super::walletzkey::{WalletZKey, WalletZKeyType};

/// Sha256(Sha256(value))
pub fn double_sha256(payload: &[u8]) -> Vec<u8> {
    let h1 = Sha256::digest(&payload);
    let h2 = Sha256::digest(&h1);
    h2.to_vec()
}

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

        let checksum = double_sha256(&payload);
        payload.append(&mut checksum[..4].to_vec());
        payload.to_base58()
    }
}

// Manages all the keys in the wallet. Note that the RwLock for this is present in `lightwallet.rs`, so we'll
// assume that this is already gone through a RwLock, so we don't lock any of the individual fields.
pub struct Keys {
    // TODO: This struct is duplicated with LightWallet and LightClient
    config: LightClientConfig,

    // Is the wallet encrypted? If it is, then when writing to disk, the seed is always encrypted
    // and the individual spending keys are not written
    pub(crate) encrypted: bool,

    // In memory only (i.e, this field is not written to disk). Is the wallet unlocked and are
    // the spending keys present to allow spending from this wallet?
    pub(crate) unlocked: bool,

    enc_seed: [u8; 48], // If locked, this contains the encrypted seed
    nonce: Vec<u8>,     // Nonce used to encrypt the wallet.

    seed: [u8; 32], // Seed phrase for this wallet. If wallet is locked, this is 0

    // List of keys, actually in this wallet. This is a combination of HD keys derived from the seed,
    // viewing keys and imported spending keys.
    pub(crate) zkeys: Vec<WalletZKey>,

    // Transparent keys. If the wallet is locked, then the secret keys will be encrypted,
    // but the addresses will be present.
    pub(crate) tkeys: Vec<secp256k1::SecretKey>,
    pub(crate) taddresses: Vec<String>,
}

impl Keys {
    pub fn serialized_version() -> u64 {
        return 20;
    }

    pub fn new(config: &LightClientConfig, seed_phrase: Option<String>) -> Result<Self, String> {
        let mut seed_bytes = [0u8; 32];

        if seed_phrase.is_none() {
            // Create a random seed.
            let mut system_rng = OsRng;
            system_rng.fill(&mut seed_bytes);
        } else {
            let phrase = match Mnemonic::from_phrase(seed_phrase.unwrap().as_str(), Language::English) {
                Ok(p) => p,
                Err(e) => {
                    let e = format!("Error parsing phrase: {}", e);
                    //error!("{}", e);
                    return Err(e);
                }
            };

            seed_bytes.copy_from_slice(&phrase.entropy());
        }

        // The seed bytes is the raw entropy. To pass it to HD wallet generation,
        // we need to get the 64 byte bip39 entropy
        let bip39_seed = Seed::new(&Mnemonic::from_entropy(&seed_bytes, Language::English).unwrap(), "");

        // Derive only the first sk and address
        let tpk = Self::get_taddr_from_bip39seed(&config, &bip39_seed.as_bytes(), 0);
        let taddr = Self::address_from_prefix_sk(&config.base58_pubkey_address(), &tpk);

        // TODO: We need to monitor addresses, and always keep 1 "free" address, so
        // users can import a seed phrase and automatically get all used addresses
        let hdkey_num = 0;
        let (extsk, _, _) = Self::get_zaddr_from_bip39seed(&config, &bip39_seed.as_bytes(), hdkey_num);

        Ok(Self {
            config: config.clone(),
            encrypted: false,
            unlocked: true,
            enc_seed: [0; 48],
            nonce: vec![],
            seed: seed_bytes,
            zkeys: vec![WalletZKey::new_hdkey(hdkey_num, extsk)],
            tkeys: vec![tpk],
            taddresses: vec![taddr],
        })
    }

    pub fn read_old<R: Read>(version: u64, mut reader: R, config: &LightClientConfig) -> io::Result<Self> {
        let encrypted = if version >= 4 { reader.read_u8()? > 0 } else { false };

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
                extsks
                    .iter()
                    .map(|sk| ExtendedFullViewingKey::from(sk))
                    .collect::<Vec<ExtendedFullViewingKey>>()
            };

            // Calculate the addresses
            let addresses = extfvks
                .iter()
                .map(|fvk| fvk.default_address().unwrap().1)
                .collect::<Vec<PaymentAddress>>();

            // If extsks is of len 0, then this wallet is locked
            let zkeys_result = if extsks.len() == 0 {
                // Wallet is locked, so read only the viewing keys.
                extfvks
                    .iter()
                    .zip(addresses.iter())
                    .enumerate()
                    .map(|(i, (extfvk, payment_address))| {
                        let zk = WalletZKey::new_locked_hdkey(i as u32, extfvk.clone());
                        if zk.zaddress != *payment_address {
                            Err(io::Error::new(ErrorKind::InvalidData, "Payment address didn't match"))
                        } else {
                            Ok(zk)
                        }
                    })
                    .collect::<Vec<io::Result<WalletZKey>>>()
            } else {
                // Wallet is unlocked, read the spending keys as well
                extsks
                    .into_iter()
                    .zip(extfvks.into_iter().zip(addresses.iter()))
                    .enumerate()
                    .map(|(i, (extsk, (extfvk, payment_address)))| {
                        let zk = WalletZKey::new_hdkey(i as u32, extsk);
                        if zk.zaddress != *payment_address {
                            return Err(io::Error::new(ErrorKind::InvalidData, "Payment address didn't match"));
                        }

                        if zk.extfvk != extfvk {
                            return Err(io::Error::new(ErrorKind::InvalidData, "Full View key didn't match"));
                        }

                        Ok(zk)
                    })
                    .collect::<Vec<io::Result<WalletZKey>>>()
            };

            // Convert vector of results into result of vector, returning an error if any one of the keys failed the checks above
            zkeys_result.into_iter().collect::<io::Result<_>>()?
        } else {
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
            tkeys
                .iter()
                .map(|sk| Self::address_from_prefix_sk(&config.base58_pubkey_address(), sk))
                .collect()
        };

        Ok(Self {
            config: config.clone(),
            encrypted,
            unlocked: !encrypted,
            enc_seed,
            nonce,
            seed: seed_bytes,
            zkeys,
            tkeys,
            taddresses,
        })
    }

    pub fn read<R: Read>(mut reader: R, config: &LightClientConfig) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        if version > Self::serialized_version() {
            let e = format!(
                "Don't know how to read wallet version {}. Do you have the latest version?",
                version
            );
            return Err(io::Error::new(ErrorKind::InvalidData, e));
        }

        let encrypted = reader.read_u8()? > 0;

        let mut enc_seed = [0u8; 48];
        reader.read_exact(&mut enc_seed)?;

        let nonce = Vector::read(&mut reader, |r| r.read_u8())?;

        // Seed
        let mut seed_bytes = [0u8; 32];
        reader.read_exact(&mut seed_bytes)?;

        let zkeys = Vector::read(&mut reader, |r| WalletZKey::read(r))?;

        let tkeys = Vector::read(&mut reader, |r| {
            let mut tpk_bytes = [0u8; 32];
            r.read_exact(&mut tpk_bytes)?;
            secp256k1::SecretKey::from_slice(&tpk_bytes).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
        })?;

        let taddresses = Vector::read(&mut reader, |r| utils::read_string(r))?;

        Ok(Self {
            config: config.clone(),
            encrypted,
            unlocked: !encrypted,
            enc_seed,
            nonce,
            seed: seed_bytes,
            zkeys,
            tkeys,
            taddresses,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write the version
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        // Write if it is encrypted
        writer.write_u8(if self.encrypted { 1 } else { 0 })?;

        // Write the encrypted seed bytes
        writer.write_all(&self.enc_seed)?;

        // Write the nonce
        Vector::write(&mut writer, &self.nonce, |w, b| w.write_u8(*b))?;

        // Write the seed
        writer.write_all(&self.seed)?;

        // Flush after writing the seed, so in case of a disaster, we can still recover the seed.
        writer.flush()?;

        // Write all the wallet's keys
        Vector::write(&mut writer, &self.zkeys, |w, zk| zk.write(w))?;

        // Write the transparent private keys
        Vector::write(&mut writer, &self.tkeys, |w, pk| w.write_all(&pk[..]))?;

        // Write the transparent addresses
        Vector::write(&mut writer, &self.taddresses, |w, a| utils::write_string(w, a))?;

        Ok(())
    }

    pub fn get_seed_phrase(&self) -> String {
        if !self.unlocked {
            return "".to_string();
        }

        Mnemonic::from_entropy(&self.seed, Language::English)
            .unwrap()
            .phrase()
            .to_string()
    }

    pub fn get_all_extfvks(&self) -> Vec<ExtendedFullViewingKey> {
        self.zkeys.iter().map(|zk| zk.extfvk.clone()).collect()
    }

    pub fn get_all_zaddresses(&self) -> Vec<String> {
        self.zkeys
            .iter()
            .map(|zk| encode_payment_address(self.config.hrp_sapling_address(), &zk.zaddress))
            .collect()
    }

    pub fn get_all_spendable_zaddresses(&self) -> Vec<String> {
        self.zkeys
            .iter()
            .filter(|zk| zk.have_spending_key())
            .map(|zk| encode_payment_address(self.config.hrp_sapling_address(), &zk.zaddress))
            .collect()
    }

    pub fn get_all_taddrs(&self) -> Vec<String> {
        self.taddresses.iter().map(|t| t.clone()).collect()
    }

    pub fn have_spending_key(&self, extfvk: &ExtendedFullViewingKey) -> bool {
        self.zkeys
            .iter()
            .find(|zk| zk.extfvk == *extfvk)
            .map(|zk| zk.have_spending_key())
            .unwrap_or(false)
    }

    pub fn get_extsk_for_extfvk(&self, extfvk: &ExtendedFullViewingKey) -> Option<ExtendedSpendingKey> {
        self.zkeys
            .iter()
            .find(|zk| zk.extfvk == *extfvk)
            .map(|zk| zk.extsk.clone())
            .flatten()
    }

    pub fn get_taddr_to_sk_map(&self) -> HashMap<String, secp256k1::SecretKey> {
        self.taddresses
            .iter()
            .zip(self.tkeys.iter())
            .map(|(addr, sk)| (addr.clone(), sk.clone()))
            .collect()
    }

    // If one of the last 'n' taddress was used, ensure we add the next HD taddress to the wallet.
    pub fn ensure_hd_taddresses(&mut self, address: &String) {
        if GAP_RULE_UNUSED_ADDRESSES == 0 {
            return;
        }

        let last_addresses = {
            self.taddresses
                .iter()
                .rev()
                .take(GAP_RULE_UNUSED_ADDRESSES)
                .map(|s| s.clone())
                .collect::<Vec<String>>()
        };

        match last_addresses.iter().position(|s| *s == *address) {
            None => {
                return;
            }
            Some(pos) => {
                //info!("Adding {} new zaddrs", (GAP_RULE_UNUSED_ADDRESSES - pos));
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
    pub fn ensure_hd_zaddresses(&mut self, address: &String) {
        if GAP_RULE_UNUSED_ADDRESSES == 0 {
            return;
        }

        let last_addresses = {
            self.zkeys
                .iter()
                .filter(|zk| zk.keytype == WalletZKeyType::HdKey)
                .rev()
                .take(GAP_RULE_UNUSED_ADDRESSES)
                .map(|s| encode_payment_address(self.config.hrp_sapling_address(), &s.zaddress))
                .collect::<Vec<String>>()
        };

        match last_addresses.iter().position(|s| *s == *address) {
            None => {
                return;
            }
            Some(pos) => {
                //info!("Adding {} new zaddrs", (GAP_RULE_UNUSED_ADDRESSES - pos));
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

    /// Adds a new z address to the wallet. This will derive a new address from the seed
    /// at the next position and add it to the wallet.
    /// NOTE: This does NOT rescan
    pub fn add_zaddr(&mut self) -> String {
        if !self.unlocked {
            return "Error: Can't add key while wallet is locked".to_string();
        }

        // Find the highest pos we have
        let pos = self
            .zkeys
            .iter()
            .filter(|zk| zk.hdkey_num.is_some())
            .max_by(|zk1, zk2| zk1.hdkey_num.unwrap().cmp(&zk2.hdkey_num.unwrap()))
            .map_or(0, |zk| zk.hdkey_num.unwrap() + 1);

        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&self.seed, Language::English).unwrap(), "");

        let (extsk, _, _) = Self::get_zaddr_from_bip39seed(&self.config, &bip39_seed.as_bytes(), pos);

        // let zaddr = encode_payment_address(self.config.hrp_sapling_address(), &address);
        let newkey = WalletZKey::new_hdkey(pos, extsk);
        self.zkeys.push(newkey.clone());

        encode_payment_address(self.config.hrp_sapling_address(), &newkey.zaddress)
    }

    /// Add a new t address to the wallet. This will derive a new address from the seed
    /// at the next position.
    /// NOTE: This will not rescan the wallet
    pub fn add_taddr(&mut self) -> String {
        if !self.unlocked {
            return "Error: Can't add key while wallet is locked".to_string();
        }

        let pos = self.tkeys.len() as u32;
        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&self.seed, Language::English).unwrap(), "");

        let sk = Self::get_taddr_from_bip39seed(&self.config, &bip39_seed.as_bytes(), pos);
        let address = self.address_from_sk(&sk);

        self.tkeys.push(sk);
        self.taddresses.push(address.clone());

        address
    }

    // Get all z-address private keys. Returns a Vector of (address, privatekey, viewkey)
    pub fn get_z_private_keys(&self) -> Vec<(String, String, String)> {
        let keys = self
            .zkeys
            .iter()
            .map(|k| {
                let pkey = match k
                    .extsk
                    .clone()
                    .map(|extsk| encode_extended_spending_key(self.config.hrp_sapling_private_key(), &extsk))
                {
                    Some(pk) => pk,
                    None => "".to_string(),
                };

                let vkey = encode_extended_full_viewing_key(self.config.hrp_sapling_viewing_key(), &k.extfvk);

                (
                    encode_payment_address(self.config.hrp_sapling_address(), &k.zaddress),
                    pkey,
                    vkey,
                )
            })
            .collect::<Vec<(String, String, String)>>();

        keys
    }

    /// Get all t-address private keys. Returns a Vector of (address, secretkey)
    pub fn get_t_secret_keys(&self) -> Vec<(String, String)> {
        self.tkeys
            .iter()
            .map(|sk| {
                (
                    self.address_from_sk(sk),
                    sk[..].to_base58check(&self.config.base58_secretkey_prefix(), &[0x01]),
                )
            })
            .collect::<Vec<(String, String)>>()
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
        self.zkeys
            .iter_mut()
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
        self.tkeys = vec![];

        // Remove all the private key from the zkeys
        self.zkeys
            .iter_mut()
            .map(|zk| zk.lock())
            .collect::<io::Result<Vec<_>>>()?;

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
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Decryption failed. Is your password correct?",
                ));
            }
        };

        // Now that we have the seed, we'll generate the extsks and tkeys, and verify the fvks and addresses
        // respectively match

        // The seed bytes is the raw entropy. To pass it to HD wallet generation,
        // we need to get the 64 byte bip39 entropy
        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&seed, Language::English).unwrap(), "");

        // Transparent keys
        let mut tkeys = vec![];
        for pos in 0..self.taddresses.len() {
            let sk = Self::get_taddr_from_bip39seed(&self.config, &bip39_seed.as_bytes(), pos as u32);
            let address = self.address_from_sk(&sk);

            if address != self.taddresses[pos] {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("taddress mismatch at {}. {} vs {}", pos, address, self.taddresses[pos]),
                ));
            }

            tkeys.push(sk);
        }

        let config = self.config.clone();
        // Go over the zkeys, and add the spending keys again
        self.zkeys
            .iter_mut()
            .map(|zk| zk.unlock(&config, bip39_seed.as_bytes(), &key))
            .collect::<io::Result<Vec<()>>>()?;

        // Everything checks out, so we'll update our wallet with the decrypted values
        self.tkeys = tkeys;
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
        self.zkeys
            .iter_mut()
            .map(|zk| zk.remove_encryption())
            .collect::<io::Result<Vec<()>>>()?;

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

    /// STATIC METHODS
    pub fn address_from_pubkeyhash(&self, ta: Option<TransparentAddress>) -> Option<String> {
        match ta {
            Some(TransparentAddress::PublicKey(hash)) => {
                Some(hash.to_base58check(&self.config.base58_pubkey_address(), &[]))
            }
            Some(TransparentAddress::Script(hash)) => {
                Some(hash.to_base58check(&self.config.base58_script_address(), &[]))
            }
            _ => None,
        }
    }

    pub fn address_from_sk(&self, sk: &secp256k1::SecretKey) -> String {
        Self::address_from_prefix_sk(&self.config.base58_pubkey_address(), sk)
    }

    pub fn address_from_prefix_sk(prefix: &[u8; 2], sk: &secp256k1::SecretKey) -> String {
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        // Encode into t address
        let mut hash160 = ripemd160::Ripemd160::new();
        hash160.update(Sha256::digest(&pk.serialize()[..].to_vec()));

        hash160.finalize().to_base58check(prefix, &[])
    }

    pub fn get_taddr_from_bip39seed(config: &LightClientConfig, bip39_seed: &[u8], pos: u32) -> SecretKey {
        assert_eq!(bip39_seed.len(), 64);

        let ext_t_key = ExtendedPrivKey::with_seed(bip39_seed).unwrap();
        ext_t_key
            .derive_private_key(KeyIndex::hardened_from_normalize_index(44).unwrap())
            .unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(config.get_coin_type()).unwrap())
            .unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(0).unwrap())
            .unwrap()
            .derive_private_key(KeyIndex::Normal(0))
            .unwrap()
            .derive_private_key(KeyIndex::Normal(pos))
            .unwrap()
            .private_key
    }

    pub fn get_zaddr_from_bip39seed(
        config: &LightClientConfig,
        bip39_seed: &[u8],
        pos: u32,
    ) -> (ExtendedSpendingKey, ExtendedFullViewingKey, PaymentAddress) {
        assert_eq!(bip39_seed.len(), 64);

        let extsk: ExtendedSpendingKey = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(bip39_seed),
            &[
                ChildIndex::Hardened(32),
                ChildIndex::Hardened(config.get_coin_type()),
                ChildIndex::Hardened(pos),
            ],
        );
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let address = extfvk.default_address().unwrap().1;

        (extsk, extfvk, address)
    }

    pub fn is_shielded_address(addr: &String, _config: &LightClientConfig) -> bool {
        match address::RecipientAddress::decode(&MAIN_NETWORK, addr) {
            Some(address::RecipientAddress::Shielded(_)) => true,
            _ => false,
        }
    }
}
