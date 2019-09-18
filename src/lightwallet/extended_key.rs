use rand::Rng;
use ring::{
    digest,
    hmac::{SigningContext, SigningKey},
};
use lazy_static::lazy_static;
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly, Error};

lazy_static! {
    static ref SECP256K1_SIGN_ONLY: Secp256k1<SignOnly> = Secp256k1::signing_only();
    static ref SECP256K1_VERIFY_ONLY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}
/// Random entropy, part of extended key.
type ChainCode = Vec<u8>;


const HARDENED_KEY_START_INDEX: u32 = 2_147_483_648; // 2 ** 31

/// KeyIndex indicates the key type and index of a child key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyIndex {
    /// Normal key, index range is from 0 to 2 ** 31 - 1
    Normal(u32),
    /// Hardened key, index range is from 2 ** 31 to 2 ** 32 - 1
    Hardened(u32),
}

impl KeyIndex {
    /// Return raw index value
    pub fn raw_index(self) -> u32 {
        match self {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(i) => i,
        }
    }

    /// Return normalize index, it will return index subtract 2 ** 31 for hardended key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate hdwallet;
    /// use hdwallet::KeyIndex;
    ///
    /// assert_eq!(KeyIndex::Normal(0).normalize_index(), 0);
    /// assert_eq!(KeyIndex::Hardened(2_147_483_648).normalize_index(), 0);
    /// ```
    pub fn normalize_index(self) -> u32 {
        match self {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(i) => i - HARDENED_KEY_START_INDEX,
        }
    }

    /// Check index range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate hdwallet;
    /// use hdwallet::KeyIndex;
    ///
    /// assert!(KeyIndex::Normal(0).is_valid());
    /// assert!(!KeyIndex::Normal(2_147_483_648).is_valid());
    /// assert!(KeyIndex::Hardened(2_147_483_648).is_valid());
    /// ```
    pub fn is_valid(self) -> bool {
        match self {
            KeyIndex::Normal(i) => i < HARDENED_KEY_START_INDEX,
            KeyIndex::Hardened(i) => i >= HARDENED_KEY_START_INDEX,
        }
    }

    /// Generate Hardened KeyIndex from normalize index value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate hdwallet;
    /// use hdwallet::KeyIndex;
    ///
    /// // hardended key from zero
    /// let hardened_index_zero = KeyIndex::hardened_from_normalize_index(0).unwrap();
    /// assert_eq!(hardened_index_zero, KeyIndex::Hardened(2_147_483_648));
    /// // also allow raw index for convernient
    /// let hardened_index_zero = KeyIndex::hardened_from_normalize_index(2_147_483_648).unwrap();
    /// assert_eq!(hardened_index_zero, KeyIndex::Hardened(2_147_483_648));
    /// ```
    pub fn hardened_from_normalize_index(i: u32) -> Result<KeyIndex, Error> {
        if i < HARDENED_KEY_START_INDEX {
            Ok(KeyIndex::Hardened(HARDENED_KEY_START_INDEX + i))
        } else {
            Ok(KeyIndex::Hardened(i))
        }
    }

    /// Generate KeyIndex from raw index value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate hdwallet;
    /// use hdwallet::KeyIndex;
    ///
    /// let normal_key = KeyIndex::from_index(0).unwrap();
    /// assert_eq!(normal_key, KeyIndex::Normal(0));
    /// let hardened_key = KeyIndex::from_index(2_147_483_648).unwrap();
    /// assert_eq!(hardened_key, KeyIndex::Hardened(2_147_483_648));
    /// ```
    pub fn from_index(i: u32) -> Result<Self, Error> {
        if i < HARDENED_KEY_START_INDEX {
            Ok(KeyIndex::Normal(i))
        } else {
            Ok(KeyIndex::Hardened(i))
        }
    }
}

impl From<u32> for KeyIndex {
    fn from(index: u32) -> Self {
        KeyIndex::from_index(index).expect("KeyIndex")
    }
}


/// ExtendedPrivKey is used for child key derivation.
/// See [secp256k1 crate documentation](https://docs.rs/secp256k1) for SecretKey signatures usage.
///
/// # Examples
///
/// ```rust
/// # extern crate hdwallet;
/// use hdwallet::{ExtendedPrivKey, KeyIndex};
///
/// let master_key = ExtendedPrivKey::random().unwrap();
/// let hardened_key_index = KeyIndex::hardened_from_normalize_index(0).unwrap();
/// let hardended_child_priv_key = master_key.derive_private_key(hardened_key_index).unwrap();
/// let normal_key_index = KeyIndex::Normal(0);
/// let noamal_child_priv_key = master_key.derive_private_key(normal_key_index).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPrivKey {
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
}

/// Indicate bits of random seed used to generate private key, 256 is recommended.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeySeed {
    S128 = 128,
    S256 = 256,
    S512 = 512,
}

impl ExtendedPrivKey {
    /// Generate an ExtendedPrivKey, use 256 size random seed.
    pub fn random() -> Result<ExtendedPrivKey, Error> {
        ExtendedPrivKey::random_with_seed_size(KeySeed::S256)
    }
    /// Generate an ExtendedPrivKey which use 128 or 256 or 512 bits random seed.
    pub fn random_with_seed_size(seed_size: KeySeed) -> Result<ExtendedPrivKey, Error> {
        let seed = {
            let mut seed = vec![0u8; seed_size as usize / 8];
            let mut rng = rand::thread_rng();
            rng.fill(seed.as_mut_slice());
            seed
        };
        Self::with_seed(&seed)
    }

    /// Generate an ExtendedPrivKey from seed
    pub fn with_seed(seed: &[u8]) -> Result<ExtendedPrivKey, Error> {
        let signature = {
            let signing_key = SigningKey::new(&digest::SHA512, b"Bitcoin seed");
            let mut h = SigningContext::with_key(&signing_key);
            h.update(&seed);
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(key)?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
    }

    fn sign_hardended_key(&self, index: u32) -> ring::hmac::Signature {
        let signing_key = SigningKey::new(&digest::SHA512, &self.chain_code);
        let mut h = SigningContext::with_key(&signing_key);
        h.update(&[0x00]);
        h.update(&self.private_key[..]);
        h.update(&index.to_be_bytes());
        h.sign()
    }

    fn sign_normal_key(&self, index: u32) -> ring::hmac::Signature {
        let signing_key = SigningKey::new(&digest::SHA512, &self.chain_code);
        let mut h = SigningContext::with_key(&signing_key);
        let public_key = PublicKey::from_secret_key(&SECP256K1_SIGN_ONLY, &self.private_key);
        h.update(&public_key.serialize());
        h.update(&index.to_be_bytes());
        h.sign()
    }

    /// Derive a child key from ExtendedPrivKey.
    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<ExtendedPrivKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::InvalidTweak);
        }
        let signature = match key_index {
            KeyIndex::Hardened(index) => self.sign_hardended_key(index),
            KeyIndex::Normal(index) => self.sign_normal_key(index),
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let mut private_key = SecretKey::from_slice(key)?;
        private_key.add_assign(&self.private_key[..])?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
    }
}
