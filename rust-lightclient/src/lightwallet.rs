use std::time::SystemTime;
use std::io::{self, Read, Write};
use std::cmp;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use protobuf::parse_from_bytes;

use bip39::{Mnemonic, Language};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use pairing::bls12_381::{Bls12};
use ff::{PrimeField, PrimeFieldRepr};

use zcash_client_backend::{
    constants::testnet::{HRP_SAPLING_PAYMENT_ADDRESS,B58_PUBKEY_ADDRESS_PREFIX,}, 
    encoding::encode_payment_address,
    proto::compact_formats::CompactBlock, welding_rig::scan_block,
};

use zcash_primitives::{
    block::BlockHash,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::Node,
    serialize::{Vector, Optional},
    transaction::{
        builder::{Builder},
        components::{Amount, OutPoint, TxOut}, components::amount::DEFAULT_FEE,
        TxId, Transaction, 
    },
     legacy::{Script, TransparentAddress},
    note_encryption::{Memo, try_sapling_note_decryption},
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey, ChildIndex},
    JUBJUB,
    primitives::{Diversifier, Note, PaymentAddress},
    jubjub::{
        JubjubEngine,
        fs::{Fs, FsRepr},    
    }
};

use crate::address;
use crate::prover;


use sha2::{Sha256, Digest};

/// Sha256(Sha256(value))
pub fn double_sha256(payload: &[u8]) -> Vec<u8> {
    let h1 = Sha256::digest(&payload);
    let h2 = Sha256::digest(&h1);
    h2.to_vec()
}

use base58::{ToBase58, FromBase58};

const ANCHOR_OFFSET: u32 = 1;

const SAPLING_ACTIVATION_HEIGHT: i32 = 280_000;


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

        let endtag = reader.read_u64::<LittleEndian>()?;
        if endtag != 11 {
            println!("End tag for blockdata {}", endtag);        
        }


        Ok(BlockData{
            height, 
            hash: BlockHash{ 0: hash_bytes }, 
            tree
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_i32::<LittleEndian>(self.height)?;
        writer.write_all(&self.hash.0)?;
        self.tree.write(&mut writer)?;
        writer.write_u64::<LittleEndian>(11)
    }
}

pub struct SaplingNoteData {
    account: usize,
    pub extfvk: ExtendedFullViewingKey, // Technically, this should be recoverable from the account number, but we're going to refactor this in the future, so I'll write it again here. 
    pub diversifier: Diversifier,
    pub note: Note<Bls12>,
    witnesses: Vec<IncrementalWitness<Node>>,
    nullifier: [u8; 32],
    pub spent: Option<TxId>,             // If this note was confirmed spent
    pub unconfirmed_spent: Option<TxId>, // If this note was spent in a send, but has not yet been confirmed.
    pub memo:  Option<Memo>,
    pub is_change: bool,
    // TODO: We need to remove the unconfirmed_spent (i.e., set it to None) if the Tx has expired
}


/// Reads an FsRepr from [u8] of length 32
/// This will panic (abort) if length provided is
/// not correct
/// TODO: This is duplicate from rustzcash.rs
fn read_fs(from: &[u8]) -> FsRepr {
    assert_eq!(from.len(), 32);

    let mut f = <<Bls12 as JubjubEngine>::Fs as PrimeField>::Repr::default();
    f.read_le(from).expect("length is 32 bytes");

    f
}

// Reading a note also needs the corresponding address to read from.
pub fn read_note<R: Read>(mut reader: R) -> io::Result<(u64, Fs)> {
    let value = reader.read_u64::<LittleEndian>()?;

    let mut r_bytes: [u8; 32] = [0; 32];
    reader.read_exact(&mut r_bytes)?;

    let r = match Fs::from_repr(read_fs(&r_bytes)) {
        Ok(r) => r,
        Err(_) => return Err(io::Error::new(
            io::ErrorKind::InvalidInput, "Couldn't parse randomness"))
    };

    Ok((value, r))
}

impl SaplingNoteData {
    fn serialized_version() -> u64 {
        1
    }

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
            extfvk: extfvk.clone(),
            diversifier: output.to.diversifier,
            note: output.note,
            witnesses: vec![witness],
            nullifier: nf,
            spent: None,
            unconfirmed_spent: None,
            memo: None,
            is_change: output.is_change,
        }
    }

    // Reading a note also needs the corresponding address to read from.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        assert_eq!(version, SaplingNoteData::serialized_version());

        let account = reader.read_u64::<LittleEndian>()? as usize;

        let extfvk = ExtendedFullViewingKey::read(&mut reader)?;

        let mut diversifier_bytes = [0u8; 11];
        reader.read_exact(&mut diversifier_bytes)?;
        let diversifier = Diversifier{0: diversifier_bytes};

        // To recover the note, read the value and r, and then use the payment address
        // to recreate the note
        let (value, r) = read_note(&mut reader)?; // TODO: This method is in a different package, because of some fields that are private

        let maybe_note = extfvk.fvk.vk.into_payment_address(diversifier, &JUBJUB).unwrap().create_note(value, r, &JUBJUB);

        let note = match maybe_note {
            Some(n)  => Ok(n),
            None     => Err(io::Error::new(io::ErrorKind::InvalidInput, "Couldn't create the note for the address"))
        }?;

        let witnesses = Vector::read(&mut reader, |r| IncrementalWitness::<Node>::read(r))?;

        let mut nullifier = [0u8; 32];
        reader.read_exact(&mut nullifier)?;

        // Note that this is only the spent field, we ignore the unconfirmed_spent field. 
        // The reason is that unconfirmed spents are only in memory, and we need to get the actual value of spent
        // from the blockchain anyway. 
        let spent = Optional::read(&mut reader, |r| {
            let mut txid_bytes = [0u8; 32];
            r.read_exact(&mut txid_bytes)?;
            Ok(TxId{0: txid_bytes})
        })?;

        let memo = Optional::read(&mut reader, |r| {
            let mut memo_bytes = [0u8; 512];
            r.read_exact(&mut memo_bytes)?;
            match Memo::from_bytes(&memo_bytes) {
                Some(m) => Ok(m),
                None    => Err(io::Error::new(io::ErrorKind::InvalidInput, "Couldn't create the memo"))
            }
        })?;

        let is_change: bool = reader.read_u8()? > 0;

        Ok(SaplingNoteData {
            account,
            extfvk,
            diversifier,
            note,
            witnesses,
            nullifier,
            spent,
            unconfirmed_spent: None,    
            memo,
            is_change,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write a version number first, so we can later upgrade this if needed.
        writer.write_u64::<LittleEndian>(SaplingNoteData::serialized_version())?;

        writer.write_u64::<LittleEndian>(self.account as u64)?;

        self.extfvk.write(&mut writer)?;

        writer.write_all(&self.diversifier.0)?;

        // Writing the note means writing the note.value and note.r. The Note is recoverable
        // from these 2 values and the Payment address. 
        writer.write_u64::<LittleEndian>(self.note.value)?;

        let mut rcm = [0; 32];
        self.note.r.into_repr().write_le(&mut rcm[..])?;
        writer.write_all(&rcm)?;

        Vector::write(&mut writer, &self.witnesses, |wr, wi| wi.write(wr) )?;

        writer.write_all(&self.nullifier)?;
        Optional::write(&mut writer, &self.spent, |w, t| w.write_all(&t.0))?;

        Optional::write(&mut writer, &self.memo, |w, m| w.write_all(m.as_bytes()))?;

        writer.write_u8(if self.is_change {1} else {0})?;

        Ok(())
    }

    pub fn note_address(&self) -> Option<String> {
        match self.extfvk.fvk.vk.into_payment_address(self.diversifier, &JUBJUB) {
            Some(pa) => Some(encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &pa)),
            None     => None
        }
    }
}

#[derive(Clone, Debug)]
pub struct Utxo {
    pub address: String,
    pub txid: TxId,
    pub output_index: u64,
    pub script: Vec<u8>,
    pub value: u64,
    pub height: i32,

    pub spent: Option<TxId>,             // If this utxo was confirmed spent
    pub unconfirmed_spent: Option<TxId>, // If this utxo was spent in a send, but has not yet been confirmed.
}

impl Utxo {
    pub fn serialized_version() -> u64 {
        return 1;
    }

    fn to_outpoint(&self) -> OutPoint {
        OutPoint { hash: self.txid.0, n: self.output_index as u32 }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        assert_eq!(version, Utxo::serialized_version());

        let address_len = reader.read_i32::<LittleEndian>()?;
        let mut address_bytes = vec![0; address_len as usize];
        reader.read_exact(&mut address_bytes)?;
        let address = String::from_utf8(address_bytes).unwrap();
        assert_eq!(address.chars().take(1).collect::<Vec<char>>()[0], 't');

        let mut txid_bytes = [0; 32];
        reader.read_exact(&mut txid_bytes)?;
        let txid = TxId { 0: txid_bytes };

        let output_index = reader.read_u64::<LittleEndian>()?;
        let value = reader.read_u64::<LittleEndian>()?;
        let height = reader.read_i32::<LittleEndian>()?;

        let script = Vector::read(&mut reader, |r| {
            let mut byte = [0; 1];
            r.read_exact(&mut byte)?;
            Ok(byte[0])
        })?;

        let spent = Optional::read(&mut reader, |r| {
            let mut txbytes = [0u8; 32];
            r.read_exact(&mut txbytes)?;
            Ok(TxId{0: txbytes})
        })?;

        let unconfirmed_spent = Optional::read(&mut reader, |r| {
            let mut txbytes = [0; 32];
            r.read_exact(&mut txbytes)?;
            Ok(TxId{0: txbytes})
        })?;

        Ok(Utxo {
            address,
            txid,
            output_index,
            script,
            value,
            height,
            spent,
            unconfirmed_spent,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(Utxo::serialized_version())?;

        writer.write_u32::<LittleEndian>(self.address.as_bytes().len() as u32)?;
        writer.write_all(self.address.as_bytes())?;

        writer.write_all(&self.txid.0)?;

        writer.write_u64::<LittleEndian>(self.output_index)?;
        writer.write_u64::<LittleEndian>(self.value)?;
        writer.write_i32::<LittleEndian>(self.height)?;

        Vector::write(&mut writer, &self.script, |w, b| w.write_all(&[*b]))?;

        Optional::write(&mut writer, &self.spent, |w, txid| w.write_all(&txid.0))?;
        Optional::write(&mut writer, &self.unconfirmed_spent, |w, txid| w.write_all(&txid.0))?;

        Ok(())
    }
}

pub struct WalletTx {
    pub block: i32,

    // Txid of this transcation. It's duplicated here (It is also the Key in the HashMap that points to this
    // WalletTx in LightWallet::txs)
    pub txid: TxId,

    // List of all notes recieved in this tx. Some of these might be change notes.
    pub notes: Vec<SaplingNoteData>,

    // List of all Utxos recieved in this Tx. Some of these might be change notes
    pub utxos: Vec<Utxo>,

    // Total shielded value spent in this Tx. Note that this is the value of the wallet's notes spent.
    // Some change may be returned in one of the notes above. Subtract the two to get the actual value spent.
    // Also note that even after subtraction, you might need to account for transparent inputs and outputs
    // to make sure the value is accurate.
    pub total_shielded_value_spent: u64,

    // Total amount of transparent funds that belong to us that were spent in this Tx.
    pub total_transparent_value_spent : u64,
}

impl WalletTx {
    pub fn serialized_version() -> u64 {
        return 1;
    }

    pub fn new(height: i32, txid: &TxId) -> Self {
        WalletTx {
            block: height,
            txid: txid.clone(),
            notes: vec![],
            utxos: vec![],
            total_shielded_value_spent: 0,
            total_transparent_value_spent: 0
        }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        assert_eq!(version, WalletTx::serialized_version());

        let block = reader.read_i32::<LittleEndian>()?;

        let mut txid_bytes = [0u8; 32];
        reader.read_exact(&mut txid_bytes)?;

        let txid = TxId{0: txid_bytes};

        let notes = Vector::read(&mut reader, |r| SaplingNoteData::read(r))?;

        let total_shielded_value_spent = reader.read_u64::<LittleEndian>()?;
        let total_transparent_value_spent = reader.read_u64::<LittleEndian>()?;

        Ok(WalletTx{
            block,
            txid,
            notes,
            utxos: vec![],
            total_shielded_value_spent,
            total_transparent_value_spent
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(WalletTx::serialized_version())?;

        writer.write_i32::<LittleEndian>(self.block)?;

        writer.write_all(&self.txid.0)?;

        Vector::write(&mut writer, &self.notes, |w, nd| nd.write(w))?;

        writer.write_u64::<LittleEndian>(self.total_shielded_value_spent)?;
        writer.write_u64::<LittleEndian>(self.total_transparent_value_spent)?;

        Ok(())
    }
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
        // Include only notes that haven't been spent, or haven't been included in an unconfirmed spend yet.
        if nd.spent.is_none() && nd.unconfirmed_spent.is_none() {
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
    seed: [u8; 32], // Seed phrase for this wallet. 

    // List of keys, actually in this wallet. This may include more
    // than keys derived from the seed, for example, if user imports 
    // a private key
    extsks:  Vec<ExtendedSpendingKey>,
    extfvks: Vec<ExtendedFullViewingKey>,
    pub address: Vec<PaymentAddress<Bls12>>,
    
    // Transparent keys. TODO: Make it not pubic
    pub tkeys: Vec<secp256k1::SecretKey>,

    // Current UTXOs that can be spent
    pub utxos: Arc<RwLock<Vec<Utxo>>>,

    blocks: Arc<RwLock<Vec<BlockData>>>,
    pub txs: Arc<RwLock<HashMap<TxId, WalletTx>>>,
}

impl LightWallet {
    pub fn serialized_version() -> u64 {
        return 1;
    }

    fn get_pk_from_seed(seed: &[u8; 32]) -> 
            (ExtendedSpendingKey, ExtendedFullViewingKey, PaymentAddress<Bls12>) {
        let extsk: ExtendedSpendingKey = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(seed),
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

    pub fn new(seed_phrase: Option<&str>) -> io::Result<Self> {
        use rand::{FromEntropy, ChaChaRng, Rng};

        let mut seed_bytes = [0u8; 32];

        if seed_phrase.is_none() {
            // Create a random seed. 
            let mut system_rng = ChaChaRng::from_entropy();
            system_rng.fill(&mut seed_bytes);
        } else {
            seed_bytes.copy_from_slice(&Mnemonic::from_phrase(seed_phrase.expect("should have a seed phrase"), 
                                        Language::English).unwrap().entropy());
        }

        // TODO: Generate transparent addresses from the seed
        let tpk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();

        // Derive only the first address
        // TODO: We need to monitor addresses, and always keep 1 "free" address, so 
        // users can import a seed phrase and automatically get all used addresses
        let (extsk, extfvk, address) = LightWallet::get_pk_from_seed(&seed_bytes);

        Ok(LightWallet {
            seed:    seed_bytes,
            extsks:  vec![extsk],
            extfvks: vec![extfvk],
            address: vec![address],
            tkeys:   vec![tpk],
            utxos:   Arc::new(RwLock::new(vec![])),
            blocks:  Arc::new(RwLock::new(vec![])),
            txs:     Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        assert_eq!(version, LightWallet::serialized_version());

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

        // TODO: Generate transparent addresses from the seed
        let tpk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();

        let utxos = Vector::read(&mut reader, |r| Utxo::read(r))?;

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
            utxos:   Arc::new(RwLock::new(utxos)),
            blocks:  Arc::new(RwLock::new(blocks)),
            txs:     Arc::new(RwLock::new(txs))
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

        Vector::write(&mut writer, &self.utxos.read().unwrap(), |w, u| u.write(w))?;

        Vector::write(&mut writer, &self.blocks.read().unwrap(), |w, b| b.write(w))?;
                
        // The hashmap, write as a set of tuples
        Vector::write(&mut writer, &self.txs.read().unwrap().iter().collect::<Vec<(&TxId, &WalletTx)>>(),
                        |w, (k, v)| {
                            w.write_all(&k.0)?;
                            v.write(w)
                        })?;
        Ok(())
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

    pub fn address_from_extfvk(extfvk: &ExtendedFullViewingKey, diversifier: Diversifier) -> String {
        encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, 
                                &extfvk.fvk.vk.into_payment_address(diversifier, &JUBJUB).unwrap())
    }

    pub fn address_from_sk(sk: &secp256k1::SecretKey) -> String {
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        // Encode into t address
        let mut hash160 = ripemd160::Ripemd160::new();
        hash160.input(Sha256::digest(&pk.serialize()[..].to_vec()));
            
        // TODO: The taddr version prefix needs to be different for testnet and mainnet
        hash160.result().to_base58check(&B58_PUBKEY_ADDRESS_PREFIX, &[])
    }
    
    pub fn address_from_pubkeyhash(ta: Option<TransparentAddress>) -> Option<String> {
        match ta {
            Some(TransparentAddress::PublicKey(hash)) => {
                Some(hash.to_base58check(&B58_PUBKEY_ADDRESS_PREFIX, &[]))
            },
            _ => None
        }
    }

    pub fn get_seed_phrase(&self) -> String {
        Mnemonic::from_entropy(&self.seed, 
                                Language::English,
        ).unwrap().phrase().to_string()
    }

    pub fn balance(&self, addr: Option<String>) -> u64 {
        self.txs.read().unwrap()
            .values()
            .map(|tx| {
                tx.notes.iter()
                    .filter(|nd| {  // TODO, this whole section is shared with verified_balance. Refactor it. 
                        match addr.clone() {
                            Some(a) => a == encode_payment_address(
                                                HRP_SAPLING_PAYMENT_ADDRESS,
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

    pub fn tbalance(&self, addr: Option<String>) -> u64 {
        self.utxos.read().unwrap().iter()
            .filter(|utxo| {
                match addr.clone() {
                    Some(a) => utxo.address == a,
                    None    => true,
                }
            })
            .map(|utxo| utxo.value )
            .sum::<u64>()
    }

    pub fn verified_balance(&self, addr: Option<String>) -> u64 {
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
                                                    HRP_SAPLING_PAYMENT_ADDRESS,
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
            Some(_) => { /* We already have the txid as an output, do nothing */}
            None => {
                let address = LightWallet::address_from_pubkeyhash(vout.script_pubkey.address());
                if address.is_none() {
                    println!("Couldn't determine address for output!");
                }
                //println!("Added {}, {}", txid, n);
                // Add the utxo     
                tx_entry.utxos.push(Utxo{
                    address: address.unwrap(),
                    txid: txid.clone(),
                    output_index: n,
                    script: vout.script_pubkey.0.clone(),
                    value: vout.value.into(),
                    height: height,
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
            match vin.script_sig.public_key() {
                Some(pk) => {
                    //println!("One of our transparent inputs was spent. {}, {}", hex::encode(pk.to_vec()), hex::encode(pubkey.to_vec()));
                    if pk[..] == pubkey[..] {
                        // Find the txid in the list of utxos that we have.
                        let txid = TxId {0: vin.prevout.hash};

                        // println!("Looking for {}, {}", txid, vin.prevout.n);

                        let value = match self.txs.read().unwrap().get(&txid) {
                            Some(wtx) => {
                                // One of the tx outputs is a match
                                wtx.utxos.iter()
                                    .find(|u| u.txid == txid && u.output_index == (vin.prevout.n as u64))
                                    .map_or(0, |u| u.value)
                            },
                            _ => 0
                        };

                        if value == 0 {
                            println!("One of the inputs was a transparent address we have, but the UTXO wasn't found");
                        }

                        total_transparent_spend += value;
                    }
                },
                _ => {}
            };
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

        // Scan shielded sapling outputs to see if anyone of them is us, and if it is, extract the memo
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

    pub fn clear_utxos(&self) {
        let mut utxos = self.utxos.write().unwrap();
        utxos.clear();
    }

    pub fn add_utxo(&self, utxo: &Utxo) {
        let mut utxos = self.utxos.write().unwrap();
        utxos.push(utxo.clone());
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

            for spend in &tx.shielded_spends {
                // TODO: Add up the spent value here and add it to the WalletTx as a Spent
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

        // TODO: This only spends from the first address right now.
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
        let tinputs = self.utxos.read().unwrap().iter()
            .map(|utxo| {
                let outpoint: OutPoint = utxo.to_outpoint();

                let coin = TxOut {
                    value: Amount::from_u64(utxo.value).unwrap(),
                    script_pubkey: Script { 0: utxo.script.clone() },
                };

                (outpoint, coin)
            })
            .collect::<Vec<(OutPoint, TxOut)>>();

        if let Err(e) = match to {
            address::RecipientAddress::Shielded(_) => {
                // The destination is a sapling address, so add all transparent inputs
                // TODO: This only spends from the first address right now.
                let sk = self.tkeys[0];

                // Add all tinputs
                tinputs.iter().map( |(outpoint, coin)| {
                    builder.add_transparent_input(sk, outpoint.clone(), coin.clone())
                }).collect::<Result<Vec<_>, _>>()
            }
            _ => {Ok(vec![])}
        } { 
            eprintln!("Error adding transparent inputs: {:?}", e);
            return None;
        }

        // Confirm we were able to select sufficient value
        // TODO: If we're sending to a t-address, we could also use t-address inputs
        let selected_value = notes.iter().map(|selected| selected.note.value).sum::<u64>() 
            + tinputs.iter().map::<u64, _>(|(_, coin)| coin.value.into()).sum::<u64>();

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
        // TODO: This is only a non-confirmed spend, and the note should be marked as such.
        let mut txs = self.txs.write().unwrap();
        for selected in notes {
            let mut spent_note = txs
                .get_mut(&selected.txid)
                .unwrap()
                .notes
                .iter_mut()
                .find(|nd| &nd.nullifier[..] == &selected.nullifier[..])
                .unwrap();
            spent_note.unconfirmed_spent = Some(tx.txid());
        }

        // Return the encoded transaction, so the caller can send it.
        let mut raw_tx = vec![];
        tx.write(&mut raw_tx).unwrap();
        Some(raw_tx.into_boxed_slice())
    }
}
