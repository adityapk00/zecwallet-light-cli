use std::io::{self, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use zcash_primitives::{
    block::BlockHash,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::Node,
    serialize::{Vector, Optional},
    transaction::{
        components::{OutPoint}, 
        TxId,
    },
    note_encryption::{Memo,},
    zip32::{ExtendedFullViewingKey,},
    primitives::{Diversifier, Note, Rseed},
};
use zcash_primitives::zip32::ExtendedSpendingKey;
use super::walletzkey::WalletZKey;


pub struct BlockData {
    pub height: i32,
    pub hash: BlockHash,
    pub tree: CommitmentTree<Node>,
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
    pub(super) account: usize,

    // Technically, this should be recoverable from the account number, 
    // but we're going to refactor this in the future, so I'll write it again here.
    pub(super) extfvk: ExtendedFullViewingKey, 
    
    pub diversifier: Diversifier,
    pub note: Note,
    pub(super) witnesses: Vec<IncrementalWitness<Node>>,
    pub(super) nullifier: [u8; 32],
    pub spent: Option<TxId>,             // If this note was confirmed spent
    pub spent_at_height: Option<i32>,    // The height at which this note was spent

    // If this note was spent in a send, but has not yet been confirmed.
    // Contains the txid and height at which it was broadcast
    pub unconfirmed_spent: Option<(TxId, u32)>, 
    pub memo:  Option<Memo>,
    pub is_change: bool,

    // If the spending key is available in the wallet (i.e., whether to keep witness up-to-date)
    pub have_spending_key: bool,         
}

// Reading a note also needs the corresponding address to read from.
fn read_rseed<R: Read>(mut reader: R) -> io::Result<Rseed> {
    let note_type = reader.read_u8()?;
    
    let mut r_bytes: [u8; 32] = [0; 32];
    reader.read_exact(&mut r_bytes)?;

    let r = match note_type {
        1 => {
            Rseed::BeforeZip212(jubjub::Fr::from_bytes(&r_bytes).unwrap())
        },
        2 => {
            Rseed::AfterZip212(r_bytes)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Bad note type"))
    };

    Ok(r)
}

fn write_rseed<W: Write>(mut writer: W, rseed: &Rseed) -> io::Result<()> {
    let note_type = match rseed {
        Rseed::BeforeZip212(_) => 1,
        Rseed::AfterZip212(_) => 2,
    };
    writer.write_u8(note_type)?;

    match rseed {
        Rseed::BeforeZip212(fr) => writer.write_all(&fr.to_bytes()),
        Rseed::AfterZip212(b) => writer.write_all(b)
    }
}

impl SaplingNoteData {
    fn serialized_version() -> u64 {
        5
    }

    pub fn new(
        walletkey: &WalletZKey,
        output: zcash_client_backend::wallet::WalletShieldedOutput
    ) -> Self {
        let witness = output.witness;

        let have_spending_key = walletkey.have_spending_key();

        let nf = {
            let mut nf = [0; 32];
            nf.copy_from_slice(
                &output
                    .note
                    .nf(&walletkey.extfvk.fvk.vk, witness.position() as u64),
            );
            nf
        };

        SaplingNoteData {
            account: output.account,
            extfvk: walletkey.extfvk.clone(),
            diversifier: *output.to.diversifier(),
            note: output.note,
            witnesses: if have_spending_key {vec![witness]} else {vec![]},
            nullifier: nf,
            spent: None,
            spent_at_height: None,
            unconfirmed_spent: None,
            memo: None,
            is_change: output.is_change,
            have_spending_key,
        }
    }

    // Reading a note also needs the corresponding address to read from.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;

        let account = reader.read_u64::<LittleEndian>()? as usize;
        
        let extfvk = ExtendedFullViewingKey::read(&mut reader)?;

        let mut diversifier_bytes = [0u8; 11];
        reader.read_exact(&mut diversifier_bytes)?;
        let diversifier = Diversifier{0: diversifier_bytes};

        // To recover the note, read the value and r, and then use the payment address
        // to recreate the note
        let (value, rseed) = if version <= 3 {
            let value = reader.read_u64::<LittleEndian>()?;

            let mut r_bytes: [u8; 32] = [0; 32];
            reader.read_exact(&mut r_bytes)?;
        
            let r = jubjub::Fr::from_bytes(&r_bytes).unwrap();
        
            (value, Rseed::BeforeZip212(r))
        } else {
            let value = reader.read_u64::<LittleEndian>()?;
            let rseed = read_rseed(&mut reader)?;

            (value, rseed)
        };
        
        let maybe_note = extfvk.fvk.vk.to_payment_address(diversifier).unwrap().create_note(value, rseed);

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

        let spent_at_height = if version >=2 {
            Optional::read(&mut reader, |r| r.read_i32::<LittleEndian>())?
        } else {
            None
        };

        let unconfirmed_spent = if version <= 4 { None } else {
            Optional::read(&mut reader, |r| {
                let mut txbytes = [0u8; 32];
                r.read_exact(&mut txbytes)?;

                let height = r.read_u32::<LittleEndian>()?;
                Ok((TxId{0: txbytes}, height))
            })?
        };

        let memo = Optional::read(&mut reader, |r| {
            let mut memo_bytes = [0u8; 512];
            r.read_exact(&mut memo_bytes)?;
            match Memo::from_bytes(&memo_bytes) {
                Some(m) => Ok(m),
                None    => Err(io::Error::new(io::ErrorKind::InvalidInput, "Couldn't create the memo"))
            }
        })?;

        let is_change: bool = reader.read_u8()? > 0;

        let have_spending_key = if version <= 2 {
            true // Will get populated in the lightwallet::read() method, for now assume true
        } else {
            reader.read_u8()? > 0
        };

        Ok(SaplingNoteData {
            account,
            extfvk,
            diversifier,
            note,
            witnesses,
            nullifier,
            spent,
            spent_at_height,
            unconfirmed_spent,
            memo,
            is_change,
            have_spending_key,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write a version number first, so we can later upgrade this if needed.
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        writer.write_u64::<LittleEndian>(self.account as u64)?;

        self.extfvk.write(&mut writer)?;

        writer.write_all(&self.diversifier.0)?;

        // Writing the note means writing the note.value and note.r. The Note is recoverable
        // from these 2 values and the Payment address.
        writer.write_u64::<LittleEndian>(self.note.value)?;

        write_rseed(&mut writer, &self.note.rseed)?;

        Vector::write(&mut writer, &self.witnesses, |wr, wi| wi.write(wr) )?;

        writer.write_all(&self.nullifier)?;
        Optional::write(&mut writer, &self.spent, |w, t| w.write_all(&t.0))?;

        Optional::write(&mut writer, &self.spent_at_height, |w, h| w.write_i32::<LittleEndian>(*h))?;

        Optional::write(&mut writer, &self.unconfirmed_spent, |w, (txid, height)| {
            w.write_all(&txid.0)?;
            w.write_u32::<LittleEndian>(*height)
        })?;

        Optional::write(&mut writer, &self.memo, |w, m| w.write_all(m.as_bytes()))?;

        writer.write_u8(if self.is_change {1} else {0})?;

        writer.write_u8(if self.have_spending_key {1} else {0})?;

        // Note that we don't write the unconfirmed_spent field, because if the wallet is restarted,
        // we don't want to be beholden to any expired txns

        Ok(())
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

    pub spent_at_height: Option<i32>,
    pub spent: Option<TxId>,             // If this utxo was confirmed spent

    // If this utxo was spent in a send, but has not yet been confirmed.
    // Contains the txid and height at which the Tx was broadcast
    pub unconfirmed_spent: Option<(TxId, u32)>, 
}

impl Utxo {
    pub fn serialized_version() -> u64 {
        return 3;
    }

    pub fn to_outpoint(&self) -> OutPoint {
        OutPoint::new(self.txid.0, self.output_index as u32)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        assert!(version <= Self::serialized_version());

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

        let spent_at_height = if version <= 1 { None } else {
            Optional::read(&mut reader, |r| {
                r.read_i32::<LittleEndian>()
            })?
        };

        let unconfirmed_spent = if version <= 2 {
            None
        } else {
            Optional::read(&mut reader, |r| {
                let mut txbytes = [0u8; 32];
                r.read_exact(&mut txbytes)?;

                let height = r.read_u32::<LittleEndian>()?;
                Ok((TxId{0: txbytes}, height))
            })?
        };

        Ok(Utxo {
            address,
            txid,
            output_index,
            script,
            value,
            height,
            spent_at_height,
            spent,
            unconfirmed_spent,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        writer.write_u32::<LittleEndian>(self.address.as_bytes().len() as u32)?;
        writer.write_all(self.address.as_bytes())?;

        writer.write_all(&self.txid.0)?;

        writer.write_u64::<LittleEndian>(self.output_index)?;
        writer.write_u64::<LittleEndian>(self.value)?;
        writer.write_i32::<LittleEndian>(self.height)?;

        Vector::write(&mut writer, &self.script, |w, b| w.write_all(&[*b]))?;

        Optional::write(&mut writer, &self.spent, |w, txid| w.write_all(&txid.0))?;

        Optional::write(&mut writer, &self.spent_at_height, |w, s| w.write_i32::<LittleEndian>(*s))?;

        Optional::write(&mut writer, &self.unconfirmed_spent, |w, (txid, height)| {
            w.write_all(&txid.0)?;
            w.write_u32::<LittleEndian>(*height)
        })?;

        Ok(())
    }
}

pub struct OutgoingTxMetadata {
    pub address: String,
    pub value  : u64,
    pub memo   : Memo,
}

impl OutgoingTxMetadata {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let address_len = reader.read_u64::<LittleEndian>()?;
        let mut address_bytes = vec![0; address_len as usize];
        reader.read_exact(&mut address_bytes)?;
        let address = String::from_utf8(address_bytes).unwrap();

        let value = reader.read_u64::<LittleEndian>()?;

        let mut memo_bytes = [0u8; 512];
        reader.read_exact(&mut memo_bytes)?;
        let memo = Memo::from_bytes(&memo_bytes).unwrap();

        Ok(OutgoingTxMetadata{
            address,
            value,
            memo,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Strings are written as len + utf8
        writer.write_u64::<LittleEndian>(self.address.as_bytes().len() as u64)?;
        writer.write_all(self.address.as_bytes())?;

        writer.write_u64::<LittleEndian>(self.value)?;
        writer.write_all(self.memo.as_bytes())
    }
}

pub struct WalletTx {
    // Block in which this tx was included
    pub block: i32,

    // Timestamp of Tx. Added in v4
    pub datetime: u64,

    // Txid of this transaction. It's duplicated here (It is also the Key in the HashMap that points to this
    // WalletTx in LightWallet::txs)
    pub txid: TxId,

    // List of all notes received in this tx. Some of these might be change notes.
    pub notes: Vec<SaplingNoteData>,

    // List of all Utxos received in this Tx. Some of these might be change notes
    pub utxos: Vec<Utxo>,

    // Total shielded value spent in this Tx. Note that this is the value of the wallet's notes spent.
    // Some change may be returned in one of the notes above. Subtract the two to get the actual value spent.
    // Also note that even after subtraction, you might need to account for transparent inputs and outputs
    // to make sure the value is accurate.
    pub total_shielded_value_spent: u64,

    // Total amount of transparent funds that belong to us that were spent in this Tx.
    pub total_transparent_value_spent : u64,

    // All outgoing sapling sends to addresses outside this wallet
    pub outgoing_metadata: Vec<OutgoingTxMetadata>,

    // Whether this TxID was downloaded from the server and scanned for Memos
    pub full_tx_scanned: bool,

    // Price of Zec when this Tx was created
    pub zec_price: Option<f64>,
}

impl WalletTx {
    pub fn serialized_version() -> u64 {
        return 5;
    }

    pub fn new(height: i32, datetime: u64, txid: &TxId, price: &Option<(u64, f64)>) -> Self {
        let zec_price = match price {
            None => None,
            Some((t, p)) => {
                // If the price was fetched within 24 hours of this Tx, we use the "current" price
                // else, we mark it as None, for the historical price fetcher to get
                if (*t as i64 - datetime as i64).abs() < 24 * 60 * 60 {
                    Some(*p)
                } else {
                    None
                }
            }
        };

        WalletTx {
            block: height,
            datetime,
            txid: txid.clone(),
            notes: vec![],
            utxos: vec![],
            total_shielded_value_spent: 0,
            total_transparent_value_spent: 0,
            outgoing_metadata: vec![],
            full_tx_scanned: false,
            zec_price,
        }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        assert!(version <= WalletTx::serialized_version());

        let block = reader.read_i32::<LittleEndian>()?;

        let datetime = if version >= 4 {
            reader.read_u64::<LittleEndian>()?
        } else {
            0
        };

        let mut txid_bytes = [0u8; 32];
        reader.read_exact(&mut txid_bytes)?;

        let txid = TxId{0: txid_bytes};

        let notes = Vector::read(&mut reader, |r| SaplingNoteData::read(r))?;
        let utxos = Vector::read(&mut reader, |r| Utxo::read(r))?;

        let total_shielded_value_spent = reader.read_u64::<LittleEndian>()?;
        let total_transparent_value_spent = reader.read_u64::<LittleEndian>()?;

        // Outgoing metadata was only added in version 2
        let outgoing_metadata = Vector::read(&mut reader, |r| OutgoingTxMetadata::read(r))?;

        let full_tx_scanned = reader.read_u8()? > 0;

        let zec_price = if version <= 4 { 
            None 
        } else { 
            Optional::read(&mut reader, |r| r.read_f64::<LittleEndian>())? 
        };
            
        Ok(WalletTx{
            block,
            datetime,
            txid,
            notes,
            utxos,
            total_shielded_value_spent,
            total_transparent_value_spent,
            outgoing_metadata,
            full_tx_scanned,
            zec_price,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(WalletTx::serialized_version())?;

        writer.write_i32::<LittleEndian>(self.block)?;

        writer.write_u64::<LittleEndian>(self.datetime)?;

        writer.write_all(&self.txid.0)?;

        Vector::write(&mut writer, &self.notes, |w, nd| nd.write(w))?;
        Vector::write(&mut writer, &self.utxos, |w, u| u.write(w))?;

        writer.write_u64::<LittleEndian>(self.total_shielded_value_spent)?;
        writer.write_u64::<LittleEndian>(self.total_transparent_value_spent)?;

        // Write the outgoing metadata
        Vector::write(&mut writer, &self.outgoing_metadata, |w, om| om.write(w))?;

        writer.write_u8(if self.full_tx_scanned {1} else {0})?;

        Optional::write(&mut writer, &self.zec_price, |w, p| w.write_f64::<LittleEndian>(*p))?;

        Ok(())
    }
}

pub struct SpendableNote {
    pub txid: TxId,
    pub nullifier: [u8; 32],
    pub diversifier: Diversifier,
    pub note: Note,
    pub witness: IncrementalWitness<Node>,
    pub extsk: ExtendedSpendingKey,
}

impl SpendableNote {
    pub fn from(txid: TxId, nd: &SaplingNoteData, anchor_offset: usize, extsk: &Option<ExtendedSpendingKey>) -> Option<Self> {
        // Include only notes that haven't been spent, or haven't been included in an unconfirmed spend yet.
        if nd.spent.is_none() && nd.unconfirmed_spent.is_none() && extsk.is_some() &&
                nd.witnesses.len() >= (anchor_offset + 1) {
            let witness = nd.witnesses.get(nd.witnesses.len() - anchor_offset - 1);

            witness.map(|w| SpendableNote {
                txid,
                nullifier: nd.nullifier,
                diversifier: nd.diversifier,
                note: nd.note.clone(),
                witness: w.clone(),
                extsk: extsk.clone().unwrap(),
            })
        } else {
            None
        }
    }
}


// Struct that tracks the latest and historical price of ZEC in the wallet
#[derive(Clone, Debug)]
pub struct WalletZecPriceInfo {
    // Latest price of ZEC and when it was fetched
    pub zec_price: Option<(u64, f64)>,

    // Wallet's currency. All the prices are in this currency
    pub currency: String,

    // When the last time historical prices were fetched
    pub last_historical_prices_fetched_at: Option<u64>,

    // Historical prices retry count
    pub historical_prices_retry_count: u64,   
}

impl WalletZecPriceInfo {
    pub fn new() -> Self {
        Self {
            zec_price: None,
            currency: "USD".to_string(), // Only USD is supported right now.
            last_historical_prices_fetched_at: None,
            historical_prices_retry_count: 0,
        }
    }

    
    pub fn serialized_version() -> u64 {
        return 1;
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        assert!(version <= Self::serialized_version());

        // The "current" zec price is not persisted, since it is almost certainly outdated
        let zec_price = None;

        // Currency is only USD for now
        let currency = "USD".to_string();

        let last_historical_prices_fetched_at = Optional::read(&mut reader, |r| r.read_u64::<LittleEndian>())?;
        let historical_prices_retry_count = reader.read_u64::<LittleEndian>()?;

        Ok(Self { zec_price, currency, last_historical_prices_fetched_at, historical_prices_retry_count })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        // We don't write the currency zec price or the currency yet. 
        Optional::write(&mut writer, &self.last_historical_prices_fetched_at, |w, t| w.write_u64::<LittleEndian>(*t))?;
        writer.write_u64::<LittleEndian>(self.historical_prices_retry_count)?;

        Ok(())
    }
}