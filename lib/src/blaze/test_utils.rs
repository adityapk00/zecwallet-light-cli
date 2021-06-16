use std::sync::Arc;

use crate::{
    compact_formats::{CompactBlock, CompactOutput, CompactSpend, CompactTx},
    lightclient::test_server::TestServerData,
    lightwallet::data::BlockData,
};
use ff::{Field, PrimeField};
use group::GroupEncoding;
use jubjub::ExtendedPoint;
use prost::Message;
use rand::{rngs::OsRng, RngCore};
use tokio::sync::RwLock;

use zcash_primitives::{
    block::BlockHash,
    constants::SPENDING_KEY_GENERATOR,
    memo::Memo,
    merkle_tree::{CommitmentTree, Hashable, IncrementalWitness, MerklePath},
    note_encryption::SaplingNoteEncryption,
    primitives::{Diversifier, Note, Nullifier, PaymentAddress, ProofGenerationKey, Rseed, ValueCommitment},
    prover::TxProver,
    redjubjub::Signature,
    sapling::Node,
    transaction::{
        components::{Amount, OutputDescription, GROTH_PROOF_SIZE},
        Transaction, TransactionData,
    },
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
};
use zcash_proofs::sapling::SaplingProvingContext;

pub fn random_u8_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);

    b
}

pub fn tree_to_string(tree: &CommitmentTree<Node>) -> String {
    let mut b1 = vec![];
    tree.write(&mut b1).unwrap();
    hex::encode(b1)
}

pub fn incw_to_string(inc_witness: &IncrementalWitness<Node>) -> String {
    let mut b1 = vec![];
    inc_witness.write(&mut b1).unwrap();
    hex::encode(b1)
}

pub fn node_to_string(n: &Node) -> String {
    let mut b1 = vec![];
    n.write(&mut b1).unwrap();
    hex::encode(b1)
}

pub fn list_all_witness_nodes(cb: &CompactBlock) -> Vec<Node> {
    let mut nodes = vec![];
    for tx in &cb.vtx {
        for co in &tx.outputs {
            nodes.push(Node::new(co.cmu().unwrap().into()))
        }
    }

    nodes
}

pub struct FakeCompactBlock {
    pub block: CompactBlock,
    pub height: u64,
}

impl FakeCompactBlock {
    pub fn new(height: u64, prev_hash: BlockHash) -> Self {
        // Create a fake Note for the account
        let mut rng = OsRng;

        let mut cb = CompactBlock::default();

        cb.height = height;
        cb.hash.resize(32, 0);
        rng.fill_bytes(&mut cb.hash);

        cb.prev_hash.extend_from_slice(&prev_hash.0);

        Self { block: cb, height }
    }

    pub fn add_txs(&mut self, ctxs: Vec<CompactTx>) {
        self.block.vtx.extend(ctxs);
    }

    // Add a new tx into the block, paying the given address the amount.
    // Returns the nullifier of the new note.
    pub fn add_random_tx(&mut self, num_outputs: usize) {
        let xsk_m = ExtendedSpendingKey::master(&[1u8; 32]);
        let extfvk = ExtendedFullViewingKey::from(&xsk_m);

        let to = extfvk.default_address().unwrap().1;
        let value = Amount::from_u64(1).unwrap();

        let mut ctx = CompactTx::default();
        ctx.hash = random_u8_32().to_vec();

        for _ in 0..num_outputs {
            // Create a fake Note for the account
            let note = Note {
                g_d: to.diversifier().g_d().unwrap(),
                pk_d: to.pk_d().clone(),
                value: value.into(),
                rseed: Rseed::AfterZip212(random_u8_32()),
            };

            // Create a fake CompactBlock containing the note
            let mut cout = CompactOutput::default();
            cout.cmu = note.cmu().to_bytes().to_vec();

            ctx.outputs.push(cout);
        }

        self.block.vtx.push(ctx);
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut b = vec![];
        self.block.encode(&mut b).unwrap();

        b
    }

    pub fn into(self) -> CompactBlock {
        self.block
    }
}

pub struct FakeCompactBlockList {
    pub blocks: Vec<FakeCompactBlock>,
    pub txns: Vec<(Transaction, u64)>,
    pub prev_hash: BlockHash,
    pub next_height: u64,
}

impl FakeCompactBlockList {
    pub fn new(len: u64) -> Self {
        let mut s = Self {
            blocks: vec![],
            txns: vec![],
            prev_hash: BlockHash([0u8; 32]),
            next_height: 1,
        };

        s.add_blocks(len);

        s
    }

    pub async fn add_pending_sends(&mut self, data: &Arc<RwLock<TestServerData>>) {
        let sent_txns = data.write().await.sent_txns.split_off(0);

        let new_block = self.add_empty_block();

        for rtx in sent_txns {
            let tx = Transaction::read(&rtx.data[..]).unwrap();
            let mut ctx = CompactTx::default();

            for out in &tx.shielded_outputs {
                let mut cout = CompactOutput::default();
                cout.cmu = out.cmu.to_repr().to_vec();
                cout.epk = out.ephemeral_key.to_bytes().to_vec();
                cout.ciphertext = out.enc_ciphertext[..52].to_vec();

                ctx.outputs.push(cout);
            }

            for spend in &tx.shielded_spends {
                let mut cs = CompactSpend::default();
                cs.nf = spend.nullifier.to_vec();

                ctx.spends.push(cs);
            }

            data.write().await.add_txns(vec![(tx.clone(), new_block.height)]);

            ctx.hash = tx.txid().0.to_vec();
            new_block.add_txs(vec![ctx]);
        }
    }

    // Add a new tx into the block, paying the given address the amount.
    // Returns the nullifier of the new note.
    pub fn add_tx_paying(&mut self, extfvk: &ExtendedFullViewingKey, value: u64) -> (Nullifier, Transaction, u64) {
        let to = extfvk.default_address().unwrap().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let note = Note {
            g_d: to.diversifier().g_d().unwrap(),
            pk_d: to.pk_d().clone(),
            value,
            rseed: Rseed::BeforeZip212(jubjub::Fr::random(rng)),
        };
        let nf = note.nf(&extfvk.fvk.vk, 0);

        let mut encryptor =
            SaplingNoteEncryption::new(None, note.clone(), to.clone(), Memo::default().into(), &mut rng);

        let mut rng = OsRng;
        let rcv = jubjub::Fr::random(&mut rng);
        let cv = ValueCommitment {
            value,
            randomness: rcv.clone(),
        };

        let cmu = note.cmu();
        let od = OutputDescription {
            cv: cv.commitment().into(),
            cmu: note.cmu(),
            ephemeral_key: ExtendedPoint::from(*encryptor.epk()),
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv.commitment().into(), &cmu),
            zkproof: [0; GROTH_PROOF_SIZE],
        };

        let mut cmu = vec![];
        cmu.extend_from_slice(&note.cmu().to_repr());
        let mut epk = vec![];
        epk.extend_from_slice(&encryptor.epk().to_bytes());
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cout = CompactOutput::default();
        cout.cmu = cmu;
        cout.epk = epk;
        cout.ciphertext = enc_ciphertext[..52].to_vec();

        let mut td = TransactionData::new();
        td.shielded_outputs.push(od);
        td.binding_sig = Signature::read(&vec![0u8; 64][..]).ok();
        let tx = td.freeze().unwrap();
        let height = self.next_height;
        self.txns.push((tx.clone(), height));

        let mut ctx = CompactTx::default();
        ctx.hash = tx.txid().clone().0.to_vec();
        ctx.outputs.push(cout);

        self.add_empty_block().add_txs(vec![ctx]);

        (nf, tx, height)
    }

    pub fn add_empty_block(&mut self) -> &'_ mut FakeCompactBlock {
        let newblk = FakeCompactBlock::new(self.next_height, self.prev_hash);
        self.next_height += 1;
        self.prev_hash = newblk.block.hash();

        self.blocks.push(newblk);
        self.blocks.last_mut().unwrap()
    }

    pub fn add_blocks(&mut self, len: u64) -> &mut Self {
        let nexth = self.next_height;

        for i in nexth..(nexth + len) {
            let mut b = FakeCompactBlock::new(i, self.prev_hash);

            self.next_height = i + 1;
            self.prev_hash = b.block.hash();

            // Add 2 transactions, each with some random Compact Outputs to this block
            for _ in 0..2 {
                b.add_random_tx(2);
            }

            self.blocks.push(b);
        }

        self
    }

    pub fn into_blockdatas(&mut self) -> Vec<BlockData> {
        let blocks = self.blocks.drain(..).collect::<Vec<_>>();

        blocks.into_iter().map(|fcb| BlockData::new(fcb.into())).rev().collect()
    }

    pub fn into_compact_blocks(&mut self) -> Vec<CompactBlock> {
        let blocks = self.blocks.drain(..).collect::<Vec<_>>();

        blocks.into_iter().map(|fcb| fcb.block).rev().collect()
    }

    pub fn into_txns(&mut self) -> Vec<(Transaction, u64)> {
        self.txns.drain(..).collect()
    }
}

pub struct FakeTxProver {}

impl TxProver for FakeTxProver {
    type SaplingProvingContext = SaplingProvingContext;

    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {
        SaplingProvingContext::new()
    }

    fn spend_proof(
        &self,
        _ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        _diversifier: Diversifier,
        _rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        _anchor: bls12_381::Scalar,
        _merkle_path: MerklePath<Node>,
    ) -> Result<
        (
            [u8; GROTH_PROOF_SIZE],
            jubjub::ExtendedPoint,
            zcash_primitives::redjubjub::PublicKey,
        ),
        (),
    > {
        let zkproof = [0u8; GROTH_PROOF_SIZE];

        let mut rng = OsRng;

        // We create the randomness of the value commitment
        let rcv = jubjub::Fr::random(&mut rng);
        let cv = ValueCommitment { value, randomness: rcv };
        // Compute value commitment
        let value_commitment: jubjub::ExtendedPoint = cv.commitment().into();

        let rk = zcash_primitives::redjubjub::PublicKey(proof_generation_key.ak.clone().into())
            .randomize(ar, SPENDING_KEY_GENERATOR);

        Ok((zkproof, value_commitment, rk))
    }

    fn output_proof(
        &self,
        _ctx: &mut Self::SaplingProvingContext,
        _esk: jubjub::Fr,
        _payment_address: PaymentAddress,
        _rcm: jubjub::Fr,
        value: u64,
    ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
        let zkproof = [0u8; GROTH_PROOF_SIZE];

        let mut rng = OsRng;

        // We create the randomness of the value commitment
        let rcv = jubjub::Fr::random(&mut rng);

        let cv = ValueCommitment { value, randomness: rcv };
        // Compute value commitment
        let value_commitment: jubjub::ExtendedPoint = cv.commitment().into();
        (zkproof, value_commitment)
    }

    fn binding_sig(
        &self,
        _ctx: &mut Self::SaplingProvingContext,
        _value_balance: Amount,
        _sighash: &[u8; 32],
    ) -> Result<Signature, ()> {
        let fake_bytes = vec![0u8; 64];
        Signature::read(&fake_bytes[..]).map_err(|_e| ())
    }
}
