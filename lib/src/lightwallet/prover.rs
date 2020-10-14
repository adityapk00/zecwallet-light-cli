//! Abstractions over the proving system and parameters for ease of use.
use bls12_381::Bls12;
use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey};
use zcash_primitives::{
    primitives::{Diversifier, PaymentAddress, ProofGenerationKey, Rseed},
    redjubjub::{PublicKey, Signature},
    transaction::components::Amount
};
use zcash_primitives::{
    merkle_tree::{MerklePath},
    prover::TxProver, sapling::Node,
    transaction::components::GROTH_PROOF_SIZE,
};
use zcash_proofs::sapling::SaplingProvingContext;

/// An implementation of [`TxProver`] using Sapling Spend and Output parameters provided
/// in-memory.
pub struct InMemTxProver {
    spend_params: Parameters<Bls12>,
    spend_vk: PreparedVerifyingKey<Bls12>,
    output_params: Parameters<Bls12>,
}

impl InMemTxProver {
    pub fn new(spend_params: &[u8], output_params: &[u8]) -> Self {
        // Deserialize params
        let spend_params = Parameters::<Bls12>::read(spend_params, false)
            .expect("couldn't deserialize Sapling spend parameters file");
        let output_params = Parameters::<Bls12>::read(output_params, false)
            .expect("couldn't deserialize Sapling spend parameters file");

        // Prepare verifying keys
        let spend_vk = prepare_verifying_key(&spend_params.vk);

        InMemTxProver {
            spend_params,
            spend_vk,
            output_params,
        }
    }
}

impl TxProver for InMemTxProver {
    type SaplingProvingContext = SaplingProvingContext;

    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {
        SaplingProvingContext::new()
    }

    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        anchor: bls12_381::Scalar,
        witness: MerklePath<Node>,
    ) -> Result<
        ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey),
        (),
    > {
        let (proof, cv, rk) = ctx.spend_proof(
            proof_generation_key,
            diversifier,
            rseed,
            ar,
            value,
            anchor,
            witness,
            &self.spend_params,
            &self.spend_vk,
        )?;

        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .expect("should be able to serialize a proof");

        Ok((zkproof, cv, rk))
    }

    fn output_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: u64,
    ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
        let (proof, cv) = ctx.output_proof(
            esk,
            payment_address,
            rcm,
            value,
            &self.output_params
        );

        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .expect("should be able to serialize a proof");

        (zkproof, cv)
    }

    fn binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        value_balance: Amount,
        sighash: &[u8; 32],
    ) -> Result<Signature, ()> {
        ctx.binding_sig(value_balance, sighash)
    }
}
