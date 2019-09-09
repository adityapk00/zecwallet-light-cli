//! Structs for handling supported address types.

use pairing::bls12_381::Bls12;
use zcash_primitives::primitives::PaymentAddress;
use zcash_client_backend::encoding::{decode_payment_address, decode_transparent_address};
use zcash_primitives::legacy::TransparentAddress;

use zcash_client_backend::constants::testnet::{
    B58_PUBKEY_ADDRESS_PREFIX, B58_SCRIPT_ADDRESS_PREFIX, HRP_SAPLING_PAYMENT_ADDRESS,
};

/// An address that funds can be sent to.
pub enum RecipientAddress {
    Shielded(PaymentAddress<Bls12>),
    Transparent(TransparentAddress),
}

impl From<PaymentAddress<Bls12>> for RecipientAddress {
    fn from(addr: PaymentAddress<Bls12>) -> Self {
        RecipientAddress::Shielded(addr)
    }
}

impl From<TransparentAddress> for RecipientAddress {
    fn from(addr: TransparentAddress) -> Self {
        RecipientAddress::Transparent(addr)
    }
}

impl RecipientAddress {
    pub fn from_str(s: &str) -> Option<Self> {
        // Try to match a sapling z address 
        if let Some(pa) = match decode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, s) {
                                Ok(ret) => ret,
                                Err(_)  => None
                            } 
        {
            Some(RecipientAddress::Shielded(pa))    // Matched a shielded address
        } else if let Some(addr) = match decode_transparent_address(
                                            &B58_PUBKEY_ADDRESS_PREFIX, &B58_SCRIPT_ADDRESS_PREFIX, s) {
                                        Ok(ret) => ret,
                                        Err(_)  => None
                                    } 
        {
            Some(RecipientAddress::Transparent(addr))   // Matched a transparent address
        } else {
            None    // Didn't match anything
        }
    }
}
