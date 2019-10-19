use super::LightWallet;

use bip39::{Mnemonic, Language};

pub struct BugBip39Derivation {}

impl BugBip39Derivation {

    pub fn has_bug(wallet: &LightWallet) -> bool {
        if wallet.zaddress.read().unwrap().len() <= 1 {
            return false;
        }

        // The seed bytes is the raw entropy. To pass it to HD wallet generation, 
        // we need to get the 64 byte bip39 entropy
        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&wallet.seed, Language::English).unwrap(), "");

        // Check z addresses
        for pos in 0..wallet.zaddress.read().unwrap().len() {
            let (_, _, address) =
                LightWallet::get_zaddr_from_bip39seed(&wallet.config, &bip39_seed.as_bytes(), pos as u32);

            if address != wallet.zaddress.read().unwrap()[pos] {
                return true;
            }
        }

        // Check t addresses
        for pos in 0..wallet.taddresses.read().unwrap().len() {
            let sk = LightWallet::get_taddr_from_bip39seed(&wallet.config, &bip39_seed.as_bytes(), pos as u32);
            let address = wallet.address_from_sk(&sk);

            if address != wallet.taddresses.read().unwrap()[pos] {
                return true;
            }
        }

        false
    }
}