///
/// In v1.0 of zecwallet-cli, there was a bug that incorrectly derived HD wallet keys after the first key. That is, the 
/// first key, address was correct, but subsequent ones were not. 
/// 
/// The issue was that the 32-byte seed was directly being used to derive then subsequent addresses instead of the 
/// 64-byte pkdf2(seed). The issue affected both t and z addresses
/// 
/// To fix the bug, we need to:
/// 1. Check if the wallet has more than 1 address for t or z addresses
/// 2. Move any funds in these addresses to the first address
/// 3. Re-derive the addresses

use super::LightWallet;
use crate::lightclient::LightClient;

use json::object;
use bip39::{Mnemonic, Language};

pub struct BugBip39Derivation {}

impl BugBip39Derivation {

    /// Check if this bug exists in the wallet
    pub fn has_bug(client: &LightClient) -> bool {
        let wallet = client.wallet.read().unwrap();

        if wallet.zaddress.read().unwrap().len() <= 1 {
            return false;
        }

        if wallet.is_encrypted() {
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

    /// Automatically fix the bug if it exists in the wallet
    pub fn fix_bug(client: &LightClient) -> String {
        use zcash_primitives::transaction::components::amount::DEFAULT_FEE;
        use std::convert::TryInto;

        if !BugBip39Derivation::has_bug(client) {
            let r = object!{
                "has_bug" => false
            };

            return r.pretty(2);
        } 
        
        // Tranfer money
        // 1. The desination is z address #0
        println!("Sending funds to ourself.");
        let zaddr = client.do_address()["z_addresses"][0].as_str().unwrap().to_string();
        let balance_json = client.do_balance();
        let amount: u64 =  balance_json["zbalance"].as_u64().unwrap() 
                         + balance_json["tbalance"].as_u64().unwrap();

        let txid = if amount > 0 {
            let fee: u64 = DEFAULT_FEE.try_into().unwrap();
            match client.do_send(vec![(&zaddr, amount-fee, None)]) {
                Ok(txid) => txid,
                Err(e) => {
                    let r = object!{
                        "has_bug" => true,
                        "fixed"   => false,
                        "error"   => e,
                    };

                    return r.pretty(2);
                }
            }
        } else {
            "".to_string()
        };


        // regen addresses
        let wallet = client.wallet.read().unwrap();
        let num_zaddrs = wallet.zaddress.read().unwrap().len();
        let num_taddrs = wallet.taddresses.read().unwrap().len();

        wallet.extsks.write().unwrap().truncate(1);
        wallet.extfvks.write().unwrap().truncate(1);
        wallet.zaddress.write().unwrap().truncate(1);

        wallet.tkeys.write().unwrap().truncate(1);
        wallet.taddresses.write().unwrap().truncate(1);

        for _ in 1..num_zaddrs {
            wallet.add_zaddr();
        }

        for _ in 1..num_taddrs {
            wallet.add_taddr();
        }

        let r = object!{
            "has_bug" => true,
            "fixed"   => true,
            "txid"    => txid,
        };

        return r.pretty(2);
    }
}