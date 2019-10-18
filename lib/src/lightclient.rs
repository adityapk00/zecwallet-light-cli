use crate::lightwallet::LightWallet;

use log::{info, warn, error};
use rand::{rngs::OsRng, seq::SliceRandom};

use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, AtomicI32, AtomicUsize, Ordering};
use std::path::Path;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter, Error, ErrorKind};

use json::{object, array, JsonValue};
use zcash_primitives::transaction::{TxId, Transaction};
use zcash_client_backend::{
    constants::testnet, constants::mainnet, constants::regtest, encoding::encode_payment_address,
};

use crate::grpc_client::{BlockId};
use crate::grpcconnector::{self, *};
use crate::SaplingParams;
use crate::ANCHOR_OFFSET;

pub const DEFAULT_SERVER: &str = "https://lightd-main.zecwallet.co:443";
pub const WALLET_NAME: &str    = "zecwallet-light-wallet.dat";
pub const LOGFILE_NAME: &str   = "zecwallet-light-wallet.debug.log";


#[derive(Clone, Debug)]
pub struct LightClientConfig {
    pub server                      : http::Uri,
    pub chain_name                  : String,
    pub sapling_activation_height   : u64,
    pub consensus_branch_id         : String,
    pub anchor_offset               : u32,
    pub no_cert_verification        : bool,
}

impl LightClientConfig {

    pub fn create(server: http::Uri, dangerous: bool) -> io::Result<(LightClientConfig, u64)> {
        // Do a getinfo first, before opening the wallet
        let info = grpcconnector::get_info(server.clone(), dangerous)
            .map_err(|e| std::io::Error::new(ErrorKind::ConnectionRefused, e))?;

        // Create a Light Client Config
        let config = LightClientConfig {
            server,
            chain_name                  : info.chain_name,
            sapling_activation_height   : info.sapling_activation_height,
            consensus_branch_id         : info.consensus_branch_id,
            anchor_offset               : ANCHOR_OFFSET,
            no_cert_verification        : dangerous,
        };

        Ok((config, info.block_height))
    }

    pub fn get_zcash_data_path(&self) -> Box<Path> {
        let mut zcash_data_location; 
        if cfg!(target_os="macos") || cfg!(target_os="windows") {
            zcash_data_location = dirs::data_dir().expect("Couldn't determine app data directory!");
            zcash_data_location.push("Zcash");
        } else {
            zcash_data_location = dirs::home_dir().expect("Couldn't determine home directory!");
            zcash_data_location.push(".zcash");
        };

        match &self.chain_name[..] {
            "main" => {},
            "test" => zcash_data_location.push("testnet3"),
            "regtest" => zcash_data_location.push("regtest"),
            c         => panic!("Unknown chain {}", c),
        };

        zcash_data_location.into_boxed_path()
    }

    pub fn get_wallet_path(&self) -> Box<Path> {
        let mut wallet_location = self.get_zcash_data_path().into_path_buf();
        wallet_location.push(WALLET_NAME);
        
        wallet_location.into_boxed_path()
    }

    pub fn get_log_path(&self) -> Box<Path> {
        let mut log_path = self.get_zcash_data_path().into_path_buf();
        log_path.push(LOGFILE_NAME);

        log_path.into_boxed_path()
    }

    pub fn get_initial_state(&self) -> Option<(u64, &str, &str)> {
        match &self.chain_name[..] {
            "test" => Some((600000,
                        "0107385846c7451480912c294b6ce1ee1feba6c2619079fd9104f6e71e4d8fe7",
                        "01690698411e3f8badea7da885e556d7aba365a797e9b20b44ac0946dced14b23c001001ab2a18a5a86aa5d77e43b69071b21770b6fe6b3c26304dcaf7f96c0bb3fed74d000186482712fa0f2e5aa2f2700c4ed49ef360820f323d34e2b447b78df5ec4dfa0401a332e89a21afb073cb1db7d6f07396b56a95e97454b9bca5a63d0ebc575d3a33000000000001c9d3564eff54ebc328eab2e4f1150c3637f4f47516f879a0cfebdf49fe7b1d5201c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc5270145e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a000000011f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d39"
                      )),
            "main" => Some((610000,
                        "000000000218882f481e3b49ca3df819734b8d74aac91f69e848d7499b34b472",
                        "0192943f1eca6525cea7ea8e26b37c792593ed50cfe2be7a1ff551a08dc64b812f001000000001deef7ae5162a9942b4b9aa797137c5bdf60750e9548664127df99d1981dda66901747ad24d5daf294ce2a27aba923e16e52e7348eea3048c5b5654b99ab0a371200149d8aff830305beb3887529f6deb150ab012916c3ce88a6b47b78228f8bfeb3f01ff84a89890cfae65e0852bc44d9aa82be2c5d204f5aebf681c9e966aa46f540e000001d58f1dfaa9db0996996129f8c474acb813bfed452d347fb17ebac2e775e209120000000001319312241b0031e3a255b0d708750b4cb3f3fe79e3503fe488cc8db1dd00753801754bb593ea42d231a7ddf367640f09bbf59dc00f2c1d2003cc340e0c016b5b13"
            )),
            _ => None
        }
    }

    pub fn get_server_or_default(server: Option<String>) -> http::Uri {
        match server {
            Some(s) => {
                let mut s = if s.starts_with("http") {s} else { "http://".to_string() + &s};
                let uri: http::Uri = s.parse().unwrap();
                if uri.port_part().is_none() {
                    s = s + ":443";
                }
                s
            }
            None    => DEFAULT_SERVER.to_string()
        }.parse().unwrap()
    }

    pub fn get_coin_type(&self) -> u32 {
        match &self.chain_name[..] {
            "main"    => mainnet::COIN_TYPE,
            "test"    => testnet::COIN_TYPE,
            "regtest" => regtest::COIN_TYPE,
            c         => panic!("Unknown chain {}", c)
        }
    }

    pub fn hrp_sapling_address(&self) -> &str {
        match &self.chain_name[..] {
            "main"    => mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "test"    => testnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "regtest" => regtest::HRP_SAPLING_PAYMENT_ADDRESS,
            c         => panic!("Unknown chain {}", c)
        }
    }

    pub fn hrp_sapling_private_key(&self) -> &str {
        match &self.chain_name[..] {
            "main"    => mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            "test"    => testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            "regtest" => regtest::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            c         => panic!("Unknown chain {}", c)
        }
    }

    pub fn base58_pubkey_address(&self) -> [u8; 2] {
        match &self.chain_name[..] {
            "main"    => mainnet::B58_PUBKEY_ADDRESS_PREFIX,
            "test"    => testnet::B58_PUBKEY_ADDRESS_PREFIX,
            "regtest" => regtest::B58_PUBKEY_ADDRESS_PREFIX,
            c         => panic!("Unknown chain {}", c)
        }
    }


    pub fn base58_script_address(&self) -> [u8; 2] {
        match &self.chain_name[..] {
            "main"    => mainnet::B58_SCRIPT_ADDRESS_PREFIX,
            "test"    => testnet::B58_SCRIPT_ADDRESS_PREFIX,
            "regtest" => regtest::B58_SCRIPT_ADDRESS_PREFIX,
            c         => panic!("Unknown chain {}", c)
        }
    }

    pub fn base58_secretkey_prefix(&self) -> [u8; 1] {
        match &self.chain_name[..] {
            "main"    => [0x80],
            "test"    => [0xEF],
            "regtest" => [0xEF],
            c         => panic!("Unknown chain {}", c)
        }
    }
}

pub struct LightClient {
    pub wallet          : Arc<LightWallet>,

    pub config          : LightClientConfig,

    // zcash-params
    pub sapling_output  : Vec<u8>,
    pub sapling_spend   : Vec<u8>,
}

impl LightClient {
    
    pub fn set_wallet_initial_state(&self) {
        use std::convert::TryInto;

        let state = self.config.get_initial_state();

        match state {
            Some((height, hash, tree)) => self.wallet.set_initial_block(height.try_into().unwrap(), hash, tree),
            _ => true,
        };
    }

    pub fn new(seed_phrase: Option<String>, config: &LightClientConfig, latest_block: u64) -> io::Result<Self> {
        let mut lc = if config.get_wallet_path().exists() {
            // Make sure that if a wallet exists, there is no seed phrase being attempted
            if !seed_phrase.is_none() {
                return Err(Error::new(ErrorKind::AlreadyExists,
                    "Cannot create a new wallet from seed, because a wallet already exists"));
            }

            let mut file_buffer = BufReader::new(File::open(config.get_wallet_path())?);
            
            let wallet = LightWallet::read(&mut file_buffer, config)?;
             LightClient {
                wallet          : Arc::new(wallet),
                config          : config.clone(),
                sapling_output  : vec![], 
                sapling_spend   : vec![]
            }
        } else {
            let l = LightClient {
                wallet          : Arc::new(LightWallet::new(seed_phrase, config, latest_block)?),
                config          : config.clone(),
                sapling_output  : vec![], 
                sapling_spend   : vec![]
            };

            l.set_wallet_initial_state();

            l
        };

        info!("Read wallet with birthday {}", lc.wallet.get_first_tx_block());
        
        // Read Sapling Params
        lc.sapling_output.extend_from_slice(SaplingParams::get("sapling-output.params").unwrap().as_ref());
        lc.sapling_spend.extend_from_slice(SaplingParams::get("sapling-spend.params").unwrap().as_ref());

        info!("Created LightClient to {}", &config.server);

        Ok(lc)
    }

    pub fn last_scanned_height(&self) -> u64 {
        self.wallet.last_scanned_height() as u64
    }

    // Export private keys
    pub fn do_export(&self, addr: Option<String>) -> JsonValue {
        // Clone address so it can be moved into the closure
        let address = addr.clone();

        // Go over all z addresses
        let z_keys = self.wallet.get_z_private_keys().iter()
            .filter( move |(addr, _)| address.is_none() || address.as_ref() == Some(addr))
            .map( |(addr, pk)|
                object!{
                    "address"     => addr.clone(),
                    "private_key" => pk.clone()
                }
            ).collect::<Vec<JsonValue>>();

        // Clone address so it can be moved into the closure
        let address = addr.clone();

        // Go over all t addresses
        let t_keys = self.wallet.get_t_secret_keys().iter()
            .filter( move |(addr, _)| address.is_none() || address.as_ref() == Some(addr))
            .map( |(addr, sk)|
                object!{
                    "address"     => addr.clone(),
                    "private_key" => sk.clone(),
                }
            ).collect::<Vec<JsonValue>>();

        let mut all_keys = vec![];
        all_keys.extend_from_slice(&z_keys);
        all_keys.extend_from_slice(&t_keys);

        all_keys.into()
    }

    pub fn do_address(&self) -> JsonValue {
        // Collect z addresses
        let z_addresses = self.wallet.address.read().unwrap().iter().map( |ad| {
            encode_payment_address(self.config.hrp_sapling_address(), &ad)
        }).collect::<Vec<String>>();

        // Collect t addresses
        let t_addresses = self.wallet.tkeys.read().unwrap().iter().map( |sk| {
            self.wallet.address_from_sk(&sk)
        }).collect::<Vec<String>>();

        object!{
            "z_addresses" => z_addresses,
            "t_addresses" => t_addresses,
        }
    }

    pub fn do_balance(&self) -> JsonValue {
        // Collect z addresses
        let z_addresses = self.wallet.address.read().unwrap().iter().map( |ad| {
            let address = encode_payment_address(self.config.hrp_sapling_address(), &ad);
            object!{
                "address" => address.clone(),
                "zbalance" => self.wallet.zbalance(Some(address.clone())),
                "verified_zbalance" => self.wallet.verified_zbalance(Some(address)),
            }
        }).collect::<Vec<JsonValue>>();

        // Collect t addresses
        let t_addresses = self.wallet.tkeys.read().unwrap().iter().map( |sk| {
            let address = self.wallet.address_from_sk(&sk);

            // Get the balance for this address
            let balance = self.wallet.tbalance(Some(address.clone()));
            
            object!{
                "address" => address,
                "balance" => balance,
            }
        }).collect::<Vec<JsonValue>>();

        object!{
            "zbalance"           => self.wallet.zbalance(None),
            "verified_zbalance"  => self.wallet.verified_zbalance(None),
            "tbalance"           => self.wallet.tbalance(None),
            "z_addresses"        => z_addresses,
            "t_addresses"        => t_addresses,
        }
    }

    pub fn do_save(&self) -> String {
        let mut file_buffer = BufWriter::with_capacity(
            1_000_000, // 1 MB write buffer
            File::create(self.config.get_wallet_path()).unwrap());
        
        match self.wallet.write(&mut file_buffer) {
            Ok(_) => {
                info!("Saved wallet");
                let response = object!{
                    "result" => "success"
                };
                response.pretty(2)
            },
            Err(e) => {
                let err = format!("ERR: {}", e);
                error!("{}", err);
                err
            }
        }
    }

    pub fn get_server_uri(&self) -> http::Uri {
        self.config.server.clone()
    }

    pub fn do_info(&self) -> String {
        match get_info(self.get_server_uri(), self.config.no_cert_verification) {
            Ok(i) => {
                let o = object!{
                    "version" => i.version,
                    "vendor" => i.vendor,
                    "taddr_support" => i.taddr_support,
                    "chain_name" => i.chain_name,
                    "sapling_activation_height" => i.sapling_activation_height,
                    "consensus_branch_id" => i.consensus_branch_id,
                    "latest_block_height" => i.block_height
                };
                o.pretty(2)
            },
            Err(e) => e
        }
    }

    pub fn do_seed_phrase(&self) -> JsonValue {
        object!{
            "seed"     => self.wallet.get_seed_phrase(),
            "birthday" => self.wallet.get_birthday()
        }
    }

    // Return a list of all notes, spent and unspent
    pub fn do_list_notes(&self, all_notes: bool) -> JsonValue {
        let mut unspent_notes: Vec<JsonValue> = vec![];
        let mut spent_notes  : Vec<JsonValue> = vec![];
        let mut pending_notes: Vec<JsonValue> = vec![];

        // Collect Sapling notes
        self.wallet.txs.read().unwrap().iter()
            .flat_map( |(txid, wtx)| {
                wtx.notes.iter().filter_map(move |nd| 
                    if !all_notes && nd.spent.is_some() {
                        None
                    } else {
                        Some(object!{
                            "created_in_block"   => wtx.block,
                            "created_in_txid"    => format!("{}", txid),
                            "value"              => nd.note.value,
                            "is_change"          => nd.is_change,
                            "address"            => self.wallet.note_address(nd),
                            "spent"              => nd.spent.map(|spent_txid| format!("{}", spent_txid)),
                            "unconfirmed_spent"  => nd.unconfirmed_spent.map(|spent_txid| format!("{}", spent_txid)),
                        })
                    }
                )
            })
            .for_each( |note| {
                if note["spent"].is_null() && note["unconfirmed_spent"].is_null() {
                    unspent_notes.push(note);
                } else if !note["spent"].is_null() {
                    spent_notes.push(note);
                } else {
                    pending_notes.push(note);
                }
            });
        
        // Collect UTXOs
        let utxos = self.wallet.get_utxos().iter()
            .filter(|utxo| utxo.unconfirmed_spent.is_none())    // Filter out unconfirmed from the list of utxos
            .map(|utxo| {
                object!{
                    "created_in_block"   => utxo.height,
                    "created_in_txid"    => format!("{}", utxo.txid),
                    "value"              => utxo.value,
                    "scriptkey"          => hex::encode(utxo.script.clone()),
                    "is_change"          => false,  // TODO: Identify notes as change if we send change to taddrs
                    "address"            => utxo.address.clone(),
                    "spent"              => utxo.spent.map(|spent_txid| format!("{}", spent_txid)),
                    "unconfirmed_spent"  => utxo.unconfirmed_spent.map(|spent_txid| format!("{}", spent_txid)),
                }
            })
            .collect::<Vec<JsonValue>>();

        // Collect pending UTXOs
        let pending_utxos = self.wallet.get_utxos().iter()
            .filter(|utxo| utxo.unconfirmed_spent.is_some())    // Filter to include only unconfirmed utxos
            .map(|utxo| 
                object!{
                    "created_in_block"   => utxo.height,
                    "created_in_txid"    => format!("{}", utxo.txid),
                    "value"              => utxo.value,
                    "scriptkey"          => hex::encode(utxo.script.clone()),
                    "is_change"          => false,  // TODO: Identify notes as change if we send change to taddrs
                    "address"            => utxo.address.clone(),
                    "spent"              => utxo.spent.map(|spent_txid| format!("{}", spent_txid)),
                    "unconfirmed_spent"  => utxo.unconfirmed_spent.map(|spent_txid| format!("{}", spent_txid)),
                }
            )
            .collect::<Vec<JsonValue>>();

        let mut res = object!{
            "unspent_notes" => unspent_notes,
            "pending_notes" => pending_notes,
            "utxos"         => utxos,
            "pending_utxos" => pending_utxos,
        };

        if all_notes {
            res["spent_notes"] = JsonValue::Array(spent_notes);
        }

        // If all notes, also add historical utxos
        if all_notes {
            res["spent_utxos"] = JsonValue::Array(self.wallet.txs.read().unwrap().values()
                .flat_map(|wtx| {
                    wtx.utxos.iter()
                        .filter(|utxo| utxo.spent.is_some())
                        .map(|utxo| {
                            object!{
                                "created_in_block"   => wtx.block,
                                "created_in_txid"    => format!("{}", utxo.txid),
                                "value"              => utxo.value,
                                "scriptkey"          => hex::encode(utxo.script.clone()),
                                "is_change"          => false,  // TODO: Identify notes as change if we send change to taddrs
                                "address"            => utxo.address.clone(),
                                "spent"              => utxo.spent.map(|spent_txid| format!("{}", spent_txid)),
                                "unconfirmed_spent"  => utxo.unconfirmed_spent.map(|spent_txid| format!("{}", spent_txid)),
                            }
                        }).collect::<Vec<JsonValue>>()
                }).collect::<Vec<JsonValue>>()
            );
        }

        res
    }

    pub fn do_list_transactions(&self) -> JsonValue {
        // Create a list of TransactionItems
        let mut tx_list = self.wallet.txs.read().unwrap().iter()
            .flat_map(| (_k, v) | {
                let mut txns: Vec<JsonValue> = vec![];

                if v.total_shielded_value_spent > 0 {
                    // If money was spent, create a transaction. For this, we'll subtract
                    // all the change notes. TODO: Add transparent change here to subtract it also
                    let total_change: u64 = v.notes.iter()
                        .filter( |nd| nd.is_change )
                        .map( |nd| nd.note.value )
                        .sum();

                    // TODO: What happens if change is > than sent ?

                    // Collect outgoing metadata
                    let outgoing_json = v.outgoing_metadata.iter()
                        .map(|om| 
                            object!{
                                "address" => om.address.clone(),
                                "value"   => om.value,
                                "memo"    => LightWallet::memo_str(&Some(om.memo.clone())),
                        })
                        .collect::<Vec<JsonValue>>();                    

                    txns.push(object! {
                        "block_height" => v.block,
                        "txid"         => format!("{}", v.txid),
                        "amount"       => total_change as i64 
                                            - v.total_shielded_value_spent as i64 
                                            - v.total_transparent_value_spent as i64,
                        "outgoing_metadata" => outgoing_json,
                    });
                } 

                // For each sapling note that is not a change, add a Tx.
                txns.extend(v.notes.iter()
                    .filter( |nd| !nd.is_change )
                    .map ( |nd| 
                        object! {
                            "block_height" => v.block,
                            "txid"         => format!("{}", v.txid),
                            "amount"       => nd.note.value as i64,
                            "address"      => self.wallet.note_address(nd),
                            "memo"         => LightWallet::memo_str(&nd.memo),
                    })
                );

                // Get the total transparent received
                let total_transparent_received = v.utxos.iter().map(|u| u.value).sum::<u64>();
                if total_transparent_received > v.total_transparent_value_spent {
                    // Create an input transaction for the transparent value as well.
                    txns.push(object!{
                        "block_height" => v.block,
                        "txid"         => format!("{}", v.txid),
                        "amount"       => total_transparent_received as i64 - v.total_transparent_value_spent as i64,
                        "address"      => v.utxos.iter().map(|u| u.address.clone()).collect::<Vec<String>>().join(","),
                        "memo"         => None::<String>
                    })
                }

                txns
            })
            .collect::<Vec<JsonValue>>();

        tx_list.sort_by( |a, b| if a["block_height"] == b["block_height"] {
                                    a["txid"].as_str().cmp(&b["txid"].as_str())
                                } else {
                                    a["block_height"].as_i32().cmp(&b["block_height"].as_i32())
                                }
        );

        JsonValue::Array(tx_list)
    }

    /// Create a new address, deriving it from the seed.
    pub fn do_new_address(&self, addr_type: &str) -> JsonValue {
        let new_address = match addr_type {
            "z" => self.wallet.add_zaddr(),
            "t" => self.wallet.add_taddr(),
            _   => {
                let e = format!("Unrecognized address type: {}", addr_type);
                error!("{}", e);
                return object!{
                    "error" => e
                };
            }
        };

        array![new_address]
    }

    pub fn do_rescan(&self) -> String {
        info!("Rescan starting");
        // First, clear the state from the wallet
        self.wallet.clear_blocks();

        // Then set the initial block
        self.set_wallet_initial_state();
        
        // Then, do a sync, which will force a full rescan from the initial state
        let response = self.do_sync(true);
        info!("Rescan finished");

        response
    }

    pub fn do_sync(&self, print_updates: bool) -> String {
        // Sync is 3 parts
        // 1. Get the latest block
        // 2. Get all the blocks that we don't have
        // 3. Find all new Txns that don't have the full Tx, and get them as full transactions 
        //    and scan them, mainly to get the memos
        let mut last_scanned_height = self.wallet.last_scanned_height() as u64;

        // This will hold the latest block fetched from the RPC
        let latest_block_height = Arc::new(AtomicU64::new(0));
        let lbh = latest_block_height.clone();
        fetch_latest_block(&self.get_server_uri(), self.config.no_cert_verification, move |block: BlockId| {
                lbh.store(block.height, Ordering::SeqCst);
            });
        let latest_block = latest_block_height.load(Ordering::SeqCst);

        if latest_block < last_scanned_height {
            let w = format!("Server's latest block({}) is behind ours({})", latest_block, last_scanned_height);
            warn!("{}", w);
            return w;
        }

        info!("Latest block is {}", latest_block);

        // Get the end height to scan to.
        let mut end_height = std::cmp::min(last_scanned_height + 1000, latest_block);

        // If there's nothing to scan, just return
        if last_scanned_height == latest_block {
            info!("Nothing to sync, returning");
            return "".to_string();
        }

        // Count how many bytes we've downloaded
        let bytes_downloaded = Arc::new(AtomicUsize::new(0));

        let mut total_reorg = 0;

        // Collect all txns in blocks that we have a tx in. We'll fetch all these
        // txs along with our own, so that the server doesn't learn which ones
        // belong to us.
        let all_new_txs = Arc::new(RwLock::new(vec![]));

        // Fetch CompactBlocks in increments
        loop {
            let local_light_wallet = self.wallet.clone();
            let local_bytes_downloaded = bytes_downloaded.clone();

            let start_height = last_scanned_height + 1;
            info!("Start height is {}", start_height);

            // Show updates only if we're syncing a lot of blocks
            if print_updates && end_height - start_height > 100 {
                print!("Syncing {}/{}\r", start_height, latest_block);
                io::stdout().flush().ok().expect("Could not flush stdout");
            }

            // Fetch compact blocks
            info!("Fetching blocks {}-{}", start_height, end_height);
            let all_txs = all_new_txs.clone();

            let last_invalid_height = Arc::new(AtomicI32::new(0));
            let last_invalid_height_inner = last_invalid_height.clone();
            fetch_blocks(&self.get_server_uri(), start_height, end_height, self.config.no_cert_verification,
                move |encoded_block: &[u8], height: u64| {
                    // Process the block only if there were no previous errors
                    if last_invalid_height_inner.load(Ordering::SeqCst) > 0 {
                        return;
                    }

                    match local_light_wallet.scan_block(encoded_block) {
                        Ok(block_txns) => {
                            all_txs.write().unwrap().extend_from_slice(&block_txns.iter().map(|txid| (txid.clone(), height as i32)).collect::<Vec<_>>()[..]);
                        },
                        Err(invalid_height) => {
                            // Block at this height seems to be invalid, so invalidate up till that point
                            last_invalid_height_inner.store(invalid_height, Ordering::SeqCst);
                        }
                    };

                    local_bytes_downloaded.fetch_add(encoded_block.len(), Ordering::SeqCst);
            });

            // Check if there was any invalid block, which means we might have to do a reorg
            let invalid_height = last_invalid_height.load(Ordering::SeqCst);
            if invalid_height > 0 {
                total_reorg += self.wallet.invalidate_block(invalid_height);

                warn!("Invalidated block at height {}. Total reorg is now {}", invalid_height, total_reorg);
            }

            // Make sure we're not re-orging too much!
            if total_reorg > (crate::lightwallet::MAX_REORG - 1) as u64 {
                error!("Reorg has now exceeded {} blocks!", crate::lightwallet::MAX_REORG);
                return format!("Reorg has exceeded {} blocks. Aborting.", crate::lightwallet::MAX_REORG);
            } 
            
            if invalid_height > 0 {
                // Reset the scanning heights
                last_scanned_height = (invalid_height - 1) as u64;
                end_height = std::cmp::min(last_scanned_height + 1000, latest_block);

                warn!("Reorg: reset scanning from {} to {}", last_scanned_height, end_height);

                continue;
            }

            // If it got here, that means the blocks are scanning properly now. 
            // So, reset the total_reorg
            total_reorg = 0;

            // We'll also fetch all the txids that our transparent addresses are involved with
            // TODO: Use for all t addresses
            let address = self.wallet.address_from_sk(&self.wallet.tkeys.read().unwrap()[0]);
            let wallet = self.wallet.clone();
            fetch_transparent_txids(&self.get_server_uri(), address, start_height, end_height, self.config.no_cert_verification,
                move |tx_bytes: &[u8], height: u64 | {
                    let tx = Transaction::read(tx_bytes).unwrap();

                    // Scan this Tx for transparent inputs and outputs
                    wallet.scan_full_tx(&tx, height as i32); 
                }
            );
            
            last_scanned_height = end_height;
            end_height = last_scanned_height + 1000;

            if last_scanned_height >= latest_block {
                break;
            } else if end_height > latest_block {
                end_height = latest_block;
            }        
        }
        if print_updates{
            println!(""); // New line to finish up the updates
        }
        
        let mut responses = vec![];

        info!("Synced to {}, Downloaded {} kB", latest_block, bytes_downloaded.load(Ordering::SeqCst) / 1024);
        responses.push(format!("Synced to {}, Downloaded {} kB", latest_block, bytes_downloaded.load(Ordering::SeqCst) / 1024));
        
        // Get the Raw transaction for all the wallet transactions

        // We need to first copy over the Txids from the wallet struct, because
        // we need to free the read lock from here (Because we'll self.wallet.txs later)
        let mut txids_to_fetch: Vec<(TxId, i32)> = self.wallet.txs.read().unwrap().values()
            .filter(|wtx| wtx.full_tx_scanned == false)
            .map(|wtx| (wtx.txid, wtx.block))
            .collect::<Vec<(TxId, i32)>>();

        info!("Fetching {} new txids, total {} with decoy", txids_to_fetch.len(), all_new_txs.read().unwrap().len());
        txids_to_fetch.extend_from_slice(&all_new_txs.read().unwrap()[..]);
        txids_to_fetch.sort();
        txids_to_fetch.dedup();

        let mut rng = OsRng;        
        txids_to_fetch.shuffle(&mut rng);

        // And go and fetch the txids, getting the full transaction, so we can 
        // read the memos

        for (txid, height) in txids_to_fetch {
            let light_wallet_clone = self.wallet.clone();
            info!("Fetching full Tx: {}", txid);

            fetch_full_tx(&self.get_server_uri(), txid, self.config.no_cert_verification, move |tx_bytes: &[u8] | {
                let tx = Transaction::read(tx_bytes).unwrap();

                light_wallet_clone.scan_full_tx(&tx, height);
            });
        };

        responses.join("\n")
    }

    pub fn do_send(&self, addrs: Vec<(&str, u64, Option<String>)>) -> String {
        info!("Creating transaction");

        let rawtx = self.wallet.send_to_address(
            u32::from_str_radix(&self.config.consensus_branch_id, 16).unwrap(), 
            &self.sapling_spend, &self.sapling_output,
            addrs
        );
        
        match rawtx {
            Ok(txbytes)   => match broadcast_raw_tx(&self.get_server_uri(), self.config.no_cert_verification, txbytes) {
                Ok(k)  => k,
                Err(e) => e,
            },
            Err(e)        => format!("Error: No Tx to broadcast. Error was: {}", e)
        }
    }
}
