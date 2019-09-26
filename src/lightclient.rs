use crate::lightwallet::LightWallet;

use log::{info, warn, error};

use std::path::Path;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter, Error, ErrorKind};

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicI32, AtomicUsize, Ordering};

use json::{object, JsonValue};

use zcash_primitives::transaction::{TxId, Transaction};
use zcash_client_backend::{
    constants::testnet, constants::mainnet, constants::regtest, encoding::encode_payment_address,
};

use futures::Future;
use hyper::client::connect::{Destination, HttpConnector};
use tower_grpc::Request;
use tower_hyper::{client, util};
use tower_util::MakeService;
use futures::stream::Stream;

use crate::grpc_client::{ChainSpec, BlockId, BlockRange, RawTransaction, 
                         TransparentAddressBlockFilter, TxFilter, Empty, LightdInfo};
use crate::grpc_client::client::CompactTxStreamer;

// Used below to return the grpc "Client" type to calling methods
type Client = crate::grpc_client::client::CompactTxStreamer<tower_request_modifier::RequestModifier<tower_hyper::client::Connection<tower_grpc::BoxBody>, tower_grpc::BoxBody>>;

pub const DEFAULT_SERVER: &str = "http://3.15.168.203:9067";
pub const WALLET_NAME: &str    = "zeclite.wallet.dat";
pub const LOGFILE_NAME: &str   = "zeclite.debug.log";

#[derive(Clone, Debug)]
pub struct LightClientConfig {
    pub server                      : String,
    pub chain_name                  : String,
    pub sapling_activation_height   : u64,
    pub consensus_branch_id         : String,
}

impl LightClientConfig {
    pub fn get_params_path(&self, name: &str) -> Box<Path> {
        let mut params_location;

        if cfg!(target_os="macos") || cfg!(target_os="windows") {
            params_location  = dirs::data_dir()
                .expect("Couldn't determine app data directory!");
            params_location.push("ZcashParams");
        } else {
            params_location  = dirs::home_dir()
                .expect("Couldn't determine home directory!");
            params_location.push(".zcash-params");
        };

        params_location.push(name);
        params_location.into_boxed_path()
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
            "main" => Some((600000,
                        "00000000011502273e3726d1a229b69ae5088eeac650d787dcd5eabe1429ea38",
                        "017d2849ae4eca1bb7a1c78369373c3234b0b2205aeec7186b83da5970fe78100201f9375bb13cb285488c932b2dee1220589f490d4d83239371c260c80d5ffe1624100183daeacfa7985762de7e4442b854a07dab147fc2c8893ee986a2fb3db452c568019238d6a0c7a927deab0faee225cd2199c19a98a0dc29782ba6fd3213fed55031000130794486a8b9d78638a1688c520dbf70da1a912e94417fd8c8dd2d6d8363946b0001b6055deb04e1f5f4b9acc22f5ab2533e44d092f124cad08c7f4200d63dee666401427466a1604032d2080811e6a2a8b509d171fd9108bc24ec14f2b27c6155851c012bab0a6072d49eaa35808b886c0e5a0ab60e4bd554fff56c408dfed91b0d2e1301421e61e5b6edb6680d7868499753dd4b5bc8e6c4f61cb62b868836e8c105b13f00019549565919c2177d57bc5034bc222d75ec3bf56723ea7e1eb7c70dcf662f3d5b000188204c256935d05a22ccf0c273619854917c3af44f78d35c766f44570dfce65b01de9f824df05c82e5eb33ef429b4316605910a8a4aa28750440a379dc1593b2460001754bb593ea42d231a7ddf367640f09bbf59dc00f2c1d2003cc340e0c016b5b13"
            )),
            _ => None
        }
    }

    pub fn get_server_or_default(server: Option<String>) -> String {
        match server {
            Some(s) => if s.starts_with("http://") {s} else { "http://".to_string() + &s}
            None    => DEFAULT_SERVER.to_string()
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
        let mut f = match File::open(config.get_params_path("sapling-output.params")) {
            Ok(file) => file,
            Err(_) => return Err(Error::new(ErrorKind::NotFound, 
                            format!("Couldn't read {}", config.get_params_path("sapling-output.params").display())))
        };
        f.read_to_end(&mut lc.sapling_output)?;
        
        let mut f = match File::open(config.get_params_path("sapling-spend.params")) {
            Ok(file) => file,
            Err(_) => return Err(Error::new(ErrorKind::NotFound, 
                            format!("Couldn't read {}", config.get_params_path("sapling-spend.params").display())))
        };
        f.read_to_end(&mut lc.sapling_spend)?;

        info!("Created LightClient to {}", &config.server);
        println!("Lightclient connecting to {}", config.server);

        Ok(lc)
    }

    pub fn last_scanned_height(&self) -> u64 {
        self.wallet.last_scanned_height() as u64
    }

    // Export private keys
    pub fn do_export(&self, addr: Option<String>) -> json::JsonValue {
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

    pub fn do_address(&self) -> json::JsonValue {
        // Collect z addresses
        let z_addresses = self.wallet.address.iter().map( |ad| {
            encode_payment_address(self.config.hrp_sapling_address(), &ad)
        }).collect::<Vec<String>>();

        // Collect t addresses
        let t_addresses = self.wallet.tkeys.iter().map( |sk| {
            self.wallet.address_from_sk(&sk)
        }).collect::<Vec<String>>();

        object!{
            "z_addresses" => z_addresses,
            "t_addresses" => t_addresses,
        }
    }

    pub fn do_balance(&self) -> json::JsonValue {       
        // Collect z addresses
        let z_addresses = self.wallet.address.iter().map( |ad| {
            let address = encode_payment_address(self.config.hrp_sapling_address(), &ad);
            object!{
                "address" => address.clone(),
                "zbalance" => self.wallet.zbalance(Some(address.clone())),
                "verified_zbalance" => self.wallet.verified_zbalance(Some(address)),
            }
        }).collect::<Vec<JsonValue>>();

        // Collect t addresses
        let t_addresses = self.wallet.tkeys.iter().map( |sk| {
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
        
        self.wallet.write(&mut file_buffer).unwrap();
        info!("Saved wallet");

        format!("Saved Wallet")
    }

    pub fn get_server_uri(&self) -> http::Uri {
        self.config.server.parse().unwrap()
    }

    pub fn get_info(uri: http::Uri) -> LightdInfo {
        use std::cell::RefCell;

        let info = Arc::new(RefCell::<LightdInfo>::default());

        let info_inner = info.clone();
        let say_hello = LightClient::make_grpc_client(uri).unwrap()
            .and_then(move |mut client| {
                client.get_lightd_info(Request::new(Empty{}))
            })
            .and_then(move |response| {
                info_inner.replace(response.into_inner());

                Ok(())
            })
            .map_err(|e| {
                println!("ERR = {:?}", e);
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap();
        let ans = info.borrow().clone();

        ans
    }

    pub fn do_info(uri: http::Uri) -> String {
        format!("{:?}", LightClient::get_info(uri))
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
                    "is_change"          => false,  // TODO: Identify notes as change
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
                    "is_change"          => false,  // TODO: Identify notes as change
                    "address"            => utxo.address.clone(),
                    "spent"              => utxo.spent.map(|spent_txid| format!("{}", spent_txid)),
                    "unconfirmed_spent"  => utxo.unconfirmed_spent.map(|spent_txid| format!("{}", spent_txid)),
                }
            )
            .collect::<Vec<JsonValue>>();;

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
                                "is_change"          => false,  // TODO: Identify notes as change
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

                // Get the total transparent recieved
                let total_transparent_received = v.utxos.iter().map(|u| u.value).sum::<u64>();
                if total_transparent_received > v.total_transparent_value_spent {
                    // Create a input transaction for the transparent value as well.
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

    pub fn do_rescan(&self) -> String {
        info!("Rescan starting");
        // First, clear the state from the wallet
        self.wallet.clear_blocks();

        // Then set the inital block
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
        self.fetch_latest_block(move |block: BlockId| {
                lbh.store(block.height, Ordering::SeqCst);
            });
        let latest_block = latest_block_height.load(Ordering::SeqCst);

        info!("Latest block is {}", latest_block);

        // Get the end height to scan to.
        let mut end_height = std::cmp::min(last_scanned_height + 1000, latest_block);

        // If there's nothing to scan, just return
        if last_scanned_height == latest_block {
            return "".to_string();
        }

        // Count how many bytes we've downloaded
        let bytes_downloaded = Arc::new(AtomicUsize::new(0));

        let mut total_reorg = 0;

        // Fetch CompactBlocks in increments
        loop {
            let local_light_wallet = self.wallet.clone();
            let local_bytes_downloaded = bytes_downloaded.clone();

            let start_height = last_scanned_height + 1;

            // Show updates only if we're syncing a lot of blocks
            if print_updates && end_height - start_height > 100 {
                print!("Syncing {}/{}\r", start_height, latest_block);
                io::stdout().flush().ok().expect("Could not flush stdout");
            }

            // Fetch compact blocks
            info!("Fetching blocks {}-{}", start_height, end_height);
            
            let last_invalid_height = Arc::new(AtomicI32::new(0));
            let last_invalid_height_inner = last_invalid_height.clone();
            self.fetch_blocks(start_height, end_height, 
                move |encoded_block: &[u8]| {
                    // Process the block only if there were no previous errors
                    if last_invalid_height_inner.load(Ordering::SeqCst) > 0 {
                        return;
                    }

                    match local_light_wallet.scan_block(encoded_block) {
                        Ok(_) => {},
                        Err(invalid_height) => {
                            // Block at this height seems to be invalid, so invalidate up till that point
                            last_invalid_height_inner.store(invalid_height, Ordering::SeqCst);
                        }
                    }

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
            let address = self.wallet.address_from_sk(&self.wallet.tkeys[0]);
            let wallet = self.wallet.clone();
            self.fetch_transparent_txids(address, start_height, end_height, 
                move |tx_bytes: &[u8], height: u64 | {
                    let tx = Transaction::read(tx_bytes).unwrap();

                    // Scan this Tx for transparent inputs and outputs
                    wallet.scan_full_tx(&tx, height as i32);   // TODO: Add the height here!
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
        let txids_to_fetch: Vec<(TxId, i32)> = self.wallet.txs.read().unwrap().values()
            .filter(|wtx| wtx.full_tx_scanned == false)
            .map(|wtx| (wtx.txid, wtx.block))
            .collect::<Vec<(TxId, i32)>>();

        info!("Fetching {} new txids", txids_to_fetch.len());

        // And go and fetch the txids, getting the full transaction, so we can 
        // read the memos        
        for (txid, height) in txids_to_fetch {
            let light_wallet_clone = self.wallet.clone();
            info!("Fetching full Tx: {}", txid);
            responses.push(format!("Fetching full Tx: {}", txid));

            self.fetch_full_tx(txid, move |tx_bytes: &[u8] | {
                let tx = Transaction::read(tx_bytes).unwrap();

                light_wallet_clone.scan_full_tx(&tx, height);
            });
        };

        responses.join("\n")
    }

    pub fn do_send(&self, addr: &str, value: u64, memo: Option<String>) -> String {
        info!("Creating transaction");
        let rawtx = self.wallet.send_to_address(
            u32::from_str_radix(&self.config.consensus_branch_id, 16).unwrap(),   // Blossom ID
            &self.sapling_spend, &self.sapling_output,
            &addr, value, memo
        );
        
        match rawtx {
            Some(txbytes)   => self.broadcast_raw_tx(txbytes),
            None            => format!("No Tx to broadcast")
        }
    }

    pub fn fetch_blocks<F : 'static + std::marker::Send>(&self, start_height: u64, end_height: u64, c: F)
        where F : Fn(&[u8]) {
        // Fetch blocks
        let uri: http::Uri = self.get_server_uri();

        let dst = Destination::try_from_uri(uri.clone()).unwrap();
        let connector = util::Connector::new(HttpConnector::new(4));
        let settings = client::Builder::new().http2_only(true).clone();
        let mut make_client = client::Connect::with_builder(connector, settings);

        let say_hello = make_client
            .make_service(dst)
            .map_err(|e| panic!("connect error: {:?}", e))
            .and_then(move |conn| {

                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                // Wait until the client is ready...
                CompactTxStreamer::new(conn)
                    .ready()
                    .map_err(|e| eprintln!("streaming error {:?}", e))
            })
            .and_then(move |mut client| {
                let bs = BlockId{ height: start_height, hash: vec!()};
                let be = BlockId{ height: end_height,   hash: vec!()};

                let br = Request::new(BlockRange{ start: Some(bs), end: Some(be)});
                client
                    .get_block_range(br)
                    .map_err(|e| {
                        eprintln!("RouteChat request failed; err={:?}", e);
                    })
                    .and_then(move |response| {
                        let inbound = response.into_inner();
                        inbound.for_each(move |b| {
                            use prost::Message;
                            let mut encoded_buf = vec![];

                            b.encode(&mut encoded_buf).unwrap();
                            c(&encoded_buf);

                            Ok(())
                        })
                        .map_err(|e| eprintln!("gRPC inbound stream error: {:?}", e))                    
                    })
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap();
    }

    pub fn fetch_transparent_txids<F : 'static + std::marker::Send>(&self, address: String, 
        start_height: u64, end_height: u64,c: F)
            where F : Fn(&[u8], u64) {
        let uri: http::Uri =  self.get_server_uri();

        let dst = Destination::try_from_uri(uri.clone()).unwrap();
        let connector = util::Connector::new(HttpConnector::new(4));
        let settings = client::Builder::new().http2_only(true).clone();
        let mut make_client = client::Connect::with_builder(connector, settings);

        let say_hello = make_client
            .make_service(dst)
            .map_err(|e| panic!("connect error: {:?}", e))
            .and_then(move |conn| {

                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                // Wait until the client is ready...
                CompactTxStreamer::new(conn)
                    .ready()
                    .map_err(|e| eprintln!("streaming error {:?}", e))
            })
            .and_then(move |mut client| {
                let start = Some(BlockId{ height: start_height, hash: vec!()});
                let end   = Some(BlockId{ height: end_height,   hash: vec!()});

                let br = Request::new(TransparentAddressBlockFilter{ address, range: Some(BlockRange{start, end}) });

                client
                    .get_address_txids(br)
                    .map_err(|e| {
                        eprintln!("RouteChat request failed; err={:?}", e);
                    })
                    .and_then(move |response| {
                        let inbound = response.into_inner();
                        inbound.for_each(move |tx| {
                            //let tx = Transaction::read(&tx.into_inner().data[..]).unwrap();
                            c(&tx.data, tx.height);

                            Ok(())
                        })
                        .map_err(|e| eprintln!("gRPC inbound stream error: {:?}", e))                    
                    })
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap();
    }

    pub fn fetch_full_tx<F : 'static + std::marker::Send>(&self, txid: TxId, c: F)
            where F : Fn(&[u8]) {
        let uri: http::Uri = self.get_server_uri();

        let say_hello = LightClient::make_grpc_client(uri).unwrap()
            .and_then(move |mut client| {
                let txfilter = TxFilter { block: None, index: 0, hash: txid.0.to_vec() };
                client.get_transaction(Request::new(txfilter))
            })
            .and_then(move |response| {
                //let tx = Transaction::read(&response.into_inner().data[..]).unwrap();
                c(&response.into_inner().data);

                Ok(())
            })
            .map_err(|e| {
                println!("ERR = {:?}", e);
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap();
    }

    pub fn broadcast_raw_tx(&self, tx_bytes: Box<[u8]>) -> String {
        use std::cell::RefCell;

        let uri: http::Uri = self.get_server_uri();

        let infostr = Arc::new(RefCell::<String>::default());
        let infostrinner = infostr.clone();

        let say_hello = LightClient::make_grpc_client(uri).unwrap()
            .and_then(move |mut client| {
                client.send_transaction(Request::new(RawTransaction {data: tx_bytes.to_vec(), height: 0}))
            })
            .and_then(move |response| {
                let sendresponse = response.into_inner();
                if sendresponse.error_code == 0 {
                    infostrinner.replace(format!("Successfully broadcast Tx: {}", sendresponse.error_message));
                } else {
                    infostrinner.replace(format!("Error: {:?}", sendresponse));
                }
                Ok(())
            })
            .map_err(|e| {
                println!("ERR = {:?}", e);
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap();

        let ans = infostr.borrow().clone();
        ans
    }

    pub fn fetch_latest_block<F : 'static + std::marker::Send>(&self, mut c : F) 
        where F : FnMut(BlockId) {
        let uri: http::Uri = self.get_server_uri();

        let say_hello = LightClient::make_grpc_client(uri).unwrap()
            .and_then(|mut client| {
                client.get_latest_block(Request::new(ChainSpec {}))
            })
            .and_then(move |response| {
                c(response.into_inner());
                Ok(())
            })
            .map_err(|e| {
                println!("ERR = {:?}", e);
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap();
    }
    
    fn make_grpc_client(uri: http::Uri) -> Result<Box<dyn Future<Item=Client, Error=tower_grpc::Status> + Send>, Box<dyn std::error::Error>> {
        let dst = Destination::try_from_uri(uri.clone())?;
        let connector = util::Connector::new(HttpConnector::new(4));
        let settings = client::Builder::new().http2_only(true).clone();
        let mut make_client = client::Connect::with_builder(connector, settings);

        let say_hello = make_client
            .make_service(dst)
            .map_err(|e| panic!("connect error: {:?}", e))
            .and_then(move |conn| {

                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                // Wait until the client is ready...
                CompactTxStreamer::new(conn).ready()
            });
        Ok(Box::new(say_hello))
    }
}





/*
 TLS Example https://gist.github.com/kiratp/dfcbcf0aa713a277d5d53b06d9db9308
 
// [dependencies]
// futures = "0.1.27"
// http = "0.1.17"
// tokio = "0.1.21"
// tower-request-modifier = { git = "https://github.com/tower-rs/tower-http" }
// tower-grpc = { version = "0.1.0", features = ["tower-hyper"] }
// tower-service = "0.2"
// tower-util = "0.1"
// tokio-rustls = "0.10.0-alpha.3"
// webpki = "0.19.1"
// webpki-roots = "0.16.0"
// tower-h2 = { git = "https://github.com/tower-rs/tower-h2" }
// openssl = "*"
// openssl-probe = "*"

use std::thread;
use std::sync::{Arc};
use futures::{future, Future};
use tower_util::MakeService;

use tokio_rustls::client::TlsStream;
use tokio_rustls::{rustls::ClientConfig, TlsConnector};
use std::net::SocketAddr;

use tokio::executor::DefaultExecutor;
use tokio::net::tcp::TcpStream;
use tower_h2;

use std::net::ToSocketAddrs;



struct Dst(SocketAddr);


impl tower_service::Service<()> for Dst {
    type Response = TlsStream<TcpStream>;
    type Error = ::std::io::Error;
    type Future = Box<dyn Future<Item = TlsStream<TcpStream>, Error = ::std::io::Error> + Send>;

    fn poll_ready(&mut self) -> futures::Poll<(), Self::Error> {
        Ok(().into())
    }

    fn call(&mut self, _: ()) -> Self::Future {
        println!("{:?}", self.0);
        let mut config = ClientConfig::new();

        config.alpn_protocols.push(b"h2".to_vec());
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let config = Arc::new(config);
        let tls_connector = TlsConnector::from(config);

        let addr_string_local = "mydomain.com";

        let domain = webpki::DNSNameRef::try_from_ascii_str(addr_string_local).unwrap();
        let domain_local = domain.to_owned();

        let stream = TcpStream::connect(&self.0).and_then(move |sock| {
            sock.set_nodelay(true).unwrap();
            tls_connector.connect(domain_local.as_ref(), sock)
        })
        .map(move |tcp| tcp);

        Box::new(stream)
    }
}

// Same implementation but without TLS. Should make it straightforward to run without TLS
// when testing on local machine

// impl tower_service::Service<()> for Dst {
//     type Response = TcpStream;
//     type Error = ::std::io::Error;
//     type Future = Box<dyn Future<Item = TcpStream, Error = ::std::io::Error> + Send>;

//     fn poll_ready(&mut self) -> futures::Poll<(), Self::Error> {
//         Ok(().into())
//     }

//     fn call(&mut self, _: ()) -> Self::Future {
//         let mut config = ClientConfig::new();
//         config.alpn_protocols.push(b"h2".to_vec());
//         config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

//         let addr_string_local = "mydomain.com".to_string();
//         let addr = addr_string_local.as_str();
        
//         let stream = TcpStream::connect(&self.0)
//             .and_then(move |sock| {
//                 sock.set_nodelay(true).unwrap();
//                 Ok(sock)
//             });
//         Box::new(stream)
//     }
// }


fn connect() {
    let keepalive = future::loop_fn((), move |_| {
        let uri: http::Uri = "https://mydomain.com".parse().unwrap();
        println!("Connecting to network at: {:?}", uri);

        let addr = "https://mydomain.com:443"
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let h2_settings = Default::default();
        let mut make_client = tower_h2::client::Connect::new(Dst {0: addr}, h2_settings, DefaultExecutor::current());

        make_client
            .make_service(())
            .map_err(|e| {
                eprintln!("HTTP/2 connection failed; err={:?}", e);
            })
            .and_then(move |conn| {
                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                MyGrpcService::new(conn)
                    // Wait until the client is ready...
                    .ready()
                    .map_err(|e| eprintln!("client closed: {:?}", e))
            })
            .and_then(move |mut client| {
                // do stuff
            })
            .then(|e| {
                eprintln!("Reopening client connection to network: {:?}", e);
                let retry_sleep = std::time::Duration::from_secs(1);

                thread::sleep(retry_sleep);
                Ok(future::Loop::Continue(()))
            })
    });

    thread::spawn(move || tokio::run(keepalive));
}

pub fn main() {
    connect();
}

 */