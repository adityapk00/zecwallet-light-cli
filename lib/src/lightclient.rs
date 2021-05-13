use crate::lightwallet::{self, LightWallet, message::Message};

use zcash_proofs::prover::LocalTxProver;
use std::sync::{Arc, RwLock, Mutex, mpsc::channel};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::path::{Path, PathBuf};
use std::fs::File;
use std::collections::{HashSet, HashMap};
use std::cmp::{max, min};
use std::io;
use std::io::prelude::*;
use std::io::{BufReader, Error, ErrorKind};

use threadpool::ThreadPool;

use json::{object, array, JsonValue};

use zcash_primitives::{note_encryption::Memo, transaction::{TxId, Transaction}};
use zcash_primitives::{constants::testnet, constants::mainnet, constants::regtest};
use zcash_primitives::consensus::{BranchId, BlockHeight, MAIN_NETWORK};
use zcash_primitives::merkle_tree::{CommitmentTree};
use zcash_primitives::sapling::{Node};
use zcash_client_backend::encoding::{decode_payment_address, encode_payment_address};

use log::{info, warn, error, LevelFilter};
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::config::{Appender, Config, Root};
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::append::rolling_file::policy::compound::{
    CompoundPolicy,
    trigger::size::SizeTrigger,
    roll::fixed_window::FixedWindowRoller,
};

use crate::grpcconnector::{self, *};
use crate::lightwallet::{fee, NodePosition};
use crate::ANCHOR_OFFSET;

mod checkpoints;

pub const DEFAULT_SERVER: &str = "https://lwdv3.zecwallet.co";
pub const WALLET_NAME: &str    = "zecwallet-light-wallet.dat";
pub const LOGFILE_NAME: &str   = "zecwallet-light-wallet.debug.log";

#[derive(Clone, Debug)]
pub struct WalletStatus {
    pub is_syncing: bool,
    pub total_blocks: u64,
    pub synced_blocks: u64,
}

impl WalletStatus {
    pub fn new() -> Self {
        WalletStatus {
            is_syncing: false,
            total_blocks: 0,
            synced_blocks: 0
        }
    }
}

#[derive(Clone, Debug)]
pub struct LightClientConfig {
    pub server                      : http::Uri,
    pub chain_name                  : String,
    pub sapling_activation_height   : u64,
    pub anchor_offset               : u32,
    pub data_dir                    : Option<String>
}

impl LightClientConfig {

    // Create an unconnected (to any server) config to test for local wallet etc...
    pub fn create_unconnected(chain_name: String, dir: Option<String>) -> LightClientConfig {
        LightClientConfig {
            server                      : http::Uri::default(),
            chain_name                  : chain_name,
            sapling_activation_height   : 1,
            anchor_offset               : ANCHOR_OFFSET,
            data_dir                    : dir,
        }
    }

    pub fn create(server: http::Uri) -> io::Result<(LightClientConfig, u64)> {
        use std::net::ToSocketAddrs;
        // Test for a connection first
        format!("{}:{}", server.host().unwrap(), server.port().unwrap())
            .to_socket_addrs()?
            .next()
            .ok_or(std::io::Error::new(ErrorKind::ConnectionRefused, "Couldn't resolve server!"))?;

        // Do a getinfo first, before opening the wallet
        let info = grpcconnector::get_info(&server)
            .map_err(|e| std::io::Error::new(ErrorKind::ConnectionRefused, e))?;

        // Create a Light Client Config
        let config = LightClientConfig {
            server,
            chain_name                  : info.chain_name,
            sapling_activation_height   : info.sapling_activation_height,
            anchor_offset               : ANCHOR_OFFSET,
            data_dir                    : None,
        };

        Ok((config, info.block_height))
    }


    /// Build the Logging config
    pub fn get_log_config(&self) -> io::Result<Config> {
        let window_size = 3; // log0, log1, log2
        let fixed_window_roller =
            FixedWindowRoller::builder().build("zecwallet-light-wallet-log{}",window_size).unwrap();
        let size_limit = 5 * 1024 * 1024; // 5MB as max log file size to roll
        let size_trigger = SizeTrigger::new(size_limit);
        let compound_policy = CompoundPolicy::new(Box::new(size_trigger),Box::new(fixed_window_roller));

        Config::builder()
            .appender(
                Appender::builder()
                    .filter(Box::new(ThresholdFilter::new(LevelFilter::Info)))
                    .build(
                        "logfile",
                        Box::new(
                            RollingFileAppender::builder()
                                .encoder(Box::new(PatternEncoder::new("{d} {l}::{m}{n}")))
                                .build(self.get_log_path(), Box::new(compound_policy))?,
                        ),
                    ),
            )
            .build(
                Root::builder()
                    .appender("logfile")
                    .build(LevelFilter::Debug),
            )
            .map_err(|e|Error::new(ErrorKind::Other, format!("{}", e)))
    }

    pub fn get_zcash_data_path(&self) -> Box<Path> {
        let mut zcash_data_location; 
        if self.data_dir.is_some() {
            zcash_data_location = PathBuf::from(&self.data_dir.as_ref().unwrap());
        } else {
            if cfg!(target_os="macos") || cfg!(target_os="windows") {
                zcash_data_location = dirs::data_dir().expect("Couldn't determine app data directory!");
                zcash_data_location.push("Zcash");
            } else {
                if dirs::home_dir().is_none() {
                    info!("Couldn't determine home dir!");
                }
                zcash_data_location = dirs::home_dir().expect("Couldn't determine home directory!");
                zcash_data_location.push(".zcash");
            };

            match &self.chain_name[..] {
                "main" => {},
                "test" => zcash_data_location.push("testnet3"),
                "regtest" => zcash_data_location.push("regtest"),
                c         => panic!("Unknown chain {}", c),
            };
        }

        // Create directory if it doesn't exist on non-mobile platforms
        #[cfg(all(not(target_os="ios"), not(target_os="android")))]
        {
            match std::fs::create_dir_all(zcash_data_location.clone()) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("Couldn't create zcash directory!\n{}", e);
                    panic!("Couldn't create zcash directory!");
                }
            }
        }

        zcash_data_location.into_boxed_path()
    }

    pub fn get_zcash_params_path(&self) -> io::Result<Box<Path>> {
        if dirs::home_dir().is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Couldn't determine Home Dir"));
        }

        let mut zcash_params = self.get_zcash_data_path().into_path_buf();
        zcash_params.push("..");
        if cfg!(target_os="macos") || cfg!(target_os="windows") {
            zcash_params.push("ZcashParams");
        } else {
            zcash_params.push(".zcash-params");
        }

        match std::fs::create_dir_all(zcash_params.clone()) {
            Ok(_) => Ok(zcash_params.into_boxed_path()),
            Err(e) => {
                eprintln!("Couldn't create zcash params directory\n{}", e);
                Err(e)
            }
        }
    }

    pub fn get_wallet_path(&self) -> Box<Path> {
        let mut wallet_location = self.get_zcash_data_path().into_path_buf();
        wallet_location.push(WALLET_NAME);
        
        wallet_location.into_boxed_path()
    }

    pub fn wallet_exists(&self) -> bool {
        return self.get_wallet_path().exists()
    }

    pub fn backup_existing_wallet(&self) -> Result<String, String> {
        if !self.wallet_exists() {
            return Err(format!("Couldn't find existing wallet to backup. Looked in {:?}", self.get_wallet_path().to_str()));
        }
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut backup_file_path = self.get_zcash_data_path().into_path_buf();
        backup_file_path.push(&format!("zecwallet-light-wallet.backup.{}.dat", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()));

        let backup_file_str = backup_file_path.to_string_lossy().to_string();
        std::fs::copy(self.get_wallet_path(), backup_file_path).map_err(|e| format!("{}", e))?;

        Ok(backup_file_str)
    }

    pub fn get_log_path(&self) -> Box<Path> {
        let mut log_path = self.get_zcash_data_path().into_path_buf();
        log_path.push(LOGFILE_NAME);

        log_path.into_boxed_path()
    }

    pub fn get_initial_state(&self, uri: &http::Uri, height: u64) -> Option<(u64, String, String)> {
        if height <= self.sapling_activation_height {
            return checkpoints::get_closest_checkpoint(&self.chain_name, height).map(|(height, hash, tree)| 
                (height, hash.to_string(), tree.to_string())
            );
        }

        // We'll get the initial state from the server. Get it at height - 100 blocks, so there is no risk 
        // of a reorg
        let fetch_height = std::cmp::max(height - 100, self.sapling_activation_height);
        info!("Getting sapling tree from LightwalletD at height {}", fetch_height);
        match grpcconnector::get_sapling_tree(uri, fetch_height as i32) {
            Ok(tree_state) => {
                let hash = tree_state.hash.clone();
                let tree = tree_state.tree.clone();
                Some((tree_state.height, hash, tree))
            },
            Err(e) => {
                error!("Error getting sapling tree:{}\nWill return checkpoint instead.", e);
                match checkpoints::get_closest_checkpoint(&self.chain_name, height) {
                    Some((height, hash, tree)) => Some((height, hash.to_string(), tree.to_string())),
                    None => None
                }
            }
        }
    }

    pub fn get_server_or_default(server: Option<String>) -> http::Uri {
        match server {
            Some(s) => {
                let mut s = if s.starts_with("http") {s} else { "http://".to_string() + &s};
                let uri: http::Uri = s.parse().unwrap();
                if uri.port().is_none() {
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

    pub fn hrp_sapling_viewing_key(&self) -> &str {
        match &self.chain_name[..] {
            "main"    => mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            "test"    => testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            "regtest" => regtest::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
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
    pub wallet          : Arc<RwLock<LightWallet>>,

    pub config          : LightClientConfig,

    // zcash-params
    pub sapling_output  : Vec<u8>,
    pub sapling_spend   : Vec<u8>,

    sync_lock           : Mutex<()>,
    sync_status         : Arc<RwLock<WalletStatus>>, // The current syncing status of the Wallet.
}

impl LightClient {
    
    pub fn set_wallet_initial_state(&self, height: u64) {
        use std::convert::TryInto;

        let state = self.config.get_initial_state(&self.get_server_uri(), height);

        match state {
            Some((height, hash, tree)) => {
                info!("Setting initial state to height {}, tree {}", height, tree);
                self.wallet.write().unwrap().set_initial_block(
                    height.try_into().unwrap(), 
                    &hash.as_str(), 
                    &tree.as_str());
                },
            _ => {},
        };
    }

    fn write_file_if_not_exists(dir: &Box<Path>, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut file_path = dir.to_path_buf();
        file_path.push(name);
        if !file_path.exists() {
            let mut file = File::create(&file_path)?;
            file.write_all(bytes)?;
        }

        Ok(())
    }

    #[cfg(feature = "embed_params")]
    fn read_sapling_params(&mut self) {
        // Read Sapling Params
        use crate::SaplingParams;
        self.sapling_output.extend_from_slice(SaplingParams::get("sapling-output.params").unwrap().as_ref());
        self.sapling_spend.extend_from_slice(SaplingParams::get("sapling-spend.params").unwrap().as_ref());
    }

    pub fn set_sapling_params(&mut self, sapling_output: &[u8], sapling_spend: &[u8]) -> Result<(), String> {
        use sha2::{Sha256, Digest};

        // The hashes of the params need to match
        const SAPLING_OUTPUT_HASH: &str = "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";
        const SAPLING_SPEND_HASH: &str = "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";

        if SAPLING_OUTPUT_HASH.to_string() != hex::encode(Sha256::digest(&sapling_output)) {
            return Err(format!("sapling-output hash didn't match. expected {}, found {}", SAPLING_OUTPUT_HASH, hex::encode(Sha256::digest(&sapling_output)) ))
        }
        if SAPLING_SPEND_HASH.to_string() != hex::encode(Sha256::digest(&sapling_spend)) {
            return Err(format!("sapling-spend hash didn't match. expected {}, found {}", SAPLING_SPEND_HASH, hex::encode(Sha256::digest(&sapling_spend)) ))
        }

        // Will not overwrite previous params
        if self.sapling_output.is_empty() {
            self.sapling_output.extend_from_slice(sapling_output);
        }

        if self.sapling_spend.is_empty() {
            self.sapling_spend.extend_from_slice(sapling_spend);
        }

        // Ensure that the sapling params are stored on disk properly as well. Only on desktop
        if cfg!(all(not(target_os="ios"), not(target_os="android"))) {
            match self.config.get_zcash_params_path() {
                Ok(zcash_params_dir) => {
                    // Create the sapling output and spend params files
                    match LightClient::write_file_if_not_exists(&zcash_params_dir, "sapling-output.params", &self.sapling_output) {
                        Ok(_) => {},
                        Err(e) => eprintln!("Warning: Couldn't write the output params!\n{}", e)
                    };
                    
                    match LightClient::write_file_if_not_exists(&zcash_params_dir, "sapling-spend.params", &self.sapling_spend) {
                        Ok(_) => {},
                        Err(e) => eprintln!("Warning: Couldn't write the output params!\n{}", e)
                    }
                },
                Err(e) => {
                    eprintln!("{}", e);
                }
            };
        }
        
        Ok(())
    }

    /// Method to create a test-only version of the LightClient
    #[allow(dead_code)]
    pub fn unconnected(seed_phrase: String, dir: Option<String>) -> io::Result<Self> {
        let config = LightClientConfig::create_unconnected("test".to_string(), dir);
        let mut l = LightClient {
                wallet          : Arc::new(RwLock::new(LightWallet::new(Some(seed_phrase), &config, 0)?)),
                config          : config.clone(),
                sapling_output  : vec![], 
                sapling_spend   : vec![],
                sync_lock       : Mutex::new(()),
                sync_status     : Arc::new(RwLock::new(WalletStatus::new())),
            };

        l.set_wallet_initial_state(0);
        
        #[cfg(feature = "embed_params")]
        l.read_sapling_params();

        info!("Created new wallet!");
        info!("Created LightClient to {}", &config.server);

        Ok(l)
    }

    /// Create a brand new wallet with a new seed phrase. Will fail if a wallet file 
    /// already exists on disk
    pub fn new(config: &LightClientConfig, latest_block: u64) -> io::Result<Self> {
        #[cfg(all(not(target_os="ios"), not(target_os="android")))]
        {        
            if config.wallet_exists() {
                return Err(Error::new(ErrorKind::AlreadyExists,
                        "Cannot create a new wallet from seed, because a wallet already exists"));
            }
        }

        let mut l = LightClient {
                wallet          : Arc::new(RwLock::new(LightWallet::new(None, config, latest_block)?)),
                config          : config.clone(),
                sapling_output  : vec![], 
                sapling_spend   : vec![],
                sync_lock       : Mutex::new(()),
                sync_status     : Arc::new(RwLock::new(WalletStatus::new())),
            };

        l.set_wallet_initial_state(latest_block);
        
        #[cfg(feature = "embed_params")]
        l.read_sapling_params();

        info!("Created new wallet with a new seed!");
        info!("Created LightClient to {}", &config.server);

        // Save
        l.do_save().map_err(|s| io::Error::new(ErrorKind::PermissionDenied, s))?;

        Ok(l)
    }

    pub fn new_from_phrase(seed_phrase: String, config: &LightClientConfig, birthday: u64, overwrite: bool) -> io::Result<Self> {
        #[cfg(all(not(target_os="ios"), not(target_os="android")))]
        {
            if !overwrite && config.wallet_exists() {
                return Err(Error::new(ErrorKind::AlreadyExists,
                        "Cannot create a new wallet from seed, because a wallet already exists"));
            }
        }

        let mut l = LightClient {
                wallet          : Arc::new(RwLock::new(LightWallet::new(Some(seed_phrase), config, birthday)?)),
                config          : config.clone(),
                sapling_output  : vec![], 
                sapling_spend   : vec![],
                sync_lock       : Mutex::new(()),
                sync_status     : Arc::new(RwLock::new(WalletStatus::new())),
            };

        println!("Setting birthday to {}", birthday);
        l.set_wallet_initial_state(birthday);
        
        #[cfg(feature = "embed_params")]
        l.read_sapling_params();

        info!("Created new wallet!");
        info!("Created LightClient to {}", &config.server);

        // Save
        l.do_save().map_err(|s| io::Error::new(ErrorKind::PermissionDenied, s))?;

        Ok(l)
    }

    pub fn read_from_buffer<R: Read>(config: &LightClientConfig, mut reader: R) -> io::Result<Self>{
        let wallet = LightWallet::read(&mut reader, config)?;
        let mut lc = LightClient {
            wallet          : Arc::new(RwLock::new(wallet)),
            config          : config.clone(),
            sapling_output  : vec![], 
            sapling_spend   : vec![],
            sync_lock       : Mutex::new(()),
            sync_status     : Arc::new(RwLock::new(WalletStatus::new())),
        };

        #[cfg(feature = "embed_params")]
        lc.read_sapling_params();

        info!("Read wallet with birthday {}", lc.wallet.read().unwrap().get_first_tx_block());
        info!("Created LightClient to {}", &config.server);

        Ok(lc)
    }

    pub fn read_from_disk(config: &LightClientConfig) -> io::Result<Self> {
        if !config.wallet_exists() {
            return Err(Error::new(ErrorKind::AlreadyExists,
                    format!("Cannot read wallet. No file at {}", config.get_wallet_path().display())));
        }

        let mut file_buffer = BufReader::new(File::open(config.get_wallet_path())?);
            
        let wallet = LightWallet::read(&mut file_buffer, config)?;
        let mut lc = LightClient {
            wallet          : Arc::new(RwLock::new(wallet)),
            config          : config.clone(),
            sapling_output  : vec![], 
            sapling_spend   : vec![],
            sync_lock       : Mutex::new(()),
            sync_status     : Arc::new(RwLock::new(WalletStatus::new())),
        };

        #[cfg(feature = "embed_params")]
        lc.read_sapling_params();

        info!("Read wallet with birthday {}", lc.wallet.read().unwrap().get_first_tx_block());
        info!("Created LightClient to {}", &config.server);

        Ok(lc)
    }

    pub fn init_logging(&self) -> io::Result<()> {
        // Configure logging first.
        let log_config = self.config.get_log_config()?;
        log4rs::init_config(log_config).map_err(|e| {
            std::io::Error::new(ErrorKind::Other, e)
        })?;

        Ok(())
    }

    pub fn attempt_recover_seed(config: &LightClientConfig, password: Option<String>) -> Result<String, String> {
        use std::io::prelude::*;
        use byteorder::{LittleEndian, ReadBytesExt};
        use libflate::gzip::Decoder;
        use bip39::{Mnemonic, Language};
        use zcash_primitives::serialize::Vector;

        let mut inp = BufReader::new(File::open(config.get_wallet_path()).unwrap());
        let version = inp.read_u64::<LittleEndian>().unwrap();
        println!("Reading wallet version {}", version);

        // At version 5, we're writing the rest of the file as a compressed stream (gzip)
        let mut reader: Box<dyn Read> = if version != 5 {
            Box::new(inp)
        } else {
            Box::new(Decoder::new(inp).unwrap())
        };

        let encrypted = if version >= 4 {
            reader.read_u8().unwrap() > 0
        } else {
            false
        };

        if encrypted && password.is_none() {
            return Err("The wallet is encrypted and a password was not specified. Please specify the password with '--password'!".to_string());
        }

        let mut enc_seed = [0u8; 48];
        if version >= 4 {
            reader.read_exact(&mut enc_seed).unwrap();
        }

        let nonce = if version >= 4 {
            Vector::read(&mut reader, |r| r.read_u8()).unwrap()
        } else {
            vec![]
        };

        let phrase = if encrypted {
            use sodiumoxide::crypto::secretbox;
            use crate::lightwallet::double_sha256;

            // Get the doublesha256 of the password, which is the right length
            let key = secretbox::Key::from_slice(&double_sha256(password.unwrap().as_bytes())).unwrap();
            let nonce = secretbox::Nonce::from_slice(&nonce).unwrap();

            let seed = match secretbox::open(&enc_seed, &nonce, &key) {
                Ok(s) => s,
                Err(_) => return Err("Decryption failed. Is your password correct?".to_string())
            };
            
            Mnemonic::from_entropy(&seed, Language::English)
        } else {
            // Seed
            let mut seed_bytes = [0u8; 32];
            reader.read_exact(&mut seed_bytes).unwrap();

            Mnemonic::from_entropy(&seed_bytes, Language::English) 
        }.map_err(|e| format!("Failed to read seed. {:?}", e));
        
        phrase.map(|m| m.phrase().to_string())
    }


    pub fn last_scanned_height(&self) -> u64 {
        self.wallet.read().unwrap().last_scanned_height() as u64
    }

    // Export private keys
    pub fn do_export(&self, addr: Option<String>) -> Result<JsonValue, &str> {
        if !self.wallet.read().unwrap().is_unlocked_for_spending() {
            error!("Wallet is locked");
            return Err("Wallet is locked");
        }

        // Clone address so it can be moved into the closure
        let address = addr.clone();
        let wallet = self.wallet.read().unwrap();
        // Go over all z addresses
        let z_keys = wallet.get_z_private_keys().iter()
            .filter( move |(addr, _, _)| address.is_none() || address.as_ref() == Some(addr))
            .map( |(addr, pk, vk)|
                object!{
                    "address"     => addr.clone(),
                    "private_key" => pk.clone(),
                    "viewing_key" => vk.clone(),
                }
            ).collect::<Vec<JsonValue>>();

        // Clone address so it can be moved into the closure
        let address = addr.clone();

        // Go over all t addresses
        let t_keys = wallet.get_t_secret_keys().iter()
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

        Ok(all_keys.into())
    }

    pub fn do_address(&self) -> JsonValue {
        let wallet = self.wallet.read().unwrap();

        // Collect z addresses
        let z_addresses = wallet.get_all_zaddresses();

        // Collect t addresses
        let t_addresses = wallet.taddresses.read().unwrap().iter().map( |a| a.clone() )
                            .collect::<Vec<String>>();

        object!{
            "z_addresses" => z_addresses,
            "t_addresses" => t_addresses,
        }
    }

    pub fn do_balance(&self) -> JsonValue {
        let wallet = self.wallet.read().unwrap();

        // Collect z addresses
        let z_addresses = wallet.get_all_zaddresses().iter().map(|zaddress| {
            object!{
                "address" => zaddress.clone(),
                "zbalance" => wallet.zbalance(Some(zaddress.clone())),
                "verified_zbalance"  => wallet.verified_zbalance(Some(zaddress.clone())),
                "spendable_zbalance" => wallet.spendable_zbalance(Some(zaddress.clone())),
                "unverified_zbalance"   => wallet.unverified_zbalance(Some(zaddress.clone()))
            }
        }).collect::<Vec<JsonValue>>();

        // Collect t addresses
        let t_addresses = wallet.taddresses.read().unwrap().iter().map( |address| {
            // Get the balance for this address
            let balance = wallet.tbalance(Some(address.clone()));
            
            object!{
                "address" => address.clone(),
                "balance" => balance,
            }
        }).collect::<Vec<JsonValue>>();

        object!{
            "zbalance"           => wallet.zbalance(None),
            "verified_zbalance"  => wallet.verified_zbalance(None),
            "spendable_zbalance" => wallet.spendable_zbalance(None),
            "unverified_zbalance"   => wallet.unverified_zbalance(None),
            "tbalance"           => wallet.tbalance(None),
            "z_addresses"        => z_addresses,
            "t_addresses"        => t_addresses,
        }
    }

    pub fn do_save(&self) -> Result<(), String> {        
        // On mobile platforms, disable the save, because the saves will be handled by the native layer, and not in rust
        if cfg!(all(not(target_os="ios"), not(target_os="android"))) { 
            // If the wallet is encrypted but unlocked, lock it again.
            {
                let mut wallet = self.wallet.write().unwrap();
                if wallet.is_encrypted() && wallet.is_unlocked_for_spending() {
                    match wallet.lock() {
                        Ok(_) => {},
                        Err(e) => {
                            let err = format!("ERR: {}", e);
                            error!("{}", err);
                            return Err(e.to_string());
                        }
                    }
                }
            }        

            {
                // Prevent any overlapping syncs during save, and don't save in the middle of a sync
                let _lock = self.sync_lock.lock().unwrap();

                let wallet = self.wallet.write().unwrap();

                let mut wallet_bytes = vec![];
                match wallet.write(&mut wallet_bytes) {
                    Ok(_) => {
                        let mut file = File::create(self.config.get_wallet_path()).unwrap();
                        file.write_all(&wallet_bytes).map_err(|e| format!("{}", e))?;
                        Ok(())
                    }, 
                    Err(e) => {
                        let err = format!("ERR: {}", e);
                        error!("{}", err);
                        Err(e.to_string())
                    }
                }
            }
        } else {
            // On ios and android just return OK
            Ok(())
        }
    }


    pub fn do_save_to_buffer(&self) -> Result<Vec<u8>, String> {
        // If the wallet is encrypted but unlocked, lock it again.
        {
           let mut wallet = self.wallet.write().unwrap();
           if wallet.is_encrypted() && wallet.is_unlocked_for_spending() {
               match wallet.lock() {
                   Ok(_) => {},
                   Err(e) => {
                       let err = format!("ERR: {}", e);
                       error!("{}", err);
                       return Err(e.to_string());
                   }
               }
           }
       }

       let mut buffer: Vec<u8> = vec![];
       match self.wallet.write().unwrap().write(&mut buffer) {
           Ok(_) => Ok(buffer),
           Err(e) => {
               let err = format!("ERR: {}", e);
               error!("{}", err);
               Err(e.to_string())
           }
       }
   }

    pub fn get_server_uri(&self) -> http::Uri {
        self.config.server.clone()
    }

    pub fn do_info(&self) -> String {
        match get_info(&self.get_server_uri()) {
            Ok(i) => {
                let o = object!{
                    "version" => i.version,
                    "git_commit" => i.git_commit,
                    "server_uri" => self.get_server_uri().to_string(),
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

    pub fn do_send_progress(&self) -> Result<JsonValue, String> {
        let progress = self.wallet.read().unwrap().get_send_progress();

        Ok(object! {
            "id" => progress.id,
            "sending" => progress.is_send_in_progress,
            "progress" => progress.progress,
            "total" => progress.total,
            "txid" => progress.last_txid,
            "error" => progress.last_error,
        })
    }

    pub fn do_seed_phrase(&self) -> Result<JsonValue, &str> {
        if !self.wallet.read().unwrap().is_unlocked_for_spending() {
            error!("Wallet is locked");
            return Err("Wallet is locked");
        }

        let wallet = self.wallet.read().unwrap();
        Ok(object!{
            "seed"     => wallet.get_seed_phrase(),
            "birthday" => wallet.get_birthday()
        })
    }

    // Return a list of all notes, spent and unspent
    pub fn do_list_notes(&self, all_notes: bool) -> JsonValue {
        let mut unspent_notes: Vec<JsonValue> = vec![];
        let mut spent_notes  : Vec<JsonValue> = vec![];
        let mut pending_notes: Vec<JsonValue> = vec![];
        
        let anchor_height: i32 = self.wallet.read().unwrap().get_anchor_height() as i32;

        {
            let wallet = self.wallet.read().unwrap();

            // First, collect all extfvk's that are spendable (i.e., we have the private key)
            let spendable_address: HashSet<String> = wallet.get_all_zaddresses().iter()
                .filter(|address| wallet.have_spending_key_for_zaddress(address))
                .map(|address| address.clone())
                .collect();

            // Collect Sapling notes
            wallet.txs.read().unwrap().iter()
                .flat_map( |(txid, wtx)| {
                    let spendable_address = spendable_address.clone();
                    wtx.notes.iter().filter_map(move |nd| 
                        if !all_notes && nd.spent.is_some() {
                            None
                        } else {
                            let address = LightWallet::note_address(self.config.hrp_sapling_address(), nd);
                            let spendable = address.is_some() && 
                                                    spendable_address.contains(&address.clone().unwrap()) && 
                                                    wtx.block <= anchor_height && nd.spent.is_none() && nd.unconfirmed_spent.is_none();

                            Some(object!{
                                "created_in_block"   => wtx.block,
                                "datetime"           => wtx.datetime,
                                "created_in_txid"    => format!("{}", txid),
                                "value"              => nd.note.value,
                                "is_change"          => nd.is_change,
                                "address"            => address,
                                "spendable"          => spendable,
                                "spent"              => nd.spent.map(|spent_txid| format!("{}", spent_txid)),
                                "spent_at_height"    => nd.spent_at_height.map(|h| format!("{}", h)),
                                "unconfirmed_spent"  => nd.unconfirmed_spent.map(|(spent_txid, _)| format!("{}", spent_txid)),
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
        }
        
        let mut unspent_utxos: Vec<JsonValue> = vec![];
        let mut spent_utxos  : Vec<JsonValue> = vec![];
        let mut pending_utxos: Vec<JsonValue> = vec![];
        
        {
            let wallet = self.wallet.read().unwrap();
            wallet.txs.read().unwrap().iter()
                .flat_map( |(txid, wtx)| {
                    wtx.utxos.iter().filter_map(move |utxo| 
                        if !all_notes && utxo.spent.is_some() {
                            None
                        } else {
                            Some(object!{
                                "created_in_block"   => wtx.block,
                                "datetime"           => wtx.datetime,
                                "created_in_txid"    => format!("{}", txid),
                                "value"              => utxo.value,
                                "scriptkey"          => hex::encode(utxo.script.clone()),
                                "is_change"          => false, // TODO: Identify notes as change if we send change to taddrs
                                "address"            => utxo.address.clone(),
                                "spent_at_height"    => utxo.spent_at_height,
                                "spent"              => utxo.spent.map(|spent_txid| format!("{}", spent_txid)),
                                "unconfirmed_spent"  => utxo.unconfirmed_spent.map(|(spent_txid, _)| format!("{}", spent_txid)),
                            })
                        }
                    )
                })
                .for_each( |utxo| {
                    if utxo["spent"].is_null() && utxo["unconfirmed_spent"].is_null() {
                        unspent_utxos.push(utxo);
                    } else if !utxo["spent"].is_null() {
                        spent_utxos.push(utxo);
                    } else {
                        pending_utxos.push(utxo);
                    }
                });
        }

        let mut res = object!{
            "unspent_notes" => unspent_notes,
            "pending_notes" => pending_notes,
            "utxos"         => unspent_utxos,
            "pending_utxos" => pending_utxos,
        };

        if all_notes {
            res["spent_notes"] = JsonValue::Array(spent_notes);
            res["spent_utxos"] = JsonValue::Array(spent_utxos);
        }

        res
    }

    pub fn do_encrypt_message(&self, to_address_str: String, memo: Memo) -> JsonValue {
        let to = match decode_payment_address(self.config.hrp_sapling_address(), &to_address_str) {
            Ok(Some(to)) => to,
            _ => {
                return object! {"error" => format!("Couldn't parse {} as a z-address", to_address_str) };
            }
        };

        match Message::new(to, memo).encrypt() {
            Ok(v) => {
                object! {"encrypted_base64" => base64::encode(v) }
            },
            Err(e) => {
                object! {"error" => format!("Couldn't encrypt. Error was {}", e)}
            }
        }
    }

    pub fn do_decrypt_message(&self, enc_base64: String) -> JsonValue {
        let wallet = self.wallet.read().unwrap();

        let data = match base64::decode(enc_base64) {
            Ok(v) => v,
            Err(e) => {
                return  object! {"error" => format!("Couldn't decode base64. Error was {}", e)}
            }
        };

        match wallet.decrypt_message(data) {
            Some(m) => object! { 
                "to" => encode_payment_address(self.config.hrp_sapling_address(), &m.to),
                "memo" => LightWallet::memo_str(Some(m.memo.clone())),
                "memohex" => hex::encode(m.memo.as_bytes())
            },
            None => object! { "error" => "Couldn't decrypt with any of the wallet's keys"}
        }
    }

    pub fn do_encryption_status(&self) -> JsonValue {
        let wallet = self.wallet.read().unwrap();
        object!{
            "encrypted" => wallet.is_encrypted(),
            "locked"    => !wallet.is_unlocked_for_spending()
        }
    }

    pub fn do_list_transactions(&self, include_memo_hex: bool) -> JsonValue {
        let wallet = self.wallet.read().unwrap();

        // Create a list of TransactionItems from wallet txns
        let mut tx_list = wallet.txs.read().unwrap().iter()
            .flat_map(| (_k, v) | {
                let mut txns: Vec<JsonValue> = vec![];

                if v.total_shielded_value_spent + v.total_transparent_value_spent > 0 {
                    // If money was spent, create a transaction. For this, we'll subtract
                    // all the change notes. TODO: Add transparent change here to subtract it also
                    let total_change: u64 = v.notes.iter()
                        .filter( |nd| nd.is_change )
                        .map( |nd| nd.note.value )
                        .sum();

                    // TODO: What happens if change is > than sent ?

                    // Collect outgoing metadata
                    let outgoing_json = v.outgoing_metadata.iter()
                        .map(|om| {
                            let mut o = object!{
                                "address" => om.address.clone(),
                                "value"   => om.value,
                                "memo"    => LightWallet::memo_str(Some(om.memo.clone()))
                            };

                            if include_memo_hex {
                                o.insert("memohex", hex::encode(om.memo.as_bytes())).unwrap();
                            }
                            
                            return o;
                        })
                        .collect::<Vec<JsonValue>>();                    

                    txns.push(object! {
                        "block_height" => v.block,
                        "datetime"     => v.datetime,
                        "txid"         => format!("{}", v.txid),
                        "zec_price"    => v.zec_price,
                        "amount"       => total_change as i64 
                                            - v.total_shielded_value_spent as i64 
                                            - v.total_transparent_value_spent as i64,
                        "outgoing_metadata" => outgoing_json,
                    });
                } 

                // For each sapling note that is not a change, add a Tx.
                txns.extend(v.notes.iter()
                    .filter( |nd| !nd.is_change )
                    .enumerate()
                    .map ( |(i, nd)| {
                        let mut o = object! {
                            "block_height" => v.block,
                            "datetime"     => v.datetime,
                            "position"     => i,
                            "txid"         => format!("{}", v.txid),
                            "zec_price"    => v.zec_price,
                            "amount"       => nd.note.value as i64,
                            "address"      => LightWallet::note_address(self.config.hrp_sapling_address(), nd),
                            "memo"         => LightWallet::memo_str(nd.memo.clone())
                        };

                        if include_memo_hex {
                            o.insert("memohex", match &nd.memo {
                                Some(m) => hex::encode(m.as_bytes()),
                                _ => "".to_string(),
                            }).unwrap();
                        }

                        return o;
                    })
                );

                // Get the total transparent received
                let total_transparent_received = v.utxos.iter().map(|u| u.value).sum::<u64>();
                if total_transparent_received > v.total_transparent_value_spent {
                    // Create an input transaction for the transparent value as well.
                    txns.push(object!{
                        "block_height" => v.block,
                        "datetime"     => v.datetime,
                        "txid"         => format!("{}", v.txid),
                        "zec_price"    => v.zec_price,
                        "amount"       => total_transparent_received as i64 - v.total_transparent_value_spent as i64,
                        "address"      => v.utxos.iter().map(|u| u.address.clone()).collect::<Vec<String>>().join(","),
                        "memo"         => None::<String>
                    })
                }

                txns
            })
            .collect::<Vec<JsonValue>>();

        // Add in all mempool txns
        tx_list.extend(wallet.mempool_txs.read().unwrap().iter().map( |(_, wtx)| {
            let amount: u64 = wtx.outgoing_metadata.iter().map(|om| om.value).sum::<u64>();
            let fee = fee::get_default_fee(wallet.last_scanned_height());

            // Collect outgoing metadata
            let outgoing_json = wtx.outgoing_metadata.iter()
                .map(|om| {
                    let mut o = object!{
                        "address" => om.address.clone(),
                        "value"   => om.value,
                        "memo"    => LightWallet::memo_str(Some(om.memo.clone())),
                    };

                    if include_memo_hex {
                        o.insert("memohex", hex::encode(om.memo.as_bytes())).unwrap();
                    }

                    return o;
                }).collect::<Vec<JsonValue>>();

            object! {
                "block_height" => wtx.block,
                "datetime"     => wtx.datetime,
                "txid"         => format!("{}", wtx.txid),
                "zec_price"    => wtx.zec_price,
                "amount"       => -1 * (fee + amount) as i64,
                "unconfirmed"  => true,
                "outgoing_metadata" => outgoing_json,
            }
        }));

        tx_list.sort_by( |a, b| if a["block_height"] == b["block_height"] {
                                    a["txid"].as_str().cmp(&b["txid"].as_str())
                                } else {
                                    a["block_height"].as_i32().cmp(&b["block_height"].as_i32())
                                }
        );

        JsonValue::Array(tx_list)
    }

    /// Create a new address, deriving it from the seed.
    pub fn do_new_address(&self, addr_type: &str) -> Result<JsonValue, String> {
        if !self.wallet.read().unwrap().is_unlocked_for_spending() {
            error!("Wallet is locked");
            return Err("Wallet is locked".to_string());
        }

        let new_address = {
            let wallet = self.wallet.write().unwrap();

            let addr = match addr_type {
                "z" => wallet.add_zaddr(),
                "t" => wallet.add_taddr(),
                _   => {
                    let e = format!("Unrecognized address type: {}", addr_type);
                    error!("{}", e);
                    return Err(e);
                }
            };

            if addr.starts_with("Error") {
                let e = format!("Error creating new address: {}", addr);
                    error!("{}", e);
                    return Err(e);
            }

            addr
        };

        self.do_save()?;

        Ok(array![new_address])
    }

    /// Convinence function to determine what type of key this is and import it
    pub fn do_import_key(&self, key: String, birthday: u64) -> Result<JsonValue, String> {
        if key.starts_with(self.config.hrp_sapling_private_key()) {
            self.do_import_sk(key, birthday)
        } else if key.starts_with(self.config.hrp_sapling_viewing_key()) {
            self.do_import_vk(key, birthday)
        } else {
            Err(format!("'{}' was not recognized as either a spending key or a viewing key because it didn't start with either '{}' or '{}'", 
                key, self.config.hrp_sapling_private_key(), self.config.hrp_sapling_viewing_key()))
        }
    }

    /// Import a new private key
    pub fn do_import_sk(&self, sk: String, birthday: u64) -> Result<JsonValue, String> {
        if !self.wallet.read().unwrap().is_unlocked_for_spending() {
            error!("Wallet is locked");
            return Err("Wallet is locked".to_string());
        }

        let new_address = {
            let mut wallet = self.wallet.write().unwrap();

            let addr = wallet.add_imported_sk(sk, birthday);
            if addr.starts_with("Error") {
                let e = format!("Error creating new address{}", addr);
                    error!("{}", e);
                    return Err(e);
            }

            addr
        };

        self.do_save()?;

        Ok(array![new_address])
    }

    /// Import a new viewing key
    pub fn do_import_vk(&self, vk: String, birthday: u64) -> Result<JsonValue, String> {
        if !self.wallet.read().unwrap().is_unlocked_for_spending() {
            error!("Wallet is locked");
            return Err("Wallet is locked".to_string());
        }

        let new_address = {
            let mut wallet = self.wallet.write().unwrap();

            let addr = wallet.add_imported_vk(vk, birthday);
            if addr.starts_with("Error") {
                let e = format!("Error creating new address{}", addr);
                    error!("{}", e);
                    return Err(e);
            }

            addr
        };

        self.do_save()?;

        Ok(array![new_address])
    }
    

    pub fn clear_state(&self) {
        // First, clear the state from the wallet
        self.wallet.read().unwrap().clear_blocks();

        // Then set the initial block
        let birthday = self.wallet.read().unwrap().get_birthday();
        self.set_wallet_initial_state(birthday);
        info!("Cleared wallet state, with birthday at {}", birthday);
    }

    pub fn do_rescan(&self) -> Result<JsonValue, String> {
        if !self.wallet.read().unwrap().is_unlocked_for_spending() {
            warn!("Wallet is locked, new HD addresses won't be added!");
        }
        
        info!("Rescan starting");
        
        self.clear_state();

        // Then, do a sync, which will force a full rescan from the initial state
        let response = self.do_sync(true);

        self.do_save()?;
        info!("Rescan finished");

        response
    }

    pub fn do_verify_from_last_checkpoint(&self) -> Result<bool, String> {
        // If there are no blocks in the wallet, then we are starting from scratch, so no need to verify anything.
        let last_height = self.wallet.read().unwrap().last_scanned_height() as u64;
        if last_height == self.config.sapling_activation_height -1 {
            info!("Reset the sapling tree verified to true. (Block height is at the begining ({}))", last_height);
            self.wallet.write().unwrap().set_sapling_tree_verified();

            return Ok(true);
        }

        // Get the first block's details, and make sure we can compute it from the last checkpoint
        // Note that we get the first block in the wallet (Not the last one). This is expected to be tip - 100 blocks.
        // We use this block to prevent any reorg risk. 
        let (end_height, _, end_tree) = match self.wallet.read().unwrap().get_wallet_sapling_tree(NodePosition::First) {
            Ok(r) => r,
            Err(e) => return Err(format!("No wallet block found: {}", e))
        };

        // Get the last checkpoint
        let (start_height, _, start_tree) = match checkpoints::get_closest_checkpoint(&self.config.chain_name, end_height as u64) {
            Some(r) => r,
            None => return Err(format!("No checkpoint found"))
        };
        
        // If the height is the same as the checkpoint, then just compare directly
        if end_height as u64 == start_height {
            let verified = end_tree == start_tree;
            
            if verified {
                info!("Reset the sapling tree verified to true");
                self.wallet.write().unwrap().set_sapling_tree_verified();
            } else {
                warn!("Sapling tree verification failed!");
                warn!("Verification Results:\nCalculated\n{}\nExpected\n{}\n", start_tree, end_tree);
            }

            return Ok(verified);
        }
        
        let sapling_tree = hex::decode(start_tree).unwrap();

        // The comupted commitment tree will be here.
        let commit_tree_computed = Arc::new(RwLock::new(CommitmentTree::read(&sapling_tree[..]).map_err(|e| format!("{}", e))?));

        let pool = ThreadPool::new(2);
        let commit_tree = commit_tree_computed.clone();
        grpcconnector::fetch_blocks(&self.get_server_uri(), start_height+1, end_height as u64, pool, 
            move |encoded_block: &[u8], height: u64| {
                let block: Result<zcash_client_backend::proto::compact_formats::CompactBlock, _>
                                        = protobuf::Message::parse_from_bytes(encoded_block);
                if block.is_err() {
                    error!("Error getting block, {}", block.err().unwrap());
                    return;
                }

                // Go over all tx, all outputs. No need to do any processing, just update the commitment tree
                for tx in block.unwrap().vtx.iter() {
                    for so in tx.outputs.iter() {
                        let node = Node::new(so.cmu().ok().unwrap().into());
                        commit_tree.write().unwrap().append(node).unwrap();
                    }
                }

                // Write updates every now and then.
                if height % 10000 == 0 {
                    info!("Verification at block {}", height);
                }
            }
        )?;

        // Get the string version of the tree
        let mut write_buf = vec![];
        commit_tree_computed.write().unwrap().write(&mut write_buf).map_err(|e| format!("{}", e))?;
        let computed_tree = hex::encode(write_buf);
        
        let verified = computed_tree == end_tree;
        if verified {
            info!("Reset the sapling tree verified to true");
            self.wallet.write().unwrap().set_sapling_tree_verified();
        } else {
            warn!("Sapling tree verification failed!");
            warn!("Verification Results:\nCalculated\n{}\nExpected\n{}\n", computed_tree, end_tree);
        }

        return Ok(verified);
    }

    /// Return the syncing status of the wallet
    pub fn do_scan_status(&self) -> WalletStatus {
        self.sync_status.read().unwrap().clone()
    }

    // Update the historical prices in the wallet, if any are present. 
    fn update_historical_prices(&self) {
        let price_info = self.wallet.read().unwrap().price_info.read().unwrap().clone();
        // First, if the retry count has exceeded 5, we give up. Something is wrong, and will need to be 
        // fixed in a later version
        if price_info.historical_prices_retry_count > 5 {
            warn!("Not getting historical prices because retry count has exceeded");
            return
        }

        // If the prices were fetched recently, don't try again soon
        if price_info.historical_prices_retry_count > 0 && 
            price_info.last_historical_prices_fetched_at.is_some() && 
            (price_info.last_historical_prices_fetched_at.unwrap() as i64 - lightwallet::now() as i64).abs() > 24 * 60 * 60 {
            warn!("Last retry failed, not trying again till tomorrow!");
            return;
        }

        // Gather all transactions that need historical prices
        let txids_to_fetch = self.wallet.read().unwrap().txs.read().unwrap().iter().filter_map(|(txid, wtx)|
            match wtx.zec_price {
                None => Some((txid.clone(), wtx.datetime)),
                Some(_) => None,
            }
        ).collect::<Vec<(TxId, u64)>>();
        info!("Fetching historical prices for {} txids", txids_to_fetch.len());

        let retry_count_increase = match grpcconnector::get_historical_zec_prices(&self.get_server_uri(), txids_to_fetch, price_info.currency) {
            Ok(prices) => {
                let w = self.wallet.read().unwrap();
                let mut txns = w.txs.write().unwrap();
                
                let any_failed = prices.iter().map(|(txid, p)| {
                    match p {
                        None => true,
                        Some(p) => {
                            // Update the price
                            info!("Historical price at txid {} was {}", txid, p);
                            txns.get_mut(txid).unwrap().zec_price = Some(*p);
                            
                            // Not failed, so return false
                            false
                        }
                    }
                }).find(|s| *s).is_some();

                // If any of the txids failed, increase the retry_count by 1.
                if any_failed { 1 } else { 0 }
            },
            Err(_) => {
                1
            }
        };

        {
            let w = self.wallet.read().unwrap();
            let mut p = w.price_info.write().unwrap();
            p.last_historical_prices_fetched_at = Some(lightwallet::now());
            p.historical_prices_retry_count += retry_count_increase;
        }
           
    }

    pub fn do_sync(&self, print_updates: bool) -> Result<JsonValue, String> {
        let mut retry_count = 0;
        loop {
            match self.do_sync_internal(print_updates, retry_count) {
                Ok(j) => {
                    // If sync was successfull, also try to get historical prices
                    self.update_historical_prices();

                    return Ok(j)
                },
                Err(e) => {
                    retry_count += 1;
                    if retry_count > 5 {
                        return Err(e);
                    }
                    // Sleep exponentially backing off
                    std::thread::sleep(std::time::Duration::from_secs((2 as u64).pow(retry_count)));
                    println!("Sync error {}\nRetry count {}", e, retry_count);
                }
            }
        }
    }

    fn do_sync_internal(&self, print_updates: bool, retry_count: u32) -> Result<JsonValue, String> {
        // We can only do one sync at a time because we sync blocks in serial order
        // If we allow multiple syncs, they'll all get jumbled up.
        let _lock = self.sync_lock.lock().unwrap();

        // See if we need to verify first
        if !self.wallet.read().unwrap().is_sapling_tree_verified() {
            match self.do_verify_from_last_checkpoint() {
                Err(e) => return Err(format!("Checkpoint failed to verify with eror:{}.\nYou should rescan.", e)),
                Ok(false) => return Err(format!("Checkpoint failed to verify: Verification returned false.\nYou should rescan.")),
                _ => {}
            }
        }

        // Sync is 3 parts
        // 1. Get the latest block
        // 2. Get all the blocks that we don't have
        // 3. Find all new Txns that don't have the full Tx, and get them as full transactions 
        //    and scan them, mainly to get the memos
        let mut last_scanned_height = self.wallet.read().unwrap().last_scanned_height() as u64;

        // This will hold the latest block fetched from the RPC
        let latest_block = fetch_latest_block(&self.get_server_uri())?.height;
       
        if latest_block < last_scanned_height {
            let w = format!("Server's latest block({}) is behind ours({})", latest_block, last_scanned_height);
            warn!("{}", w);
            return Err(w);
        }

        info!("Latest block is {}", latest_block);

        // Get the end height to scan to.
        let scan_batch_size = 1000;
        let mut end_height = std::cmp::min(last_scanned_height + scan_batch_size, latest_block);

        // If there's nothing to scan, just return
        if last_scanned_height == latest_block {
            info!("Nothing to sync, returning");
            return Ok(object!{ "result" => "success" })
        }

        {
            let mut status = self.sync_status.write().unwrap();
            status.is_syncing = true;
            status.synced_blocks = last_scanned_height;
            status.total_blocks = latest_block;
        }

        // Count how many bytes we've downloaded
        let bytes_downloaded = Arc::new(AtomicUsize::new(0));

        let mut total_reorg = 0;

        // Collect all txns in blocks that we have a tx in. We'll fetch all these
        // txs along with our own, so that the server doesn't learn which ones
        // belong to us.
        let all_new_txs = Arc::new(RwLock::new(vec![]));

        // Create a new threadpool (upto 8, atleast 2 threads) to scan with
        let pool = ThreadPool::new(max(2, min(8, num_cpus::get())));

        // Fetch CompactBlocks in increments
        let mut pass = 0;
        loop {
            pass +=1 ;
            // Collect all block times, because we'll need to update transparent tx
            // datetime via the block height timestamp
            let block_times = Arc::new(RwLock::new(HashMap::new()));

            let local_light_wallet = self.wallet.clone();
            let local_bytes_downloaded = bytes_downloaded.clone();

            let start_height = last_scanned_height + 1;

            // Show updates only if we're syncing a lot of blocks
            if print_updates && (latest_block - start_height) > 100 {
                print!("Syncing {}/{}\r", start_height, latest_block);
                io::stdout().flush().ok().expect("Could not flush stdout");
            }

            {
                let mut status = self.sync_status.write().unwrap();
                status.is_syncing = true;
                status.synced_blocks = start_height;
                status.total_blocks = latest_block;
            }

            // Fetch compact blocks
            info!("Fetching blocks {}-{}", start_height, end_height);

            let all_txs = all_new_txs.clone();
            let block_times_inner = block_times.clone();

            let last_invalid_height = Arc::new(AtomicI32::new(0));
            let last_invalid_height_inner = last_invalid_height.clone();

            let tpool = pool.clone();
            fetch_blocks(&self.get_server_uri(), start_height, end_height, pool.clone(),
                move |encoded_block: &[u8], height: u64| {
                    // Process the block only if there were no previous errors
                    if last_invalid_height_inner.load(Ordering::SeqCst) > 0 {
                        return;
                    }

                    // Parse the block and save it's time. We'll use this timestamp for 
                    // transactions in this block that might belong to us.
                    let block: Result<zcash_client_backend::proto::compact_formats::CompactBlock, _>
                                        = protobuf::Message::parse_from_bytes(encoded_block);
                    match block {
                        Ok(b) => {
                            block_times_inner.write().unwrap().insert(b.height, b.time);
                        },
                        Err(_) => {}
                    }

                    match local_light_wallet.read().unwrap().scan_block_with_pool(encoded_block, &tpool) {
                        Ok(block_txns) => {
                            // Add to global tx list
                            all_txs.write().unwrap().extend_from_slice(&block_txns.iter().map(|txid| (txid.clone(), height as i32)).collect::<Vec<_>>()[..]);
                        },
                        Err(invalid_height) => {
                            // Block at this height seems to be invalid, so invalidate up till that point
                            last_invalid_height_inner.store(invalid_height, Ordering::SeqCst);
                        }
                    };

                    local_bytes_downloaded.fetch_add(encoded_block.len(), Ordering::SeqCst);
            })?;

            // Check if there was any invalid block, which means we might have to do a reorg
            let invalid_height = last_invalid_height.load(Ordering::SeqCst);
            if invalid_height > 0 {
                total_reorg += self.wallet.read().unwrap().invalidate_block(invalid_height);

                warn!("Invalidated block at height {}. Total reorg is now {}", invalid_height, total_reorg);
            }

            // Make sure we're not re-orging too much!
            if total_reorg > (crate::lightwallet::MAX_REORG - 1) as u64 {
                error!("Reorg has now exceeded {} blocks!", crate::lightwallet::MAX_REORG);
                return Err(format!("Reorg has exceeded {} blocks. Aborting.", crate::lightwallet::MAX_REORG));
            } 
            
            if invalid_height > 0 {
                // Reset the scanning heights
                last_scanned_height = (invalid_height - 1) as u64;
                end_height = std::cmp::min(last_scanned_height + scan_batch_size, latest_block);

                warn!("Reorg: reset scanning from {} to {}", last_scanned_height, end_height);

                continue;
            }

            // If it got here, that means the blocks are scanning properly now. 
            // So, reset the total_reorg
            total_reorg = 0;

            // We'll also fetch all the txids that our transparent addresses are involved with
            {
                // Copy over addresses so as to not lock up the wallet, which we'll use inside the callback below. 
                let addresses = self.wallet.read().unwrap()
                                    .taddresses.read().unwrap().iter().map(|a| a.clone())
                                    .collect::<Vec<String>>();
                
                // Create a channel so the fetch_transparent_txids can send the results back
                let (ctx, crx) = channel();
                let num_addresses = addresses.len();

                for address in addresses {
                    let wallet = self.wallet.clone();
                    let block_times_inner = block_times.clone();

                    // If this is the first pass after a retry, fetch older t address txids too, becuse
                    // they might have been missed last time.
                    let transparent_start_height = if pass == 1 && retry_count > 0 {
                        start_height - scan_batch_size
                    } else {
                        start_height
                    };

                    let pool = pool.clone();
                    let server_uri = self.get_server_uri();
                    let ctx = ctx.clone();

                    pool.execute(move || {
                        // Fetch the transparent transactions for this address, and send the results 
                        // via the channel
                        let r = fetch_transparent_txids(&server_uri, address, transparent_start_height, end_height,
                            move |tx_bytes: &[u8], height: u64| {
                                let tx = Transaction::read(tx_bytes).unwrap();

                                // Scan this Tx for transparent inputs and outputs
                                let datetime = block_times_inner.read().unwrap().get(&height).map(|v| *v).unwrap_or(0);
                                wallet.read().unwrap().scan_full_tx(&tx, height as i32, datetime as u64); 
                        });
                        ctx.send(r).unwrap();
                    });
                }

                // Collect all results from the transparent fetches, and make sure everything was OK. 
                // If it was not, we return an error, which will go back to the retry
                crx.iter().take(num_addresses).collect::<Result<Vec<()>, String>>()?;
            }           
            
            // Do block height accounting
            last_scanned_height = end_height;
            end_height = last_scanned_height + scan_batch_size;

            if last_scanned_height >= latest_block {
                break;
            } else if end_height > latest_block {
                end_height = latest_block;
            }
        }

        if print_updates{
            println!(""); // New line to finish up the updates
        }

        info!("Synced to {}, Downloaded {} kB", latest_block, bytes_downloaded.load(Ordering::SeqCst) / 1024);
        {
            let mut status = self.sync_status.write().unwrap();
            status.is_syncing = false;
            status.synced_blocks = latest_block;
            status.total_blocks = latest_block;
        }

        // Get the zec price from the server
        match grpcconnector::get_current_zec_price(&self.get_server_uri()) {
            Ok(p) => {
                self.wallet.write().unwrap().set_latest_zec_price(p);
            }
            Err(s) => error!("Error fetching latest price: {}", s)
        }

        // Get the Raw transaction for all the wallet transactions

        // We need to first copy over the Txids from the wallet struct, because
        // we need to free the read lock from here (Because we'll self.wallet.txs later)
        let mut txids_to_fetch: Vec<(TxId, i32)> = self.wallet.read().unwrap().txs.read().unwrap().values()
                                                        .filter(|wtx| wtx.full_tx_scanned == false)
                                                        .map(|wtx| (wtx.txid.clone(), wtx.block))
                                                        .collect::<Vec<(TxId, i32)>>();

        info!("Fetching {} new txids, total {} with decoy", txids_to_fetch.len(), all_new_txs.read().unwrap().len());
        txids_to_fetch.extend_from_slice(&all_new_txs.read().unwrap()[..]);
        txids_to_fetch.sort();
        txids_to_fetch.dedup();

        let result: Vec<Result<(), String>> = {
            // Fetch all the txids in a parallel iterator
            use rayon::prelude::*;

            let light_wallet_clone = self.wallet.clone();
            let server_uri = self.get_server_uri();

            txids_to_fetch.par_iter().map(|(txid, height)| {
                info!("Fetching full Tx: {}", txid);

                match fetch_full_tx(&server_uri, *txid) {
                    Ok(tx_bytes) => {
                        let tx = Transaction::read(&tx_bytes[..]).unwrap();
    
                        light_wallet_clone.read().unwrap().scan_full_tx(&tx, *height, 0);
                        Ok(())
                    },
                    Err(e) => Err(e)
                }
            }).collect()
        };
        
        // Wait for all the fetches to finish.
        match result.into_iter().collect::<Result<Vec<()>, String>>() {
            Ok(_) => Ok(object!{
                "result" => "success",
                "latest_block" => latest_block,
                "downloaded_bytes" => bytes_downloaded.load(Ordering::SeqCst)
            }),
            Err(e) => Err(format!("Error fetching all txns for memos: {}", e))
        }        
    }

    pub fn do_shield(&self, address: Option<String>) -> Result<String, String> {
        let fee = fee::get_default_fee(self.wallet.read().unwrap().last_scanned_height());
        let tbal = self.wallet.read().unwrap().tbalance(None);

        // Make sure there is a balance, and it is greated than the amount
        if tbal <= fee {
            return Err(format!("Not enough transparent balance to shield. Have {} zats, need more than {} zats to cover tx fee", tbal, fee));
        }

        let addr = address.or(self.wallet.read().unwrap().get_all_zaddresses().get(0).map(|s| s.clone())).unwrap();
        let branch_id = self.consensus_branch_id();

        let result = {
            let _lock = self.sync_lock.lock().unwrap();
            let prover = LocalTxProver::from_bytes(&self.sapling_spend, &self.sapling_output);
            
            self.wallet.read().unwrap().send_to_address(
                branch_id,
                prover,
                true, 
                vec![(&addr, tbal - fee, None)],
                |txbytes| broadcast_raw_tx(&self.get_server_uri(), txbytes)
            )
        };

        result.map(|(txid, _)| txid)
    }

    fn consensus_branch_id(&self) -> u32 { 
        let height = self.wallet.read().unwrap().last_scanned_height();
        let branch: BranchId = BranchId::for_height(&MAIN_NETWORK, BlockHeight::from_u32(height as u32));
        let branch_id: u32 = u32::from(branch);
        branch_id
    }

    pub fn do_send(&self, addrs: Vec<(&str, u64, Option<String>)>) -> Result<String, String> {
        // First, get the concensus branch ID
        let branch_id = self.consensus_branch_id();
        info!("Creating transaction");

        let result = {
            let _lock = self.sync_lock.lock().unwrap();
            let prover = LocalTxProver::from_bytes(&self.sapling_spend, &self.sapling_output);

            self.wallet.read().unwrap().send_to_address(
                branch_id, 
                prover,
                false,
                addrs,
                |txbytes| broadcast_raw_tx(&self.get_server_uri(), txbytes)
            )
        };
        
        result.map(|(txid, _)| txid)
    }
}

#[cfg(test)]
pub mod tests {
    use lazy_static::lazy_static;
    use tempdir::TempDir;
    use super::{LightClient, LightClientConfig};

    lazy_static!{
        static ref TEST_SEED: String = "youth strong sweet gorilla hammer unhappy congress stamp left stereo riot salute road tag clean toilet artefact fork certain leopard entire civil degree wonder".to_string();
    }

    #[test]
    pub fn test_encrypt_decrypt() {
        let lc = super::LightClient::unconnected(TEST_SEED.to_string(), None).unwrap();

        assert!(!lc.do_export(None).is_err());
        assert!(!lc.do_new_address("z").is_err());
        assert!(!lc.do_new_address("t").is_err());
        assert_eq!(lc.do_seed_phrase().unwrap()["seed"], TEST_SEED.to_string());

        // Encrypt and Lock the wallet
        lc.wallet.write().unwrap().encrypt("password".to_string()).unwrap();
        assert!(lc.do_export(None).is_err());
        assert!(lc.do_seed_phrase().is_err());
        assert!(lc.do_new_address("t").is_err());
        assert!(lc.do_new_address("z").is_err());
        assert!(lc.do_send(vec![("z", 0, None)]).is_err());

        // Do a unlock, and make sure it all works now
        lc.wallet.write().unwrap().unlock("password".to_string()).unwrap();
        assert!(!lc.do_export(None).is_err());
        assert!(!lc.do_seed_phrase().is_err());

        // This will lock the wallet again, so after this, we'll need to unlock again
        assert!(!lc.do_new_address("t").is_err());
        lc.wallet.write().unwrap().unlock("password".to_string()).unwrap();
        
        assert!(!lc.do_new_address("z").is_err());
    }

    #[test]
    pub fn test_bad_import() {
        let lc = super::LightClient::unconnected(TEST_SEED.to_string(), None).unwrap();
        
        assert!(lc.do_import_sk("bad_priv_key".to_string(), 0).is_err());
        assert!(lc.do_import_vk("bad_view_key".to_string(), 0).is_err());
    }

    #[test]
    pub fn test_addresses() {
        let lc = super::LightClient::unconnected(TEST_SEED.to_string(), None).unwrap();
        
        {
            let addresses = lc.do_address();
            // When restoring from seed, there should be 5+1 addresses
            assert_eq!(addresses["z_addresses"].len(), 6);
            assert_eq!(addresses["t_addresses"].len(), 6);
        }
        
        // Add new z and t addresses
        let taddr1 = lc.do_new_address("t").unwrap()[0].as_str().unwrap().to_string();
        let taddr2 = lc.do_new_address("t").unwrap()[0].as_str().unwrap().to_string();        
        let zaddr1 = lc.do_new_address("z").unwrap()[0].as_str().unwrap().to_string();
        let zaddr2 = lc.do_new_address("z").unwrap()[0].as_str().unwrap().to_string();
        
        let addresses = lc.do_address();
        assert_eq!(addresses["z_addresses"].len(), 8);
        assert_eq!(addresses["z_addresses"][6], zaddr1);
        assert_eq!(addresses["z_addresses"][7], zaddr2);

        assert_eq!(addresses["t_addresses"].len(), 8);
        assert_eq!(addresses["t_addresses"][6], taddr1);
        assert_eq!(addresses["t_addresses"][7], taddr2);

        use std::sync::{Arc, RwLock, Mutex};
        use crate::lightclient::{WalletStatus, LightWallet};

        // When creating a new wallet, there is only 1 address
        let config = LightClientConfig::create_unconnected("test".to_string(), None);
        let lc = LightClient {
            wallet          : Arc::new(RwLock::new(LightWallet::new(None, &config, 0).unwrap())),
            config          : config,
            sapling_output  : vec![], 
            sapling_spend   : vec![],
            sync_lock       : Mutex::new(()),
            sync_status     : Arc::new(RwLock::new(WalletStatus::new())),
        };
        {
            let addresses = lc.do_address();
            // New wallets have only 1 address
            assert_eq!(addresses["z_addresses"].len(), 1);
            assert_eq!(addresses["t_addresses"].len(), 1);
        }
    }

    #[test]
    pub fn test_wallet_creation() {
        // Create a new tmp director
        {
            let tmp = TempDir::new("lctest").unwrap();
            let dir_name = tmp.path().to_str().map(|s| s.to_string());

            // A lightclient to a new, empty directory works.
            let config = LightClientConfig::create_unconnected("test".to_string(), dir_name);
            let lc = LightClient::new(&config, 0).unwrap();
            let seed = lc.do_seed_phrase().unwrap()["seed"].as_str().unwrap().to_string();
            lc.do_save().unwrap();

            // Doing another new will fail, because the wallet file now already exists
            assert!(LightClient::new(&config, 0).is_err());

            // new_from_phrase will not work either, again, because wallet file exists
            assert!(LightClient::new_from_phrase(TEST_SEED.to_string(), &config, 0, false).is_err());

            // Creating a lightclient to the same dir without a seed should re-read the same wallet
            // file and therefore the same seed phrase
            let lc2 = LightClient::read_from_disk(&config).unwrap();
            assert_eq!(seed, lc2.do_seed_phrase().unwrap()["seed"].as_str().unwrap().to_string());
        }

        // Now, get a new directory, and try to read from phrase
        {
            let tmp = TempDir::new("lctest").unwrap();
            let dir_name = tmp.path().to_str().map(|s| s.to_string());

            let config = LightClientConfig::create_unconnected("test".to_string(), dir_name);

            // read_from_disk will fail, because the dir doesn't exist
            assert!(LightClient::read_from_disk(&config).is_err());

            // New from phrase should work becase a file doesn't exist already
            let lc = LightClient::new_from_phrase(TEST_SEED.to_string(), &config, 0, false).unwrap();
            assert_eq!(TEST_SEED.to_string(), lc.do_seed_phrase().unwrap()["seed"].as_str().unwrap().to_string());
            lc.do_save().unwrap();

            // Now a new will fail because wallet exists
            assert!(LightClient::new(&config, 0).is_err());
        }
    }

    #[test]
    pub fn test_recover_seed() {
        // Create a new tmp director
        {
            let tmp = TempDir::new("lctest").unwrap();
            let dir_name = tmp.path().to_str().map(|s| s.to_string());

            // A lightclient to a new, empty directory works.
            let config = LightClientConfig::create_unconnected("test".to_string(), dir_name);
            let lc = LightClient::new(&config, 0).unwrap();
            let seed = lc.do_seed_phrase().unwrap()["seed"].as_str().unwrap().to_string();
            lc.do_save().unwrap();

            assert_eq!(seed, LightClient::attempt_recover_seed(&config, None).unwrap());

            // Now encrypt and save the file
            let pwd = "password".to_string();
            lc.wallet.write().unwrap().encrypt(pwd.clone()).unwrap();
            lc.do_save().unwrap();

            assert_eq!(seed, LightClient::attempt_recover_seed(&config, Some(pwd)).unwrap());
        }
    }

    #[test]
    pub fn test_set_params() {
        let tmp = TempDir::new("lctest").unwrap();
        let dir_name = tmp.path().to_str().map(|s| s.to_string());

        let config = LightClientConfig::create_unconnected("test".to_string(), dir_name);
        let mut lc = LightClient::new(&config, 0).unwrap();

        use crate::SaplingParams;
        assert!(lc.set_sapling_params(
            SaplingParams::get("sapling-output.params").unwrap().as_ref(), 
            SaplingParams::get("sapling-spend.params").unwrap().as_ref()).is_ok());
    }


    #[test]
    fn test_checkpoint_block_verification() {
        let tmp = TempDir::new("lctest").unwrap();
        let dir_name = tmp.path().to_str().map(|s| s.to_string());
        let config = LightClientConfig::create_unconnected("test".to_string(), dir_name);
        let lc = LightClient::new(&config, 0).unwrap();

        assert_eq!(lc.wallet.read().unwrap().is_sapling_tree_verified(), false);
    
        // Verifying it immediately should succeed because there are no blocks, and start height is sapling activation height
        assert!(lc.do_verify_from_last_checkpoint().is_ok());
        assert_eq!(lc.wallet.read().unwrap().is_sapling_tree_verified(), true);
    
        // Test data
        let (height, hash, tree) =  (650000, "003f7e09a357a75c3742af1b7e1189a9038a360cebb9d55e158af94a1c5aa682",
        "010113f257f93a40e25cfc8161022f21c06fa2bc7fb03ee9f9399b3b30c636715301ef5b99706e40a19596d758bf7f4fd1b83c3054557bf7fab4801985642c317d41100001b2ad599fd7062af72bea99438dc5d8c3aa66ab52ed7dee3e066c4e762bd4e42b0001599dd114ec6c4c5774929a342d530bf109b131b48db2d20855afa9d37c92d6390000019159393c84b1bf439d142ed2c54ee8d5f7599a8b8f95e4035a75c30b0ec0fa4c0128e3a018bd08b2a98ed8b6995826f5857a9dc2777ce6af86db1ae68b01c3c53d0000000001e3ec5d790cc9acc2586fc6e9ce5aae5f5aba32d33e386165c248c4a03ec8ed670000011f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d39");
    
        assert!(lc.wallet.write().unwrap().set_initial_block(height, hash, tree));

        // Setting inital block should make the verification status false
        assert_eq!(lc.wallet.read().unwrap().is_sapling_tree_verified(), false);
    
        // Now, verifying it immediately should succeed because it should just verify the checkpoint
        assert!(lc.do_verify_from_last_checkpoint().is_ok());
        assert_eq!(lc.wallet.read().unwrap().is_sapling_tree_verified(), true);
    }
    

}