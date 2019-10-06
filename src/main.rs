#[macro_use]
extern crate rust_embed;

mod lightclient;
mod grpcconnector;
mod lightwallet;
mod commands;

use std::io::{Result, Error, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use lightclient::{LightClient, LightClientConfig};

use log::{info, LevelFilter};
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::config::{Appender, Config, Root};
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::append::rolling_file::policy::compound::{
    CompoundPolicy,
    trigger::size::SizeTrigger,
    roll::fixed_window::FixedWindowRoller,
};

use rustyline::error::ReadlineError;
use rustyline::Editor;

use clap::{Arg, App};

pub mod grpc_client {
    include!(concat!(env!("OUT_DIR"), "/cash.z.wallet.sdk.rpc.rs"));
}

#[derive(RustEmbed)]
#[folder = "zcash-params/"]
pub struct SaplingParams;

const ANCHOR_OFFSET: u32 = 4;

/// Build the Logging config
fn get_log_config(config: &LightClientConfig) -> Result<Config> {
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
                            .build(config.get_log_path(), Box::new(compound_policy))?,
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


pub fn main() {
    // Get command line arguments
    let matches = App::new("Zecwallet CLI")
                    .version("0.2.1") 
                    .arg(Arg::with_name("seed")
                        .short("s")
                        .long("seed")
                        .value_name("seed_phrase")
                        .help("Create a new wallet with the given 24-word seed phrase. Will fail if wallet already exists")
                        .takes_value(true))
                    .arg(Arg::with_name("server")
                        .long("server")
                        .value_name("server")
                        .help("Lightwalletd server to connect to.")
                        .takes_value(true)
                        .default_value(lightclient::DEFAULT_SERVER))
                    .get_matches();

    let maybe_server  = matches.value_of("server").map(|s| s.to_string());
    let seed          = matches.value_of("seed").map(|s| s.to_string());

    let server = LightClientConfig::get_server_or_default(maybe_server);

    // Test to make sure the server has all of scheme, host and port
    if server.scheme_str().is_none() || server.host().is_none() || server.port_part().is_none() {
        eprintln!("Please provide the --server parameter as [scheme]://[host]:[port].\nYou provided: {}", server);
        return;
    }

    // Do a getinfo first, before opening the wallet
    let info = match grpcconnector::get_info(server.clone()) {
        Ok(ld) => ld,
        Err(e) => {
            eprintln!("Error:\n{}\nCouldn't get server info, quitting!", e);
            return;
        }
    };

    // Create a Light Client Config
    let config = lightclient::LightClientConfig {
        server                      : server.clone(),
        chain_name                  : info.chain_name,
        sapling_activation_height   : info.sapling_activation_height,
        consensus_branch_id         : info.consensus_branch_id,
        anchor_offset               : ANCHOR_OFFSET,
    };

    // Configure logging first.
    let log_config = match get_log_config(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error:\n{}\nCouldn't configure logging, quitting!", e);
            return;
        }
    };
    log4rs::init_config(log_config).unwrap();

    // Startup
    info!(""); // Blank line
    info!("Starting Zecwallet-CLI");
    info!("Light Client config {:?}", config);

    let lightclient = match LightClient::new(seed, &config, info.block_height) {
        Ok(lc) => Arc::new(lc),
        Err(e) => { eprintln!("Failed to start wallet. Error was:\n{}", e); return; }
    };


    // At startup, run a sync
    let sync_update = lightclient.do_sync(true);
    println!("{}", sync_update);

    let (command_tx, command_rx) = std::sync::mpsc::channel::<(String, Vec<String>)>();
    let (resp_tx, resp_rx) = std::sync::mpsc::channel::<String>();

    let lc = lightclient.clone();
    std::thread::spawn(move || {
        loop {
            match command_rx.recv_timeout(Duration::from_secs(5 * 60)) {
                Ok((cmd, args)) => {
                    let args = args.iter().map(|s| s.as_ref()).collect();
                    let cmd_response = commands::do_user_command(&cmd, &args, &lc);
                    resp_tx.send(cmd_response).unwrap();

                    if cmd == "quit" {
                        info!("Quit");
                        break;
                    }
                },
                Err(_) => {
                    // Timeout. Do a sync to keep the wallet up-to-date. False to whether to print updates on the console
                    info!("Timeout, doing a sync");
                    lc.do_sync(false);
                }
            }
        }
    });

    // `()` can be used when no completer is required
    let mut rl = Editor::<()>::new();

    println!("Ready!");

    loop {
        let readline = rl.readline(&format!("({}) Block:{} (type 'help') >> ",
                                            config.chain_name,
                                            lightclient.last_scanned_height()));
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                // Parse command line arguments
                let mut cmd_args = match shellwords::split(&line) {
                    Ok(args) => args,
                    Err(_)   => {
                        println!("Mismatched Quotes");
                        continue;
                    }
                };

                if cmd_args.is_empty() {
                    continue;
                }

                let cmd = cmd_args.remove(0);
                let args: Vec<String> = cmd_args;            
                command_tx.send((cmd, args)).unwrap();

                // Wait for the response
                match resp_rx.recv() {
                    Ok(response) => println!("{}", response),
                    _ => { eprintln!("Error receiving response");}
                }

                // Special check for Quit command.
                if line == "quit" {
                    break;
                }
            },
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                info!("CTRL-C");
                println!("{}", lightclient.do_save());
                break
            },
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                info!("CTRL-D");
                println!("{}", lightclient.do_save());
                break
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break
            }
        }
    }

}