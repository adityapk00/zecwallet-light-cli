use std::io::{Result, Error, ErrorKind};
use std::sync::Arc;
use std::sync::mpsc::{channel, Sender, Receiver};

use zecwalletlitelib::{commands, startup_helpers,
    lightclient::{self, LightClient, LightClientConfig},
};

use log::{info, error, LevelFilter};
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::config::{Appender, Config, Root};
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::append::rolling_file::policy::compound::{
    CompoundPolicy,
    trigger::size::SizeTrigger,
    roll::fixed_window::FixedWindowRoller,
};



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
    use clap::{Arg, App};
    let matches = App::new("Zecwallet CLI")
                    .version("1.0.0")
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
                    .arg(Arg::with_name("dangerous")
                        .long("dangerous")
                        .help("Disable server TLS certificate verification. Use this if you're running a local lightwalletd with a self-signed certificate. WARNING: This is dangerous, don't use it with a server that is not your own.")
                        .takes_value(false))
                    .arg(Arg::with_name("recover")
                        .long("recover")
                        .help("Attempt to recover the seed from the wallet")
                        .takes_value(false))
                    .arg(Arg::with_name("nosync")
                        .help("By default, zecwallet-cli will sync the wallet at startup. Pass --nosync to prevent the automatic sync at startup.")
                        .long("nosync")
                        .short("n")
                        .takes_value(false))
                    .arg(Arg::with_name("COMMAND")
                        .help("Command to execute. If a command is not specified, zecwallet-cli will start in interactive mode.")
                        .required(false)
                        .index(1))
                    .arg(Arg::with_name("PARAMS")
                        .help("Params to execute command with. Run the 'help' command to get usage help.")
                        .required(false)
                        .multiple(true))
                    .get_matches();

    if matches.is_present("recover") {
        attempt_recover_seed();
        return;
    }

    let command = matches.value_of("COMMAND");
    let params = matches.values_of("PARAMS").map(|v| v.collect()).or(Some(vec![])).unwrap();

    let maybe_server  = matches.value_of("server").map(|s| s.to_string());
    let seed          = matches.value_of("seed").map(|s| s.to_string());

    let server = LightClientConfig::get_server_or_default(maybe_server);

    // Test to make sure the server has all of scheme, host and port
    if server.scheme_str().is_none() || server.host().is_none() || server.port_part().is_none() {
        eprintln!("Please provide the --server parameter as [scheme]://[host]:[port].\nYou provided: {}", server);
        return;
    }

    let dangerous = matches.is_present("dangerous");
    let nosync = matches.is_present("nosync");
    let (command_tx, resp_rx) = match startup(server, dangerous, seed, !nosync, command.is_none()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error during startup: {}", e);
            error!("Error during startup: {}", e);
            match e.raw_os_error() {
                Some(13) => {
                    startup_helpers::report_permission_error();
                },
                _ => eprintln!("Something else!")
            }
            return;
        }
    };

    if command.is_none() {
        start_interactive(command_tx, resp_rx);
    } else {
        command_tx.send(
            (command.unwrap().to_string(),
                params.iter().map(|s| s.to_string()).collect::<Vec<String>>()))
            .unwrap();

        match resp_rx.recv() {
            Ok(s) => println!("{}", s),
            Err(e) => {
                let e = format!("Error executing command {}: {}", command.unwrap(), e);
                eprintln!("{}", e);
                error!("{}", e);
            }
        }

        // Save before exit
        command_tx.send(("save".to_string(), vec![])).unwrap();
        resp_rx.recv().unwrap();
    }
}

fn startup(server: http::Uri, dangerous: bool, seed: Option<String>, first_sync: bool, print_updates: bool)
        -> Result<(Sender<(String, Vec<String>)>, Receiver<String>)> {
    // Try to get the configuration
    let (config, latest_block_height) = LightClientConfig::create(server.clone(), dangerous)?;

    // Configure logging first.
    let log_config = get_log_config(&config)?;
    log4rs::init_config(log_config).map_err(|e| {
        std::io::Error::new(ErrorKind::Other, e)
    })?;

    let lightclient = Arc::new(LightClient::new(seed, &config, latest_block_height)?);

    // Print startup Messages
    info!(""); // Blank line
    info!("Starting Zecwallet-CLI");
    info!("Light Client config {:?}", config);

    if print_updates {
        println!("Lightclient connecting to {}", config.server);
    }

    // Start the command loop
    let (command_tx, resp_rx) = command_loop(lightclient.clone());

    // At startup, run a sync.
    if first_sync {
        let update = lightclient.do_sync(true);
        if print_updates {
            println!("{}", update);
        }
    }

    Ok((command_tx, resp_rx))
}


fn start_interactive(command_tx: Sender<(String, Vec<String>)>, resp_rx: Receiver<String>) {
    // `()` can be used when no completer is required
    let mut rl = rustyline::Editor::<()>::new();

    println!("Ready!");

    let send_command = |cmd: String, args: Vec<String>| -> String {
        command_tx.send((cmd.clone(), args)).unwrap();
        match resp_rx.recv() {
            Ok(s) => s,
            Err(e) => {
                let e = format!("Error executing command {}: {}", cmd, e);
                eprintln!("{}", e);
                error!("{}", e);
                return "".to_string()
            }
        }
    };

    let info = &send_command("info".to_string(), vec![]);
    let chain_name = json::parse(info).unwrap()["chain_name"].as_str().unwrap().to_string();

    loop {
        // Read the height first
        let height = json::parse(&send_command("height".to_string(), vec![])).unwrap()["height"].as_i64().unwrap();

        let readline = rl.readline(&format!("({}) Block:{} (type 'help') >> ",
                                                    chain_name, height));
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

                println!("{}", send_command(cmd, args));

                // Special check for Quit command.
                if line == "quit" {
                    break;
                }
            },
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("CTRL-C");
                info!("CTRL-C");
                println!("{}", send_command("save".to_string(), vec![]));
                break
            },
            Err(rustyline::error::ReadlineError::Eof) => {
                println!("CTRL-D");
                info!("CTRL-D");
                println!("{}", send_command("save".to_string(), vec![]));
                break
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break
            }
        }
    }
}


fn command_loop(lightclient: Arc<LightClient>) -> (Sender<(String, Vec<String>)>, Receiver<String>) {
    let (command_tx, command_rx) = channel::<(String, Vec<String>)>();
    let (resp_tx, resp_rx) = channel::<String>();

    let lc = lightclient.clone();
    std::thread::spawn(move || {
        loop {
            match command_rx.recv_timeout(std::time::Duration::from_secs(5 * 60)) {
                Ok((cmd, args)) => {
                    let args = args.iter().map(|s| s.as_ref()).collect();

                    let cmd_response = commands::do_user_command(&cmd, &args, lc.as_ref());
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

    (command_tx, resp_rx)
}

fn attempt_recover_seed() {
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::{BufReader};
    use byteorder::{LittleEndian, ReadBytesExt,};
    use bip39::{Mnemonic, Language};

    // Create a Light Client Config in an attempt to recover the file.
    let config = LightClientConfig {
        server: "0.0.0.0:0".parse().unwrap(),
        chain_name: "main".to_string(),
        sapling_activation_height: 0,
        consensus_branch_id: "000000".to_string(),
        anchor_offset: 0,
        no_cert_verification: false,
    };

    let mut reader = BufReader::new(File::open(config.get_wallet_path()).unwrap());
    let version = reader.read_u64::<LittleEndian>().unwrap();
    println!("Reading wallet version {}", version);

    // Seed
    let mut seed_bytes = [0u8; 32];
    reader.read_exact(&mut seed_bytes).unwrap();

    let phrase = Mnemonic::from_entropy(&seed_bytes, Language::English,).unwrap().phrase().to_string();

    println!("Recovered seed phrase:\n{}", phrase);
}
