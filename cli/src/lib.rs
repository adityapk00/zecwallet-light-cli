use std::io::{self, Error, ErrorKind};
use std::sync::Arc;
use std::sync::mpsc::{channel, Sender, Receiver};

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


use zecwalletlitelib::{commands,
    lightclient::{LightClient, LightClientConfig},
};

#[macro_export]
macro_rules! configure_clapapp {
    ( $freshapp: expr ) => {
    $freshapp.version("1.0.0")
            .arg(Arg::with_name("dangerous")
                .long("dangerous")
                .help("Disable server TLS certificate verification. Use this if you're running a local lightwalletd with a self-signed certificate. WARNING: This is dangerous, don't use it with a server that is not your own.")
                .takes_value(false))
            .arg(Arg::with_name("nosync")
                .help("By default, zecwallet-cli will sync the wallet at startup. Pass --nosync to prevent the automatic sync at startup.")
                .long("nosync")
                .short("n")
                .takes_value(false))
            .arg(Arg::with_name("recover")
                .long("recover")
                .help("Attempt to recover the seed from the wallet")
                .takes_value(false))
            .arg(Arg::with_name("seed")
                .short("s")
                .long("seed")
                .value_name("seed_phrase")
                .help("Create a new wallet with the given 24-word seed phrase. Will fail if wallet already exists")
                .takes_value(true))
            .arg(Arg::with_name("birthday")
                .long("birthday")
                .value_name("birthday")
                .help("Specify wallet birthday when restoring from seed. This is the earlist block height where the wallet has a transaction.")
                .takes_value(true))
            .arg(Arg::with_name("server")
                .long("server")
                .value_name("server")
                .help("Lightwalletd server to connect to.")
                .takes_value(true)
                .default_value(lightclient::DEFAULT_SERVER))
            .arg(Arg::with_name("COMMAND")
                .help("Command to execute. If a command is not specified, zecwallet-cli will start in interactive mode.")
                .required(false)
                .index(1))
            .arg(Arg::with_name("PARAMS")
                .help("Params to execute command with. Run the 'help' command to get usage help.")
                .required(false)
                .multiple(true))
    };
}

/// This function is only tested against Linux.
pub fn report_permission_error() {
    let user = std::env::var("USER").expect(
        "Unexpected error reading value of $USER!");
    let home = std::env::var("HOME").expect(
        "Unexpected error reading value of $HOME!");
    let current_executable = std::env::current_exe()
        .expect("Unexpected error reporting executable path!");
    eprintln!("USER: {}", user);
    eprintln!("HOME: {}", home);
    eprintln!("Executable: {}", current_executable.display());
    if home == "/" {
        eprintln!("User {} must have permission to write to '{}.zcash/' .",
                  user,
                  home);
    } else {
        eprintln!("User {} must have permission to write to '{}/.zcash/' .",
                  user,
                  home);
    }
}

/// Build the Logging config
pub fn get_log_config(config: &LightClientConfig) -> io::Result<Config> {
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


pub fn startup(server: http::Uri, dangerous: bool, seed: Option<String>, birthday: u64, first_sync: bool, print_updates: bool)
        -> io::Result<(Sender<(String, Vec<String>)>, Receiver<String>)> {
    // Try to get the configuration
    let (config, latest_block_height) = LightClientConfig::create(server.clone(), dangerous)?;

    // Configure logging first.
    let log_config = get_log_config(&config)?;
    log4rs::init_config(log_config).map_err(|e| {
        std::io::Error::new(ErrorKind::Other, e)
    })?;

    let lightclient = match seed {
        Some(phrase) => Arc::new(LightClient::new_from_phrase(phrase, &config, birthday)?),
        None => {
            if config.wallet_exists() {
                Arc::new(LightClient::read_from_disk(&config)?)
            } else {
                println!("Creating a new wallet");
                Arc::new(LightClient::new(&config, latest_block_height)?)
            }
        }
    };

    // Print startup Messages
    info!(""); // Blank line
    info!("Starting Zecwallet-CLI");
    info!("Light Client config {:?}", config);

    if print_updates {
        println!("Lightclient connecting to {}", config.server);
    }

    // At startup, run a sync.
    if first_sync {
        let update = lightclient.do_sync(true);
        if print_updates {
            match update {
                Ok(j) => {
                    println!("{}", j.pretty(2));
                },
                Err(e) => println!("{}", e)
            }
        }
    }

    // Start the command loop
    let (command_tx, resp_rx) = command_loop(lightclient.clone());

    Ok((command_tx, resp_rx))
}

pub fn start_interactive(command_tx: Sender<(String, Vec<String>)>, resp_rx: Receiver<String>) {
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


pub fn command_loop(lightclient: Arc<LightClient>) -> (Sender<(String, Vec<String>)>, Receiver<String>) {
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
                    match lc.do_sync(false) {
                        Ok(_) => {},
                        Err(e) => {error!("{}", e)}
                    }
                }
            }
        }
    });

    (command_tx, resp_rx)
}

pub fn attempt_recover_seed() {
    // Create a Light Client Config in an attempt to recover the file.
    let config = LightClientConfig {
        server: "0.0.0.0:0".parse().unwrap(),
        chain_name: "main".to_string(),
        sapling_activation_height: 0,
        consensus_branch_id: "000000".to_string(),
        anchor_offset: 0,
        no_cert_verification: false,
        data_dir: None,
    };

    match LightClient::attempt_recover_seed(&config) {
        Ok(seed) => println!("Recovered seed: '{}'", seed),
        Err(e)   => eprintln!("Failed to recover seed. Error: {}", e)
    };
}
