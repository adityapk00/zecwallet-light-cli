use std::io::{self};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use log::{error, info};

use zecwalletlitelib::lightclient::lightclient_config::LightClientConfig;
use zecwalletlitelib::{commands, lightclient::LightClient};

pub mod version;

#[macro_export]
macro_rules! configure_clapapp {
    ( $freshapp: expr ) => {
    $freshapp.version(VERSION)
            .arg(Arg::with_name("nosync")
                .help("By default, zecwallet-cli will sync the wallet at startup. Pass --nosync to prevent the automatic sync at startup.")
                .long("nosync")
                .short("n")
                .takes_value(false))
            .arg(Arg::with_name("recover")
                .long("recover")
                .help("Attempt to recover the seed from the wallet")
                .takes_value(false))
            .arg(Arg::with_name("password")
                .long("password")
                .help("When recovering seed, specify a password for the encrypted wallet")
                .takes_value(true))
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
                .default_value(lightclient::lightclient_config::DEFAULT_SERVER))
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
    let user = std::env::var("USER").expect("Unexpected error reading value of $USER!");
    let home = std::env::var("HOME").expect("Unexpected error reading value of $HOME!");
    let current_executable = std::env::current_exe().expect("Unexpected error reporting executable path!");
    eprintln!("USER: {}", user);
    eprintln!("HOME: {}", home);
    eprintln!("Executable: {}", current_executable.display());
    if home == "/" {
        eprintln!("User {} must have permission to write to '{}.zcash/' .", user, home);
    } else {
        eprintln!("User {} must have permission to write to '{}/.zcash/' .", user, home);
    }
}

pub fn startup(
    server: http::Uri,
    seed: Option<String>,
    birthday: u64,
    first_sync: bool,
    print_updates: bool,
) -> io::Result<(Sender<(String, Vec<String>)>, Receiver<String>)> {
    // Try to get the configuration
    let (config, latest_block_height) = LightClientConfig::create(server.clone())?;

    let lightclient = match seed {
        Some(phrase) => Arc::new(LightClient::new_from_phrase(phrase, &config, birthday, false)?),
        None => {
            if config.wallet_exists() {
                Arc::new(LightClient::read_from_disk(&config)?)
            } else {
                println!("Creating a new wallet");
                Arc::new(LightClient::new(&config, latest_block_height)?)
            }
        }
    };

    // Initialize logging
    lightclient.init_logging()?;

    // Print startup Messages
    info!(""); // Blank line
    info!("Starting Zecwallet-CLI");
    info!("Light Client config {:?}", config);

    if print_updates {
        println!("Lightclient connecting to {}", config.server);
    }

    // At startup, run a sync.
    if first_sync {
        let update = commands::do_user_command("sync", &vec![], lightclient.as_ref());
        if print_updates {
            println!("{}", update);
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
                return "".to_string();
            }
        }
    };

    let info = send_command("info".to_string(), vec![]);
    let chain_name = json::parse(&info).unwrap()["chain_name"].as_str().unwrap().to_string();

    loop {
        // Read the height first
        let height = json::parse(&send_command("height".to_string(), vec!["false".to_string()])).unwrap()["height"]
            .as_i64()
            .unwrap();

        let readline = rl.readline(&format!("({}) Block:{} (type 'help') >> ", chain_name, height));
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                // Parse command line arguments
                let mut cmd_args = match shellwords::split(&line) {
                    Ok(args) => args,
                    Err(_) => {
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
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("CTRL-C");
                info!("CTRL-C");
                println!("{}", send_command("save".to_string(), vec![]));
                break;
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                println!("CTRL-D");
                info!("CTRL-D");
                println!("{}", send_command("save".to_string(), vec![]));
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
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
                }
                Err(_) => {
                    // Timeout. Do a sync to keep the wallet up-to-date. False to whether to print updates on the console
                    info!("Timeout, doing a sync");
                    commands::do_user_command("sync", &vec![], lc.as_ref());
                }
            }
        }
    });

    (command_tx, resp_rx)
}

pub fn attempt_recover_seed(_password: Option<String>) {
    // Create a Light Client Config in an attempt to recover the file.
    let _config = LightClientConfig {
        server: "0.0.0.0:0".parse().unwrap(),
        chain_name: "main".to_string(),
        sapling_activation_height: 0,
        anchor_offset: 0,
        data_dir: None,
    };

    // match LightClient::attempt_recover_seed(&config, password) {
    //     Ok(seed) => {
    //         println!("Recovered seed: '{}'", seed);
    //         println!("Do you want to use this seed to re-create a new wallet?");

    //         let mut rl = rustyline::Editor::<()>::new();
    //         match rl.readline("(Y / N): ") {
    //             Ok(response) => {
    //                 if response.to_ascii_uppercase() == "Y" {
    //                     match attempt_save_recovered(&config, seed) {
    //                         Ok(backup_path) => {
    //                             eprintln!("Backed up existing wallet to {}", backup_path);
    //                             eprintln!("Saved a new wallet. Please start Zecwallet Lite to rescan your wallet.");
    //                         }
    //                         Err(e) => {
    //                             eprintln!("Failed to save recovered seed. Error: {}", e)
    //                         }
    //                     };
    //                 } else {
    //                     println!("Leaving wallet unchanged");
    //                 }
    //             }
    //             Err(_) => {
    //                 println!("Leaving wallet unchanged");
    //             }
    //         }
    //     }
    //     Err(e) => eprintln!("Failed to recover seed. Error: {}", e),
    // };
}

// fn attempt_save_recovered(config: &LightClientConfig, seed: String) -> Result<String, String> {
//     let backup_path = config.backup_existing_wallet()?;
//     let lightclient = LightClient::new_from_phrase(seed, &config, 0, true).map_err(|e| format!("{}", e))?;

//     lightclient.do_save()?;

//     Ok(backup_path)
// }
