mod lightclient;
mod lightwallet;
mod address;
mod prover;
mod commands;

use std::sync::Arc;
use std::time::Duration;
use lightclient::LightClient;

use rustyline::error::ReadlineError;
use rustyline::Editor;

pub mod grpc_client {
    include!(concat!(env!("OUT_DIR"), "/cash.z.wallet.sdk.rpc.rs"));
}



pub fn main() {
    use clap::{Arg, App};

    let matches = App::new("Light Client")
                    .version("1.0") 
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

    let server  = matches.value_of("server").map(|s| s.to_string());
    let seed    = matches.value_of("seed").map(|s| s.to_string());

    println!("Creating Light Wallet");

    let lightclient = match LightClient::new(seed, server) {
        Ok(lc) => Arc::new(lc),
        Err(e) => { eprintln!("Failed to start wallet. Error was:\n{}", e); return; }
    };

    // At startup, run a sync
    let sync_update = lightclient.do_sync();
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
                        break;
                    }
                },
                Err(_) => {
                    // Timeout. Do a sync to keep the wallet up-to-date
                    lc.do_sync();
                }
            }
        }
    });

    // `()` can be used when no completer is required
    let mut rl = Editor::<()>::new();
    let _ = rl.load_history("history.txt");

    println!("Ready!");

    loop {
        let readline = rl.readline(&format!("Block:{} (type 'help') >> ", lightclient.last_scanned_height()));
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
                    _ => { eprintln!("Error receiveing response");}
                }

                // Special check for Quit command.
                if line == "quit" {
                    break;
                }
            },
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                println!("{}", lightclient.do_save());
                break
            },
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                println!("{}", lightclient.do_save());
                break
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break
            }
        }
    }
    rl.save_history("history.txt").unwrap();
}