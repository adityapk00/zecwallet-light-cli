mod lightclient;
mod lightwallet;
mod address;
mod prover;
mod commands;

use std::sync::Arc;

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
                    .get_matches();

    let seed: Option<String> = matches.value_of("seed").map(|s| s.to_string());

    let lightclient = match LightClient::new(seed) {
        Ok(lc) => Arc::new(lc),
        Err(e) => { eprintln!("Failed to start wallet. Error was:\n{}", e); return; }
    };

    let (command_tx, command_rx) = std::sync::mpsc::channel::<(String, Vec<String>)>();
    let (resp_tx, resp_rx) = std::sync::mpsc::channel::<String>();

    let lc = lightclient.clone();
    std::thread::spawn(move || {
        println!("Starting Light Client");
        
        loop {
            match command_rx.recv() {
                Ok((cmd, args)) => {
                    let args = args.iter().map(|s| s.as_ref()).collect();
                    let cmd_response = commands::do_user_command(&cmd, &args, &lc);
                    resp_tx.send(cmd_response).unwrap();

                    if cmd == "quit" {
                        break;
                    }
                },
                _ => {}
            }
        }

        println!("finished running");
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
                // commands::do_user_command(&cmd, &args, &mut lightclient);
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
                lightclient.do_save();
                break
            },
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                lightclient.do_save();
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