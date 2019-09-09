mod lightclient;
mod lightwallet;
mod address;
mod prover;
mod commands;

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

    let mut lightclient = match LightClient::new(matches.value_of("seed")) {
        Ok(lc) => lc,
        Err(e) => { 
            eprintln!("Failed to start wallet. Error was:\n{}", e);
            return;
        }
    };

    println!("Starting Light Client");

    // `()` can be used when no completer is required
    let mut rl = Editor::<()>::new();
    let _ = rl.load_history("history.txt");

    println!("Ready!");

    loop {
        let readline = rl.readline(&format!("Block:{} (type 'help') >> ", lightclient.last_scanned_height()));
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                commands::do_user_command(&line, &mut lightclient);

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