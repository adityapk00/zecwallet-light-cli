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
    let mut lightclient = LightClient::new();

    // At startup, read the wallet.dat 
    commands::do_user_command(&"read".to_string(), &mut lightclient);

    // `()` can be used when no completer is required
    let mut rl = Editor::<()>::new();
    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }
    loop {
        let readline = rl.readline(&format!("Block:{} (h for help) >> ", lightclient.last_scanned_height()));
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