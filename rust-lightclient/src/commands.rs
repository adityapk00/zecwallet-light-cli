use std::collections::HashMap;

use crate::LightClient;

pub trait Command {
    fn help(&self);

    fn short_help(&self) -> String;

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String;
}

struct SyncCommand {}
impl Command for SyncCommand {
    fn help(&self) {
        println!("Type sync for syncing");
    }

    fn short_help(&self) -> String {
        "Download CompactBlocks and sync to the server".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_sync()
    }
}

struct RescanCommand {}
impl Command for RescanCommand {
    fn help(&self) {
        println!("Rescan the wallet from it's initial state, rescanning and downloading all blocks and transactions.");
    }

    fn short_help(&self) -> String {
        "Rescan the wallet, downloading and scanning all blocks and transactions".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_rescan()
    }
}


struct HelpCommand {}
impl Command for HelpCommand {
    fn help(&self) {
        println!("Lists all available commands");
    }

    fn short_help(&self) -> String {
        "Lists all available commands".to_string()
    }

    fn exec(&self, _args: &[&str], _: &LightClient) -> String {
        let mut responses = vec![];
        // Print a list of all commands
        responses.push(format!("Available commands:"));
        get_commands().iter().for_each(| (cmd, obj) | {
            responses.push(format!("{} - {}", cmd, obj.short_help()));
        });

        responses.join("\n")
    }
}

struct InfoCommand {}
impl Command for InfoCommand {
    fn help(&self) {
        println!("Gets server info");
    }

    fn short_help(&self) -> String {
        "Get the lightwalletd server's info".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_sync();
        lightclient.do_info()
    }
}

struct AddressCommand {}
impl Command for AddressCommand {
    fn help(&self) {
        println!("Show my addresses");
    }

    fn short_help(&self) -> String {
        "List all current addresses".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {        
        lightclient.do_sync();
        
        format!("{}", lightclient.do_address().pretty(2))
    }
}

struct SendCommand {}
impl Command for SendCommand {
    fn help(&self) {
        println!("Sends ZEC to an address");
        println!("Usage:");
        println!("send recipient_address value memo");
    }

    fn short_help(&self) -> String {
        "Send ZEC to the given address".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        // Parse the args. 
        // 1 - Destination address. T or Z address
        if args.len() < 2 || args.len() > 3 {
            return self.short_help();
        }

        // Make sure we can parse the amount
        let value = match args[1].parse::<u64>() {
            Ok(amt) => amt,
            Err(e)  => {
                return format!("Couldn't parse amount: {}", e);;
            }
        };

        let memo = if args.len() == 3 { Some(args[2].to_string()) } else {None};
        
        lightclient.do_sync();

        lightclient.do_send(args[0], value, memo)
    }
}

struct SaveCommand {}
impl Command for SaveCommand {
    fn help(&self) {
        println!("Save wallet to disk");
    }

    fn short_help(&self) -> String {
        "Save wallet file to disk".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_save()
    }
}

struct SeedCommand {}
impl Command for SeedCommand {
    fn help(&self) {
        println!("Show the seed phrase for the wallet");
    }

    fn short_help(&self) -> String {
        "Display the seed phrase".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_seed_phrase()
    }
}

struct TransactionsCommand {}
impl Command for TransactionsCommand {
    fn help(&self) {
        println!("Show transactions");
    }

    fn short_help(&self) -> String {
        "List all transactions in the wallet".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_sync();

        format!("{}", lightclient.do_list_transactions().pretty(2))
    }
}


struct NotesCommand {}
impl Command for NotesCommand {
    fn help(&self) {
        println!("Show Notes");
    }

    fn short_help(&self) -> String {
        "List all sapling notes in the wallet".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        // Parse the args. 
        if args.len() > 1 {
            return self.short_help();
        }

        // Make sure we can parse the amount
        let all_notes = if args.len() == 1 {
            match args[0] {
                "all" => true,
                _     => return "Invalid argument. Specify 'all' to include unspent notes".to_string()
            }
        } else {
            false
        };

        lightclient.do_sync();
        
        format!("{}", lightclient.do_list_notes(all_notes).pretty(2))
    }
}


struct QuitCommand {}
impl Command for QuitCommand {
        fn help(&self) {
        println!("Quit");
    }

    fn short_help(&self) -> String {
        "Quit the lightwallet, saving state to disk".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_save()
    }
}

// TODO: Add rescan command
// TODO: Add consolidate command to consolidate t inputs

pub fn get_commands() -> Box<HashMap<String, Box<dyn Command>>> {
    let mut map: HashMap<String, Box<dyn Command>> = HashMap::new();

    map.insert("sync".to_string(),      Box::new(SyncCommand{}));
    map.insert("rescan".to_string(),    Box::new(RescanCommand{}));
    map.insert("help".to_string(),      Box::new(HelpCommand{}));
    map.insert("address".to_string(),   Box::new(AddressCommand{}));
    map.insert("info".to_string(),      Box::new(InfoCommand{}));
    map.insert("send".to_string(),      Box::new(SendCommand{}));
    map.insert("save".to_string(),      Box::new(SaveCommand{}));
    map.insert("quit".to_string(),      Box::new(QuitCommand{}));
    map.insert("list".to_string(),      Box::new(TransactionsCommand{}));
    map.insert("notes".to_string(),     Box::new(NotesCommand{}));
    map.insert("seed".to_string(),      Box::new(SeedCommand{}));

    Box::new(map)
}

pub fn do_user_command(cmd: &str, args: &Vec<&str>, lightclient: &LightClient) -> String {
    match get_commands().get(cmd) {
        Some(cmd) => cmd.exec(args, lightclient),
        None      => format!("Unknown command : {}. Type 'help' for a list of commands", cmd)
    }
}
