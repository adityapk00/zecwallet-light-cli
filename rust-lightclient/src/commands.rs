use std::collections::HashMap;

use crate::LightClient;

pub trait Command {
    fn help(&self);

    fn short_help(&self) -> String;

    fn exec(&self, _args: &[String], lightclient: &mut LightClient);
}

struct SyncCommand {}

impl Command for SyncCommand {
    fn help(&self) {
        println!("Type sync for syncing");
    }

    fn short_help(&self) -> String {
        "Download CompactBlocks and sync to the server".to_string()
    }

    fn exec(&self, _args: &[String], lightclient: &mut LightClient) {
        lightclient.do_sync();
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

    fn exec(&self, _args: &[String], _: &mut LightClient) {
        // Print a list of all commands
        println!("Available commands:");
        get_commands().iter().for_each(| (cmd, obj) | {
            println!("{} - {}", cmd, obj.short_help());
        });
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

    fn exec(&self, _args: &[String], lightclient: &mut LightClient) {
        lightclient.do_info();
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

    fn exec(&self, _args: &[String], lightclient: &mut LightClient) {
        let res = lightclient.do_address();
        println!("{}", res.pretty(2));
    }
}

struct SendCommand {}
impl Command for SendCommand {
    fn help(&self) {
        println!("Send ZEC");
    }

    fn short_help(&self) -> String {
        "Send ZEC to the given address".to_string()
    }

    fn exec(&self, _args: &[String], lightclient: &mut LightClient) {
        lightclient.do_send(
            "ztestsapling1x65nq4dgp0qfywgxcwk9n0fvm4fysmapgr2q00p85ju252h6l7mmxu2jg9cqqhtvzd69jwhgv8d".to_string(), 
            150000, 
            Some("Hello from the command".to_string()));
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

    fn exec(&self, _args: &[String], lightclient: &mut LightClient) {
        lightclient.do_save();
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

    fn exec(&self, _args: &[String], lightclient: &mut LightClient) {
        let phrase = lightclient.do_seed_phrase();

        println!("PLEASE SAVE YOUR SEED PHRASE CAREFULLY AND DO NOT SHARE IT");
        println!();
        println!("{}", phrase);
        println!();
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

    fn exec(&self, _args: &[String], lightclient: &mut LightClient) {
        let txns = lightclient.do_list_transactions();
        println!("{}", txns.pretty(2));
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

    fn exec(&self, _args: &[String], lightclient: &mut LightClient) {
        lightclient.do_save();
    }
}


pub fn get_commands() -> Box<HashMap<String, Box<dyn Command>>> {
    let mut map: HashMap<String, Box<dyn Command>> = HashMap::new();

    map.insert("sync".to_string(),      Box::new(SyncCommand{}));
    map.insert("help".to_string(),      Box::new(HelpCommand{}));
    map.insert("address".to_string(),   Box::new(AddressCommand{}));
    map.insert("info".to_string(),      Box::new(InfoCommand{}));
    map.insert("send".to_string(),      Box::new(SendCommand{}));
    map.insert("save".to_string(),      Box::new(SaveCommand{}));
    map.insert("quit".to_string(),      Box::new(QuitCommand{}));
    map.insert("list".to_string(),      Box::new(TransactionsCommand{}));
    map.insert("seed".to_string(),      Box::new(SeedCommand{}));

    Box::new(map)
}

pub fn do_user_command(cmd: &String, lightclient: &mut LightClient) {
    match get_commands().get(cmd) {
        Some(cmd) => cmd.exec(&[], lightclient),
        None      => {
            println!("Unknown command : {}. Type 'help' for a list of commands", cmd);
        }
    }
}
