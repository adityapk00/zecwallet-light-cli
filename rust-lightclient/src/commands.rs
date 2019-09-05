use std::collections::HashMap;

use crate::LightClient;

pub trait Command {
    fn help(&self);

    fn short_help(&self) -> String;

    fn exec(&self, args: &[String], lightclient: &LightClient);
}

struct SyncCommand {}

impl Command for SyncCommand {
    fn help(&self) {
        println!("Type sync for syncing");
    }

    fn short_help(&self) -> String {
        "Download CompactBlocks and sync to the server".to_string()
    }

    fn exec(&self, args: &[String], lightclient: &LightClient) {
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

    fn exec(&self, args: &[String], _: &LightClient) {
        // Print a list of all commands
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

    fn exec(&self, args: &[String], lightclient: &LightClient) {
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

    fn exec(&self, args: &[String], lightclient: &LightClient) {
        lightclient.do_address();
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

    fn exec(&self, args: &[String], lightclient: &LightClient) {
        lightclient.do_send(
            "ztestsapling1x65nq4dgp0qfywgxcwk9n0fvm4fysmapgr2q00p85ju252h6l7mmxu2jg9cqqhtvzd69jwhgv8d".to_string(), 
            1500000, 
            Some("Hello from the command".to_string()));
    }
}

pub fn get_commands() -> Box<HashMap<String, Box<dyn Command>>> {
    let mut map: HashMap<String, Box<dyn Command>> = HashMap::new();

    map.insert("sync".to_string(),      Box::new(SyncCommand{}));
    map.insert("help".to_string(),      Box::new(HelpCommand{}));
    map.insert("address".to_string(),   Box::new(AddressCommand{}));
    map.insert("info".to_string(),      Box::new(InfoCommand{}));
    map.insert("send".to_string(),      Box::new(SendCommand{}));

    Box::new(map)
}

pub fn do_user_command(cmd: String, lightclient: &LightClient) {
    match get_commands().get(&cmd) {
        Some(cmd) => cmd.exec(&[], lightclient),
        None      => {
            println!("Unknown command : {}. Type 'help' for a list of commands", cmd);
        }
    }
}
