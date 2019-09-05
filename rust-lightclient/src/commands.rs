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

pub fn get_commands() -> Box<HashMap<String, Box<dyn Command>>> {
    let mut map: HashMap<String, Box<dyn Command>> = HashMap::new();

    map.insert("sync".to_string(),      Box::new(SyncCommand{}));
    map.insert("help".to_string(),      Box::new(HelpCommand{}));
    map.insert("address".to_string(),   Box::new(AddressCommand{}));

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