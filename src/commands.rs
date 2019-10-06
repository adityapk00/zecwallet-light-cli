use std::collections::HashMap;

use crate::LightClient;

pub trait Command {
    fn help(&self) -> String;

    fn short_help(&self) -> String;

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String;
}

struct SyncCommand {}
impl Command for SyncCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Sync the light client with the server");
        h.push("Usage:");
        h.push("sync");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Download CompactBlocks and sync to the server".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_sync(true)
    }
}

struct RescanCommand {}
impl Command for RescanCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Rescan the wallet, rescanning all blocks for new transactions");
        h.push("Usage:");
        h.push("rescan");
        h.push("");
        h.push("This command will download all blocks since the intial block again from the light client server");
        h.push("and attempt to scan each block for transactions belonging to the wallet.");

        h.join("\n")
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
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("List all available commands");
        h.push("Usage:");
        h.push("help [command_name]");
        h.push("");
        h.push("If no \"command_name\" is specified, a list of all available commands is returned");
        h.push("Example:");
        h.push("help send");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Lists all available commands".to_string()
    }

    fn exec(&self, args: &[&str], _: &LightClient) -> String {
        let mut responses = vec![];

        // Print a list of all commands
        match args.len() {
            0 => {
                responses.push(format!("Available commands:"));
                get_commands().iter().for_each(| (cmd, obj) | {
                    responses.push(format!("{} - {}", cmd, obj.short_help()));
                });

                responses.join("\n")
            },
            1 => {
                match get_commands().get(args[0]) {
                    Some(cmd) => cmd.help(),
                    None => format!("Command {} not found", args[0])
                }
            },
            _ => self.help()
        }
    }
}

struct InfoCommand {}
impl Command for InfoCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Get info about the lightwalletd we're connected to");
        h.push("Usage:");
        h.push("info");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Get the lightwalletd server's info".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_sync(true);
        
        LightClient::do_info(lightclient.get_server_uri())
    }
}

struct BalanceCommand {}
impl Command for BalanceCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Show the current TAZ balance in the wallet");
        h.push("Usage:");
        h.push("balance");
        h.push("");
        h.push("Transparent and Shielded balances, along with the addresses they belong to are displayed");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Show the current TAZ balance in the wallet".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_sync(true);
        
        format!("{}", lightclient.do_balance().pretty(2))
    }
}


struct AddressCommand {}
impl Command for AddressCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("List current addresses in the wallet");
        h.push("Usage:");
        h.push("address");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "List all addresses in the wallet".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        format!("{}", lightclient.do_address().pretty(2))
    }
}

struct ExportCommand {}
impl Command for ExportCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Export private key for an individual wallet addresses.");
        h.push("Note: To backup the whole wallet, use the 'seed' command insted");
        h.push("Usage:");
        h.push("export [t-address or z-address]");
        h.push("");
        h.push("If no address is passed, private key for all addresses in the wallet are exported.");
        h.push("");
        h.push("Example:");
        h.push("export ztestsapling1x65nq4dgp0qfywgxcwk9n0fvm4fysmapgr2q00p85ju252h6l7mmxu2jg9cqqhtvzd69jwhgv8d");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Export private key for wallet addresses".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() > 1 {
            return self.help();
        }

        let address = if args.is_empty() { None } else { Some(args[0].to_string()) };

        format!("{}", lightclient.do_export(address).pretty(2))
    }
}


struct SendCommand {}
impl Command for SendCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Send TAZ to a given address");
        h.push("Usage:");
        h.push("send <address> <amount in tazoshis> \"optional_memo\"");
        h.push("");
        h.push("Example:");
        h.push("send ztestsapling1x65nq4dgp0qfywgxcwk9n0fvm4fysmapgr2q00p85ju252h6l7mmxu2jg9cqqhtvzd69jwhgv8d 200000 \"Hello from the command line\"");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Send TAZ to the given address".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        // Parse the args. 
        // 1 - Destination address. T or Z address
        if args.len() < 2 || args.len() > 3 {
            return self.help();
        }

        // Make sure we can parse the amount
        let value = match args[1].parse::<u64>() {
            Ok(amt) => amt,
            Err(e)  => {
                return format!("Couldn't parse amount: {}", e);;
            }
        };

        let memo = if args.len() == 3 { Some(args[2].to_string()) } else {None};
        
        lightclient.do_sync(true);

        lightclient.do_send(args[0], value, memo)
    }
}

struct SaveCommand {}
impl Command for SaveCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Save the wallet to disk");
        h.push("Usage:");
        h.push("save");
        h.push("");
        h.push("The wallet is saved to disk. The wallet is periodically saved to disk (and also saved upon exit)");
        h.push("but you can use this command to explicitly save it to disk");

        h.join("\n")
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
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Show the wallet's seed phrase");
        h.push("Usage:");
        h.push("seed");
        h.push("");
        h.push("Your wallet is entirely recoverable from the seed phrase. Please save it carefully and don't share it with anyone");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Display the seed phrase".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        format!("{}", lightclient.do_seed_phrase().pretty(2))
    }
}

struct TransactionsCommand {}
impl Command for TransactionsCommand {
    fn help(&self)  -> String {
        let mut h = vec![];
        h.push("List all incoming and outgoing transactions from this wallet");
        h.push("Usage:");
        h.push("list");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "List all transactions in the wallet".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_sync(true);

        format!("{}", lightclient.do_list_transactions().pretty(2))
    }
}

struct NewAddressCommand {}
impl Command for NewAddressCommand {
    fn help(&self)  -> String {
        let mut h = vec![];
        h.push("Create a new address in this wallet");
        h.push("Usage:");
        h.push("new [z | t]");
        h.push("");
        h.push("Example:");
        h.push("To create a new z address:");
        h.push("new z");
        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Create a new address in this wallet".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() != 1 {
            return format!("No address type specified\n{}", self.help());
        }

        format!("{}", lightclient.do_new_address(args[0]).pretty(2))
    }
}

struct NotesCommand {}
impl Command for NotesCommand {
    fn help(&self)  -> String {
        let mut h = vec![];
        h.push("Show all sapling notes and utxos in this wallet");
        h.push("Usage:");
        h.push("notes [all]");
        h.push("");
        h.push("If you supply the \"all\" parameter, all previously spent sapling notes and spent utxos are also included");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "List all sapling notes and utxos in the wallet".to_string()
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
                a     => return format!("Invalid argument \"{}\". Specify 'all' to include unspent notes", a)
            }
        } else {
            false
        };

        lightclient.do_sync(true);
        
        format!("{}", lightclient.do_list_notes(all_notes).pretty(2))
    }
}


struct QuitCommand {}
impl Command for QuitCommand {
    fn help(&self)  -> String {
        let mut h = vec![];
        h.push("Save the wallet to disk and quit");
        h.push("Usage:");
        h.push("quit");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Quit the lightwallet, saving state to disk".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        lightclient.do_save()
    }
}

pub fn get_commands() -> Box<HashMap<String, Box<dyn Command>>> {
    let mut map: HashMap<String, Box<dyn Command>> = HashMap::new();

    map.insert("sync".to_string(),      Box::new(SyncCommand{}));
    map.insert("rescan".to_string(),    Box::new(RescanCommand{}));
    map.insert("help".to_string(),      Box::new(HelpCommand{}));
    map.insert("balance".to_string(),   Box::new(BalanceCommand{}));
    map.insert("addresses".to_string(), Box::new(AddressCommand{}));
    map.insert("export".to_string(),    Box::new(ExportCommand{}));
    map.insert("info".to_string(),      Box::new(InfoCommand{}));
    map.insert("send".to_string(),      Box::new(SendCommand{}));
    map.insert("save".to_string(),      Box::new(SaveCommand{}));
    map.insert("quit".to_string(),      Box::new(QuitCommand{}));
    map.insert("list".to_string(),      Box::new(TransactionsCommand{}));
    map.insert("notes".to_string(),     Box::new(NotesCommand{}));
    map.insert("new".to_string(),       Box::new(NewAddressCommand{}));
    map.insert("seed".to_string(),      Box::new(SeedCommand{}));

    Box::new(map)
}

pub fn do_user_command(cmd: &str, args: &Vec<&str>, lightclient: &LightClient) -> String {
    match get_commands().get(cmd) {
        Some(cmd) => cmd.exec(args, lightclient),
        None      => format!("Unknown command : {}. Type 'help' for a list of commands", cmd)
    }
}
