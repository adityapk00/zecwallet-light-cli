use crate::lightwallet::keys::Keys;
use crate::{lightclient::LightClient, lightwallet::utils};
use json::object;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::convert::TryInto;
use tokio::runtime::Runtime;
use zcash_primitives::transaction::components::amount::DEFAULT_FEE;

lazy_static! {
    static ref RT: Runtime = tokio::runtime::Runtime::new().unwrap();
}

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
        RT.block_on(async move {
            match lightclient.do_sync(true).await {
                Ok(j) => j.pretty(2),
                Err(e) => e,
            }
        })
    }
}

struct EncryptionStatusCommand {}
impl Command for EncryptionStatusCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Check if the wallet is encrypted and if it is locked");
        h.push("Usage:");
        h.push("encryptionstatus");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Check if the wallet is encrypted and if it is locked".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        RT.block_on(async move { lightclient.do_encryption_status().await.pretty(2) })
    }
}

struct SyncStatusCommand {}
impl Command for SyncStatusCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Get the sync status of the wallet");
        h.push("Usage:");
        h.push("syncstatus");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Get the sync status of the wallet".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        RT.block_on(async move {
            let status = lightclient.do_sync_status().await;

            let o = if status.in_progress {
                object! {
                    "sync_id" => status.sync_id,
                    "in_progress" => status.in_progress,
                    "last_error" => status.last_error,
                    "start_block" => status.start_block,
                    "end_block" => status.end_block,
                    "witness_blocks" => status.blocks_tree_done,
                    "synced_blocks" => status.blocks_done,
                    "trial_decryptions_blocks" => status.trial_dec_done,
                    "txn_scan_blocks" => status.txn_scan_done,
                    "total_blocks" => status.blocks_total,
                    "batch_num" => status.batch_num,
                    "batch_total" => status.batch_total
                }
            } else {
                object! {
                    "sync_id" => status.sync_id,
                    "in_prorgess" => status.in_progress,
                    "last_error" => status.last_error,
                }
            };
            o.pretty(2)
        })
    }
}

struct VerifyCommand {}
impl Command for VerifyCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Verify the current blocks from the latest checkpoint.");
        h.push("Usage:");
        h.push("verify");
        h.push("");
        h.push("This command will download all blocks since the last checkpoint and make sure we have the currect block at the tip.");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Verify from the latest checkpoint".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        RT.block_on(async move {
            match lightclient.do_verify_from_last_checkpoint().await {
                Ok(v) => {
                    let j = object! { "result" => v };
                    j.pretty(2)
                }
                Err(e) => e,
            }
        })
    }
}

struct SendProgressCommand {}
impl Command for SendProgressCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Get the progress of any send transactions that are currently computing");
        h.push("Usage:");
        h.push("sendprogress");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Get the progress of any send transactions that are currently computing".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        RT.block_on(async move {
            match lightclient.do_send_progress().await {
                Ok(j) => j.pretty(2),
                Err(e) => e,
            }
        })
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
        RT.block_on(async move {
            match lightclient.do_rescan().await {
                Ok(j) => j.pretty(2),
                Err(e) => e,
            }
        })
    }
}

struct ClearCommand {}
impl Command for ClearCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Clear the wallet state, rolling back the wallet to an empty state.");
        h.push("Usage:");
        h.push("clear");
        h.push("");
        h.push("This command will clear all notes, utxos and transactions from the wallet, setting up the wallet to be synced from scratch.");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Clear the wallet state, rolling back the wallet to an empty state.".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        RT.block_on(async move {
            lightclient.clear_state().await;

            let result = object! { "result" => "success" };
            result.pretty(2)
        })
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
                get_commands().iter().for_each(|(cmd, obj)| {
                    responses.push(format!("{} - {}", cmd, obj.short_help()));
                });

                responses.join("\n")
            }
            1 => match get_commands().get(args[0]) {
                Some(cmd) => cmd.help(),
                None => format!("Command {} not found", args[0]),
            },
            _ => self.help(),
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
        RT.block_on(async move { lightclient.do_info().await })
    }
}

struct ZecPriceCommand {}
impl Command for ZecPriceCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Get the latest ZEC price in the wallet's currency (USD)");
        h.push("Usage:");
        h.push("zecprice");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Get the latest ZEC price in the wallet's currency (USD)".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        RT.block_on(async move { lightclient.do_zec_price().await })
    }
}

struct LastTxIdCommand {}
impl Command for LastTxIdCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Show the latest TxId in the wallet");
        h.push("Usage:");
        h.push("lasttxid");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Show the latest TxId in the wallet".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        RT.block_on(async move { format!("{}", lightclient.do_last_txid().await.pretty(2)) })
    }
}

struct BalanceCommand {}
impl Command for BalanceCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Show the current ZEC balance in the wallet");
        h.push("Usage:");
        h.push("balance");
        h.push("");
        h.push("Transparent and Shielded balances, along with the addresses they belong to are displayed");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Show the current ZEC balance in the wallet".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        RT.block_on(async move { format!("{}", lightclient.do_balance().await.pretty(2)) })
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
        RT.block_on(async move { format!("{}", lightclient.do_address().await.pretty(2)) })
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

        RT.block_on(async move {
            let address = if args.is_empty() {
                None
            } else {
                Some(args[0].to_string())
            };
            match lightclient.do_export(address).await {
                Ok(j) => j,
                Err(e) => object! { "error" => e },
            }
            .pretty(2)
        })
    }
}

struct EncryptCommand {}
impl Command for EncryptCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Encrypt the wallet with a password");
        h.push("Note 1: This will encrypt the seed and the sapling and transparent private keys.");
        h.push("        Use 'unlock' to temporarily unlock the wallet for spending or 'decrypt' ");
        h.push("        to permanatly remove the encryption");
        h.push("Note 2: If you forget the password, the only way to recover the wallet is to restore");
        h.push("        from the seed phrase.");
        h.push("Usage:");
        h.push("encrypt password");
        h.push("");
        h.push("Example:");
        h.push("encrypt my_strong_password");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Encrypt the wallet with a password".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() != 1 {
            return self.help();
        }

        let passwd = args[0].to_string();

        RT.block_on(async move {
            match lightclient.wallet.encrypt(passwd).await {
                Ok(_) => object! { "result" => "success" },
                Err(e) => object! {
                    "result" => "error",
                    "error"  => e.to_string()
                },
            }
            .pretty(2)
        })
    }
}

struct DecryptCommand {}
impl Command for DecryptCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Completely remove wallet encryption, storing the wallet in plaintext on disk");
        h.push(
            "Note 1: This will decrypt the seed and the sapling and transparent private keys and store them on disk.",
        );
        h.push("        Use 'unlock' to temporarily unlock the wallet for spending");
        h.push("Note 2: If you've forgotten the password, the only way to recover the wallet is to restore");
        h.push("        from the seed phrase.");
        h.push("Usage:");
        h.push("decrypt password");
        h.push("");
        h.push("Example:");
        h.push("decrypt my_strong_password");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Completely remove wallet encryption".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() != 1 {
            return self.help();
        }

        let passwd = args[0].to_string();
        RT.block_on(async move {
            match lightclient.wallet.remove_encryption(passwd).await {
                Ok(_) => object! { "result" => "success" },
                Err(e) => object! {
                    "result" => "error",
                    "error"  => e.to_string()
                },
            }
            .pretty(2)
        })
    }
}

struct UnlockCommand {}
impl Command for UnlockCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Unlock the wallet's encryption in memory, allowing spending from this wallet.");
        h.push("Note 1: This will decrypt spending keys in memory only. The wallet remains encrypted on disk");
        h.push("        Use 'decrypt' to remove the encryption permanatly.");
        h.push("Note 2: If you've forgotten the password, the only way to recover the wallet is to restore");
        h.push("        from the seed phrase.");
        h.push("Usage:");
        h.push("unlock password");
        h.push("");
        h.push("Example:");
        h.push("unlock my_strong_password");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Unlock wallet encryption for spending".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() != 1 {
            return self.help();
        }

        let passwd = args[0].to_string();
        RT.block_on(async move {
            match lightclient.wallet.unlock(passwd).await {
                Ok(_) => object! { "result" => "success" },
                Err(e) => object! {
                    "result" => "error",
                    "error"  => e.to_string()
                },
            }
            .pretty(2)
        })
    }
}

struct LockCommand {}
impl Command for LockCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Lock a wallet that's been temporarily unlocked. You should already have encryption enabled.");
        h.push("Note 1: This will remove all spending keys from memory. The wallet remains encrypted on disk");
        h.push("Note 2: If you've forgotten the password, the only way to recover the wallet is to restore");
        h.push("        from the seed phrase.");
        h.push("Usage:");
        h.push("lock");
        h.push("");
        h.push("Example:");
        h.push("lock");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Lock a wallet that's been temporarily unlocked".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() != 0 {
            let mut h = vec![];
            h.push("Extra arguments to lock. Did you mean 'encrypt'?");
            h.push("");

            return format!("{}\n{}", h.join("\n"), self.help());
        }

        RT.block_on(async move {
            match lightclient.wallet.lock().await {
                Ok(_) => object! { "result" => "success" },
                Err(e) => object! {
                    "result" => "error",
                    "error"  => e.to_string()
                },
            }
            .pretty(2)
        })
    }
}

struct ShieldCommand {}
impl Command for ShieldCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Shield all your transparent funds");
        h.push("Usage:");
        h.push("shield [optional address]");
        h.push("");
        h.push("NOTE: The fee required to send this transaction (currently ZEC 0.0001) is additionally deducted from your balance.");
        h.push("Example:");
        h.push("shield");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Shield your transparent ZEC into a sapling address".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        // Parse the address or amount
        let address = if args.len() > 0 {
            Some(args[0].to_string())
        } else {
            None
        };
        RT.block_on(async move {
            match lightclient.do_shield(address).await {
                Ok(txid) => {
                    object! { "txid" => txid }
                }
                Err(e) => {
                    object! { "error" => e }
                }
            }
            .pretty(2)
        })
    }
}

struct EncryptMessageCommand {}
impl Command for EncryptMessageCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Encrypt a memo to be sent to a z-address offline");
        h.push("Usage:");
        h.push("encryptmessage <address> \"memo\"");
        h.push("OR");
        h.push("encryptmessage \"{'address': <address>, 'memo': <memo>}\" ");
        h.push("");
        h.push("NOTE: This command only returns the encrypted payload. It does not broadcast it. You are expected to send the encrypted payload to the recipient offline");
        h.push("Example:");
        h.push("encryptmessage ztestsapling1x65nq4dgp0qfywgxcwk9n0fvm4fysmapgr2q00p85ju252h6l7mmxu2jg9cqqhtvzd69jwhgv8d \"Hello from the command line\"");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Encrypt a memo to be sent to a z-address offline".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() < 1 || args.len() > 3 {
            return self.help();
        }

        // Check for a single argument that can be parsed as JSON
        let (to, memo) = if args.len() == 1 {
            let arg_list = args[0];
            let j = match json::parse(&arg_list) {
                Ok(j) => j,
                Err(e) => {
                    let es = format!("Couldn't understand JSON: {}", e);
                    return format!("{}\n{}", es, self.help());
                }
            };

            if !j.has_key("address") || !j.has_key("memo") {
                let es = format!("Need 'address' and 'memo'\n");
                return format!("{}\n{}", es, self.help());
            }

            let memo = utils::interpret_memo_string(j["memo"].as_str().unwrap().to_string());
            if memo.is_err() {
                return format!("{}\n{}", memo.err().unwrap(), self.help());
            }
            let to = j["address"].as_str().unwrap().to_string();

            (to, memo.unwrap())
        } else if args.len() == 2 {
            let to = args[0].to_string();

            let memo = utils::interpret_memo_string(args[1].to_string());
            if memo.is_err() {
                return format!("{}\n{}", memo.err().unwrap(), self.help());
            }

            (to, memo.unwrap())
        } else {
            return format!("Wrong number of arguments. Was expecting 1 or 2\n{}", self.help());
        };

        if let Ok(m) = memo.try_into() {
            lightclient.do_encrypt_message(to, m).pretty(2)
        } else {
            return format!("Couldn't encode memo");
        }
    }
}

struct DecryptMessageCommand {}
impl Command for DecryptMessageCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Attempt to decrypt a message with all the view keys in the wallet.");
        h.push("Usage:");
        h.push("decryptmessage \"encrypted_message_base64\"");
        h.push("");
        h.push("Example:");
        h.push("decryptmessage RW5jb2RlIGFyYml0cmFyeSBvY3RldHMgYXMgYmFzZTY0LiBSZXR1cm5zIGEgU3RyaW5nLg==");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Attempt to decrypt a message with all the view keys in the wallet.".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() != 1 {
            return self.help();
        }

        RT.block_on(async move { lightclient.do_decrypt_message(args[0].to_string()).await.pretty(2) })
    }
}

struct SendCommand {}
impl Command for SendCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Send ZEC to a given address(es)");
        h.push("Usage:");
        h.push("send <address> <amount in zatoshis || \"entire-verified-zbalance\"> \"optional_memo\"");
        h.push("OR");
        h.push("send '[{'address': <address>, 'amount': <amount in zatoshis>, 'memo': <optional memo>}, ...]'");
        h.push("");
        h.push("NOTE: The fee required to send this transaction (currently ZEC 0.0001) is additionally deducted from your balance.");
        h.push("Example:");
        h.push("send ztestsapling1x65nq4dgp0qfywgxcwk9n0fvm4fysmapgr2q00p85ju252h6l7mmxu2jg9cqqhtvzd69jwhgv8d 200000 \"Hello from the command line\"");
        h.push("");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Send ZEC to the given address".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        // Parse the args. There are two argument types.
        // 1 - A set of 2(+1 optional) arguments for a single address send representing address, value, memo?
        // 2 - A single argument in the form of a JSON string that is "[{address: address, value: value, memo: memo},...]"
        if args.len() < 1 || args.len() > 3 {
            return self.help();
        }

        RT.block_on(async move {
            // Check for a single argument that can be parsed as JSON
            let send_args = if args.len() == 1 {
                let arg_list = args[0];

                let json_args = match json::parse(&arg_list) {
                    Ok(j) => j,
                    Err(e) => {
                        let es = format!("Couldn't understand JSON: {}", e);
                        return format!("{}\n{}", es, self.help());
                    }
                };

                if !json_args.is_array() {
                    return format!("Couldn't parse argument as array\n{}", self.help());
                }

                let fee = u64::from(DEFAULT_FEE);
                let all_zbalance = lightclient.wallet.verified_zbalance(None).await.checked_sub(fee);

                let maybe_send_args = json_args
                    .members()
                    .map(|j| {
                        if !j.has_key("address") || !j.has_key("amount") {
                            Err(format!("Need 'address' and 'amount'\n"))
                        } else {
                            let amount = match j["amount"].as_str() {
                                Some("entire-verified-zbalance") => all_zbalance,
                                _ => Some(j["amount"].as_u64().unwrap()),
                            };

                            match amount {
                                Some(amt) => Ok((
                                    j["address"].as_str().unwrap().to_string().clone(),
                                    amt,
                                    j["memo"].as_str().map(|s| s.to_string().clone()),
                                )),
                                None => Err(format!("Not enough in wallet to pay transaction fee of {}", fee)),
                            }
                        }
                    })
                    .collect::<Result<Vec<(String, u64, Option<String>)>, String>>();

                match maybe_send_args {
                    Ok(a) => a.clone(),
                    Err(s) => {
                        return format!("Error: {}\n{}", s, self.help());
                    }
                }
            } else if args.len() == 2 || args.len() == 3 {
                let address = args[0].to_string();

                // Make sure we can parse the amount
                let value = match args[1].parse::<u64>() {
                    Ok(amt) => amt,
                    Err(e) => {
                        if args[1] == "entire-verified-zbalance" {
                            let fee = u64::from(DEFAULT_FEE);
                            match lightclient.wallet.verified_zbalance(None).await.checked_sub(fee) {
                                Some(amt) => amt,
                                None => return format!("Not enough in wallet to pay transaction fee of {}", fee),
                            }
                        } else {
                            return format!("Couldn't parse amount: {}", e);
                        }
                    }
                };

                let memo = if args.len() == 3 {
                    Some(args[2].to_string())
                } else {
                    None
                };

                // Memo has to be None if not sending to a shileded address
                if memo.is_some() && !Keys::is_shielded_address(&address, &lightclient.config) {
                    return format!("Can't send a memo to the non-shielded address {}", address);
                }

                vec![(args[0].to_string(), value, memo)]
            } else {
                return self.help();
            };

            // Convert to the right format. String -> &str.
            let tos = send_args
                .iter()
                .map(|(a, v, m)| (a.as_str(), *v, m.clone()))
                .collect::<Vec<_>>();
            match lightclient.do_send(tos).await {
                Ok(txid) => {
                    object! { "txid" => txid }
                }
                Err(e) => {
                    object! { "error" => e }
                }
            }
            .pretty(2)
        })
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
        RT.block_on(async move {
            match lightclient.do_save().await {
                Ok(_) => {
                    let r = object! { "result" => "success" };
                    r.pretty(2)
                }
                Err(e) => {
                    let r = object! {
                        "result" => "error",
                        "error" => e
                    };
                    r.pretty(2)
                }
            }
        })
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
        RT.block_on(async move {
            match lightclient.do_seed_phrase().await {
                Ok(j) => j,
                Err(e) => object! { "error" => e },
            }
            .pretty(2)
        })
    }
}

struct TransactionsCommand {}
impl Command for TransactionsCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("List all incoming and outgoing transactions from this wallet");
        h.push("Usage:");
        h.push("list [allmemos]");
        h.push("");
        h.push("If you include the 'allmemos' argument, all memos are returned in their raw hex format");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "List all transactions in the wallet".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() > 1 {
            return format!("Didn't understand arguments\n{}", self.help());
        }

        let include_memo_hex = if args.len() == 1 {
            if args[0] == "allmemos" || args[0] == "true" || args[0] == "yes" {
                true
            } else {
                return format!("Couldn't understand first argument '{}'\n{}", args[0], self.help());
            }
        } else {
            false
        };

        RT.block_on(async move { format!("{}", lightclient.do_list_transactions(include_memo_hex).await.pretty(2)) })
    }
}

struct ImportCommand {}
impl Command for ImportCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Import an external spending or viewing key into the wallet");
        h.push("Usage:");
        h.push("import <spending_key | viewing_key> <birthday> [norescan]");
        h.push("OR");
        h.push("import '{'key': <spending_key or viewing_key>, 'birthday': <birthday>, 'norescan': <true>}'");
        h.push("");
        h.push("Birthday is the earliest block number that has transactions belonging to the imported key. Rescanning will start from this block. If not sure, you can specify '0', which will start rescanning from the first sapling block.");
        h.push("Note that you can import only the full spending (private) key or the full viewing key.");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Import spending or viewing keys into the wallet".to_string()
    }

    fn exec(&self, args: &[&str], lightclient: &LightClient) -> String {
        if args.len() == 0 || args.len() > 3 {
            return format!("Insufficient arguments\n\n{}", self.help());
        }

        let (key, birthday, rescan) = if args.len() == 1 {
            // If only one arg, parse it as JSON
            let json_args = match json::parse(&args[0]) {
                Ok(j) => j,
                Err(e) => {
                    let es = format!("Couldn't understand JSON: {}", e);
                    return format!("{}\n{}", es, self.help());
                }
            };

            if !json_args.is_object() {
                return format!("Couldn't parse argument as a JSON object\n{}", self.help());
            }

            if !json_args.has_key("key") {
                return format!(
                    "'key' field is required in the JSON, containing the spending or viewing key to import\n{}",
                    self.help()
                );
            }

            if !json_args.has_key("birthday") {
                return format!("'birthday' field is required in the JSON, containing the birthday of the spending or viewing key\n{}", self.help());
            }

            (
                json_args["key"].as_str().unwrap().to_string(),
                json_args["birthday"].as_u64().unwrap(),
                !json_args.has_key("norescan"),
            )
        } else {
            let key = args[0];
            let birthday = match args[1].parse::<u64>() {
                Ok(b) => b,
                Err(_) => {
                    return format!(
                        "Couldn't parse {} as birthday. Please specify an integer. Ok to use '0'",
                        args[1]
                    )
                }
            };

            let rescan = if args.len() == 3 {
                if args[2] == "norescan" || args[2] == "false" || args[2] == "no" {
                    false
                } else {
                    return format!(
                        "Couldn't undestand the argument '{}'. Please pass 'norescan' to prevent rescanning the wallet",
                        args[2]
                    );
                }
            } else {
                true
            };

            (key.to_string(), birthday, rescan)
        };

        RT.block_on(async move {
            let r = match lightclient.do_import_key(key, birthday).await {
                Ok(r) => r.pretty(2),
                Err(e) => return format!("Error: {}", e),
            };

            if rescan {
                match lightclient.do_rescan().await {
                    Ok(_) => {}
                    Err(e) => return format!("Error: Rescan failed: {}", e),
                };
            }

            return r;
        })
    }
}

struct HeightCommand {}
impl Command for HeightCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Get the latest block height that the wallet is at.");
        h.push("Usage:");
        h.push("height");
        h.push("");
        h.push("Pass 'true' (default) to sync to the server to get the latest block height. Pass 'false' to get the latest height in the wallet without checking with the server.");

        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Get the latest block height that the wallet is at".to_string()
    }

    fn exec(&self, _args: &[&str], lightclient: &LightClient) -> String {
        RT.block_on(async move {
            format!(
                "{}",
                object! { "height" => lightclient.wallet.last_scanned_height().await}.pretty(2)
            )
        })
    }
}

struct DefaultFeeCommand {}
impl Command for DefaultFeeCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Returns the default fee in zats for outgoing transactions");
        h.push("Usage:");
        h.push("defaultfee <optional_block_height>");
        h.push("");
        h.push("Example:");
        h.push("defaultfee");
        h.join("\n")
    }

    fn short_help(&self) -> String {
        "Returns the default fee in zats for outgoing transactions".to_string()
    }

    fn exec(&self, args: &[&str], _lightclient: &LightClient) -> String {
        if args.len() > 1 {
            return format!("Was expecting at most 1 argument\n{}", self.help());
        }

        RT.block_on(async move {
            let j = object! { "defaultfee" => u64::from(DEFAULT_FEE)};
            j.pretty(2)
        })
    }
}

struct NewAddressCommand {}
impl Command for NewAddressCommand {
    fn help(&self) -> String {
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

        RT.block_on(async move {
            match lightclient.do_new_address(args[0]).await {
                Ok(j) => j,
                Err(e) => object! { "error" => e },
            }
            .pretty(2)
        })
    }
}

struct NotesCommand {}
impl Command for NotesCommand {
    fn help(&self) -> String {
        let mut h = vec![];
        h.push("Show all sapling notes and utxos in this wallet");
        h.push("Usage:");
        h.push("notes [all]");
        h.push("");
        h.push(
            "If you supply the \"all\" parameter, all previously spent sapling notes and spent utxos are also included",
        );

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
                a => return format!("Invalid argument \"{}\". Specify 'all' to include unspent notes", a),
            }
        } else {
            false
        };

        RT.block_on(async move { format!("{}", lightclient.do_list_notes(all_notes).await.pretty(2)) })
    }
}

struct QuitCommand {}
impl Command for QuitCommand {
    fn help(&self) -> String {
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
        RT.block_on(async move {
            match lightclient.do_save().await {
                Ok(_) => "".to_string(),
                Err(e) => e,
            }
        })
    }
}

pub fn get_commands() -> Box<HashMap<String, Box<dyn Command>>> {
    let mut map: HashMap<String, Box<dyn Command>> = HashMap::new();

    map.insert("sync".to_string(), Box::new(SyncCommand {}));
    map.insert("syncstatus".to_string(), Box::new(SyncStatusCommand {}));
    map.insert("encryptionstatus".to_string(), Box::new(EncryptionStatusCommand {}));
    map.insert("encryptmessage".to_string(), Box::new(EncryptMessageCommand {}));
    map.insert("decryptmessage".to_string(), Box::new(DecryptMessageCommand {}));
    map.insert("rescan".to_string(), Box::new(RescanCommand {}));
    map.insert("clear".to_string(), Box::new(ClearCommand {}));
    map.insert("help".to_string(), Box::new(HelpCommand {}));
    map.insert("lasttxid".to_string(), Box::new(LastTxIdCommand {}));
    map.insert("balance".to_string(), Box::new(BalanceCommand {}));
    map.insert("addresses".to_string(), Box::new(AddressCommand {}));
    map.insert("height".to_string(), Box::new(HeightCommand {}));
    map.insert("sendprogress".to_string(), Box::new(SendProgressCommand {}));
    map.insert("import".to_string(), Box::new(ImportCommand {}));
    map.insert("export".to_string(), Box::new(ExportCommand {}));
    map.insert("info".to_string(), Box::new(InfoCommand {}));
    map.insert("zecprice".to_string(), Box::new(ZecPriceCommand {}));
    map.insert("send".to_string(), Box::new(SendCommand {}));
    map.insert("shield".to_string(), Box::new(ShieldCommand {}));
    map.insert("save".to_string(), Box::new(SaveCommand {}));
    map.insert("quit".to_string(), Box::new(QuitCommand {}));
    map.insert("list".to_string(), Box::new(TransactionsCommand {}));
    map.insert("notes".to_string(), Box::new(NotesCommand {}));
    map.insert("new".to_string(), Box::new(NewAddressCommand {}));
    map.insert("defaultfee".to_string(), Box::new(DefaultFeeCommand {}));
    map.insert("seed".to_string(), Box::new(SeedCommand {}));
    map.insert("encrypt".to_string(), Box::new(EncryptCommand {}));
    map.insert("decrypt".to_string(), Box::new(DecryptCommand {}));
    map.insert("unlock".to_string(), Box::new(UnlockCommand {}));
    map.insert("lock".to_string(), Box::new(LockCommand {}));

    map.insert("verify".to_string(), Box::new(VerifyCommand {}));

    Box::new(map)
}

pub fn do_user_command(cmd: &str, args: &Vec<&str>, lightclient: &LightClient) -> String {
    match get_commands().get(&cmd.to_ascii_lowercase()) {
        Some(cmd) => cmd.exec(args, lightclient),
        None => format!("Unknown command : {}. Type 'help' for a list of commands", cmd),
    }
}

#[cfg(test)]
pub mod tests {
    use super::do_user_command;
    use crate::lightclient::{lightclient_config::LightClientConfig, LightClient};
    use lazy_static::lazy_static;
    use tokio::runtime::Runtime;

    lazy_static! {
        static ref TEST_SEED: String = "youth strong sweet gorilla hammer unhappy congress stamp left stereo riot salute road tag clean toilet artefact fork certain leopard entire civil degree wonder".to_string();
    }

    pub fn test_command_caseinsensitive() {
        let lc = Runtime::new()
            .unwrap()
            .block_on(LightClient::test_new(
                &LightClientConfig::create_unconnected("main".to_string(), None),
                Some(TEST_SEED.to_string()),
                0,
            ))
            .unwrap();

        assert_eq!(
            do_user_command("addresses", &vec![], &lc),
            do_user_command("AddReSSeS", &vec![], &lc)
        );
        assert_eq!(
            do_user_command("addresses", &vec![], &lc),
            do_user_command("Addresses", &vec![], &lc)
        );
    }

    #[test]
    pub fn test_nosync_commands() {
        // The following commands should run
    }
}
