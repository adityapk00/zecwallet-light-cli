## Zecwallet-cli BIP39 derivation bug

In v1.0 of zecwallet-cli, there was a bug that incorrectly derived HD wallet keys after the first key. That is, the first key, address was correct, but subsequent ones were not. 

The issue was that the 32-byte seed was directly being used to derive then subsequent addresses instead of the 64-byte pkdf2(seed). The issue affected both t and z addresses.

Note that no funds are at risk. The issue is that, if in the future, you import the seed into a different wallet, you might not see all your addresses in the new wallet, so it's better to fix it now. 

## Fix
If you start a wallet that has this bug, you'll be notified. 
The bug can be automatically fixed by the wallet by running the `fixbip39bug` command. Just start `zecwallet-cli` and type `fixbip39bug`.

If you have any funds in the incorrect addresses, they'll be sent to yourself, and the correct addresses re-derived. 