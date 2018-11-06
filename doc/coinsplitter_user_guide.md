# Coin Splitter User Guide

Author: Mark B. Lundeberg

Repository: [https://github.com/markblundeberg/coinsplitter_checkdatasig](https://github.com/markblundeberg/coinsplitter_checkdatasig)

## Description
This software is a variant of Electron Cash that has the added ability to split coins between two different Bitcoin Cash consensus rulesets that will exist starting on November 15, 2018.

The [principle of operation](https://docs.google.com/document/d/12WNybIX4-l2p9Pap0XGRGwLe2DONi4IbyjD6rKnC8gU/edit) is to create a coin (i.e., a transaction output) that can be spent in two ways, using an OP_IF-branching in bitcoin Script:

 - Path 1, whose execution includes a new opcode [OP_CHECKDATASIGVERIFY](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/op_checkdatasig.md), or,
 - Path 0, which executes like a normal address.

By spending the coin on path 1, you create a new coin that can only exist on a chain whose consensus rules support OP_CHECKDATASIGVERIFY (referred to as CDS chain below). Later on, the coin can be refunded on other chains by using path 0. The tool makes this operation streamlined into a user-friendly and nearly automatic process.

Different node software will follow different chains (under default config):

 - CDS chain: ABC >0.18.X, BU >1.5.X, XT release “K”.
 - Non-CDS chains: Older versions of ABC, BU, XT; all SV versions.

## Limitations
This tool does not work directly with hardware wallets. To split coins with hardware wallets, you should send already-split coins (e.g., created using this tool with a software wallet, or gotten from someone else) to the hardware wallet, and then mix those already-split coins together with your hardware wallet’s coins.

This tool only directly creates a **one-way split**. You can start immediately transacting with the post-split CDS-chain coins, but not the non-CDS coins. If you do use the associated coins on non-CDS chains, this means that you are creating conflicting transactions that could in principle be replayed back onto the CDS chain, during a block reorganization. Therefore, the non-CDS coins should be left to sit until you are sure that a block reorganization is unlikely. Alternatively, you may achieve a two-way split by asking someone else to send you a coin that is already incompatible with the CDS chain, and mix that together with your non-CDS coins; this allows you to also immediately make non-CDS transactions.

**Warning:** This tool has been well-tested but in principle it could lose the funds on the ‘split contract’ address. For this reason, only a small nominal amount should be sent to this address (like the default 1000 satoshis). A small coin is entirely sufficient to induce splitting on a much larger coin, when mixed together in one transaction.


## Installing

You can download packaged versions of the tool (Linux/Win) at [https://github.com/markblundeberg/coinsplitter_checkdatasig/releases/latest](https://github.com/markblundeberg/coinsplitter_checkdatasig/releases/latest)
The file checksums have been signed by me (Mark Lundeberg), PGP key [0x7C6BEB5309693C85E3F51DFBDC1959C1BE5BF112](http://pgp.mit.edu/pks/lookup?search=0x7C6BEB5309693C85E3F51DFBDC1959C1BE5BF112&op=index). The files are used in the same way as you would use Electron Cash.

Source + README at [https://github.com/markblundeberg/coinsplitter_checkdatasig](https://github.com/markblundeberg/coinsplitter_checkdatasig).

## Usage

The software starts up in the same manner as Electron Cash, and is able to open any Electron Cash wallet. The splitting tool itself only works on a wallet with private keys (not watching-only wallets nor hardware wallets). During any point of the process, you may close the dialog and/or wallet, since the script keys are deterministically derived from a private key in your wallet (the key associated with ‘Master address’ indicated in the dialog).

### Steps:
1. Open a wallet with balance.
2. Open the Network dialog to ensure you are connected to an server whose node software supports OP_CHECKDATASIGVERIFY. Suggested servers:
    - bch.imaginary.cash
    - electron.jochen-hoenicke.de
    - electroncash.ueo.ch
    - wallet.satoshiscoffeehouse.com
    - (and many more)
3. Open menu **Tools | Coin Splitter**.
4. Click on button **“Fund split contract...”**. It will open a transaction preview that you can inspect. The tool sends 0.00001 BCH (1000 satoshis, ~ $0.005 USD) to a special P2SH address (starting with 3… or bitcoincash:p…). Click on Broadcast.
5. Now click on the button **“Redeem with split (CDS chain)”** and broadcast the resulting transaction. There are two variants:
    1. Redeeming just the split coin -- this creates a single coin of ~660 satoshi value that can only exist on the CDS chain. You can mix this coin with other coins to create more splitted coins.
    2. Redeem the coin together with all wallet coins. This saves you the additional complication/expense of mixing the coin, by combining all of your wallet’s funds into a single coin.

At this point, you now have split coins that can exist only on the CDS chain. If you are not planning to make transactions on non-CDS chains for some time, then the process is now finished. If you are going to make non-CDS chain transactions then some care is needed to make sure that a block reorganization attack cannot undo your split CDS-chain transactions. **Any action taken with your coins on non-CDS chains can theoretically be replayed onto the CDS chain!** For the paranoid, the best practice is to wait at least 200 blocks (a bit more than a day), after which a block reorganization attack becomes technically infeasible.

The funding created in step #4 may or may not have been replayed onto non-CDS chains. If it has been replayed, then you can recover the 660 satoshis by connecting to a non-CDS server, re-opening the Coin Splitting dialog, and then clicking on button **“Refund (any chain)”**. Again, it is best practice to not do this for at least ~200 blocks.

### You can do most of the steps before the fork!

Steps 1-4 can actually be performed prior to the fork. In that case, the splittable coin will exist on all chains, just as if you had waited until after the fork and then ensured the transaction was replayed on all chains. You can even do step 5 and save the transaction for later broadcast, though beware if you use the wallet in the interim, then this may spend some of the inputs from the saved transaction and thereby invalidate it.

### Privacy mode

If you prefer to not connect together your wallet addresses, it’s also possible to open the coin splitting tool by right clicking on an address from the Addresses tab. This creates a per-address splitting contract and gives the option of only combining coins that reside on that address.


## Visual example (via screenshots)

### From Tools menu

![Opening the Coin splitter](/doc/img/1-opening.png)

Opening the Coin splitter

![Initial state](/doc/img/2-initial-state.png)

Initial state

![3](/doc/img/3.png)

Result of clicking on “Create splittable coin” -- the wallet here has chosen to use a change address (yellow input) to create a splittable coin of value 0.00001 BCH (prslp… address), with the excess sent to another change address.

![4](/doc/img/4.png)

After clicking “Broadcast”, we see that the splittable coin information (txid, etc.) has been filled in, and we may now click on Redeem / Refund buttons.

![5](/doc/img/5.png)

If the dialog and wallet is closed then re-opened, it automatically finds the previously made splittable coin again. This will find any coin on the prslp… address, and works even if it the tx was created by some means other than this dialog. This address is deterministically derived, so that it can be recovered as long as you saved the wallet mnemonic.


![6](/doc/img/6.png)

The result of clicking “Redeem with split”, with “combine all coins” option selected. The splittable coin (first input) is combined with all coins in the wallet: three coins on receiving addresses (green), and the change output from the previous transaction (yellow). The single resultant output coin can only exist on the CDS chain, and is placed on the first unused address.

![7](/doc/img/7.png)

At the time of writing, there is no CDS chain (aside from testnet -- info) -- therefore, broadcasting this transaction fails! This error code will also happen after fork day, if we try to broadcast on a non-CDS node. (We could however make a refund, which is perfectly valid on any chain.)

### From Address list

![20](/doc/img/20.png)

In the same wallet, we now open the coin split dialog via the Addresses tab. (As usual in Electron Cash, this tab can be shown via the View menu). This opens the coin splitter in a slightly more private mode, that doesn’t link together your wallet addresses in the same transactions.

![21](/doc/img/21.png)

Several differences can be seen compared to when we opened from the Tools menu:

- The “master address” is the address we chose, rather than the wallet’s first address.
- The split contract address is totally different.
- The dialog doesn’t find any existing coin (since it is looking on a different address compared to the other dialog)
- A new spend option has appeared, which is selected by default.

![22](/doc/img/22.png)

Clicking on ‘Create splittable coin’, both the transaction input and change output correspond to the address we have selected. This step only succeeds if you have selected an address with nonzero balance!

![23](/doc/img/23.png)

The result of clicking “Redeem with split”, with “combine all coins from address” option selected. The splittable coin is combined with all coins on the address -- which turns out to be just one coin -- the change output from the funding transaction. Other coins in the wallet are ignored. Again, the single output coin can only exist on the CDS chain. Beware however that other coins in the wallet will have not been split, yet!

