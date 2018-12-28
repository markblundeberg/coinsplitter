
import time
import webbrowser
import hashlib

from electroncash.i18n import _
from electroncash.address import OpCodes, Address, Script, hash160, ScriptOutput
from electroncash.transaction import Transaction,TYPE_ADDRESS
import electroncash.web as web
from electroncash.wallet import Multisig_Wallet

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from .util import *
from .qrtextedit import ShowQRTextEdit

from electroncash.util import print_error, print_stderr, NotEnoughFunds

from .transaction_dialog import show_transaction

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_dialog(*args, **kwargs):
    d = SplitDialog(*args, **kwargs)
    dialogs.append(d)

class SplitDialog(QDialog, MessageBoxMixin):
    search_done_signal = pyqtSignal(object)

    def __init__(self, main_window, address, password):
        QDialog.__init__(self, parent=main_window)

        self.main_window = main_window
        self.wallet = main_window.wallet
        self.config = main_window.config

        #self.address = address  # address to spend from
        self.password = password # save for funding

        if address:
            self.fund_domain = [address]
            self.fund_change_address = address
            self.default_redeem_address = address
            self.entropy_address = address
        else:
            self.fund_domain = None
            self.fund_change_address = None
            self.default_redeem_address = self.wallet.get_unused_address()
            self.entropy_address = self.wallet.get_addresses()[0]

        if not self.default_redeem_address:
            # self.wallet.get_unused_address() returns None for imported privkey wallets.
            self.close()
            self.main_window.show_error(_("For imported private key wallets, please open the coin splitter from the Addresses tab by right clicking on an address, instead of via the Tools menu."))
            return

        # Extract private key
        index = self.wallet.get_address_index(self.entropy_address)
        try:
            key = self.wallet.keystore.get_private_key(index, password)
        except:
            self.close()
            self.main_window.show_error(_("Coin splitter only works with wallets possessing private keys. See the User Guide for details on how to split other wallets' coins, at:") + "\nhttps://github.com/markblundeberg/coinsplitter_checkdatasig/blob/master/doc/coinsplitter_user_guide.md")
            return
        privkey = int.from_bytes(key[0],'big')

        if isinstance(self.wallet, Multisig_Wallet):
            self.main_window.show_error("Multi-sig wallet support is partial.\nThe splitter coin itself is *not* multisig and belongs to you alone (it cannot be redeemed by other parties).")

        # Create contract derived from private key
        self.contract = SplitContract(privkey)

        self.setWindowTitle(_("OP_CHECKDATASIG Coin Splitting"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)
        l = QLabel(_("Master address") + ": " + self.entropy_address.to_ui_string())
        l.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(l)

        l = QLabel(_("Split contract") + ": " + self.contract.address.to_ui_string())
        l.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(l)

        hbox = QHBoxLayout()
        vbox.addLayout(hbox)

        addr_URL = web.BE_URL(self.config, 'addr', self.contract.address)
        b = QPushButton(_("View on block explorer"))
        b.clicked.connect(lambda: webbrowser.open(addr_URL))
        hbox.addWidget(b)
        if not addr_URL:
            b.setDisabled(True)

        b = QPushButton(_("View redeem script..."))
        b.clicked.connect(self.showscript)
        hbox.addWidget(b)

        hbox.addStretch(1)


        l = QLabel("<b>%s</b>"%(_("Splittable coin creation/finding:")))
        vbox.addWidget(l)

        hbox = QHBoxLayout()
        vbox.addLayout(hbox)

        b = QPushButton(_("Create splittable coin"))
        b.clicked.connect(self.fund)
        hbox.addWidget(b)
        self.fund_button = b

        b = QPushButton("x")
        b.clicked.connect(self.search)
        hbox.addWidget(b)
        self.search_button = b

        hbox.addStretch(1)


        grid = QGridLayout()
        vbox.addLayout(grid)

        l = QLabel(_("TXID"))
        grid.addWidget(l, 0, 0)

        l = QLabel(_("Out#"))
        grid.addWidget(l, 0, 1)

        l = QLabel(_("Value (sats)"))
        grid.addWidget(l, 0, 2)

        self.fund_txid_e = QLineEdit()
        self.fund_txid_e.textEdited.connect(self.changed_coin)
        grid.addWidget(self.fund_txid_e, 1, 0)

        self.fund_txout_e = QLineEdit()
        self.fund_txout_e.setMaximumWidth(40)
        self.fund_txout_e.setAlignment(Qt.AlignRight)
        self.fund_txout_e.textEdited.connect(self.changed_coin)
        grid.addWidget(self.fund_txout_e, 1, 1)

        self.fund_value_e = QLineEdit()
        self.fund_value_e.setMaximumWidth(70)
        self.fund_value_e.setAlignment(Qt.AlignRight)
        self.fund_value_e.textEdited.connect(self.changed_coin)
        grid.addWidget(self.fund_value_e, 1, 2)


        l = QLabel("<b>%s</b>"%(_("Splittable coin spending:")))
        vbox.addWidget(l)

        self.option1_rb = QRadioButton(_("Only spend splittable coin"))
        self.option2_rb = QRadioButton()
        self.option3_rb = QRadioButton(_("Combine with all coins from wallet") + ' "%s"'%(self.wallet.basename()))
        vbox.addWidget(self.option1_rb)
        vbox.addWidget(self.option2_rb)
        vbox.addWidget(self.option3_rb)
        if self.fund_change_address:
            self.option2_rb.setText(_("Combine with all coins from address") + " %.10s..."%(self.fund_change_address.to_ui_string()))
            self.option2_rb.setChecked(True)
        else:
            self.option3_rb.setChecked(True)
            self.option2_rb.setHidden(True)


        hbox = QHBoxLayout()
        vbox.addLayout(hbox)
        l = QLabel(_("Output to:"))
        hbox.addWidget(l)
        self.redeem_address_e = QLineEdit()
        self.redeem_address_e.setText(self.default_redeem_address.to_full_ui_string())
        hbox.addWidget(self.redeem_address_e)


        hbox = QHBoxLayout()
        vbox.addLayout(hbox)

        b = QPushButton(_("Redeem with split (CDS chain only)"))
        b.clicked.connect(lambda: self.spend('redeem'))
        hbox.addWidget(b)
        self.redeem_button = b

        b = QPushButton(_("Refund (any chain)"))
        b.clicked.connect(lambda: self.spend('refund'))
        hbox.addWidget(b)
        self.refund_button = b

        self.changed_coin()

        self.search_done_signal.connect(self.search_done)
        self.search()

        self.show()

    def closeEvent(self, event):
        event.accept()
        try:
            dialogs.remove(self)
        except ValueError:
            pass

    def reject(self,):
        self.close()

    def showscript(self,):
        if not self.contract:
            return
        script = self.contract.redeemscript
        schex = script.hex()

        try:
            sco = ScriptOutput(script)
            decompiled = sco.to_ui_string()
        except:
            decompiled = "decompiling error"

        d = QDialog(self)
        d.setWindowTitle(_('Split contract script'))
        d.setMinimumSize(610, 490)

        layout = QGridLayout(d)

        script_bytes_e = QTextEdit()
        layout.addWidget(QLabel(_('Bytes')), 1, 0)
        layout.addWidget(script_bytes_e, 1, 1)
        script_bytes_e.setText(schex)
        script_bytes_e.setReadOnly(True)
        #layout.setRowStretch(2,3)

        decompiled_e = QTextEdit()
        layout.addWidget(QLabel(_('ASM')), 3, 0)
        layout.addWidget(decompiled_e, 3, 1)
        decompiled_e.setText(decompiled)
        decompiled_e.setReadOnly(True)
        #layout.setRowStretch(3,1)

        hbox = QHBoxLayout()

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)

        layout.addLayout(hbox, 4, 1)
#        d.setWindowModality(Qt.WindowModal)
#        d.exec_()
        d.show()

    def changed_coin(self,):
        # if any of the txid/out#/value changes
        try:
            txid = bytes.fromhex(self.fund_txid_e.text())
            assert len(txid) == 32
            prevout_n = int(self.fund_txout_e.text())
            value = int(self.fund_value_e.text())
        except:
            self.redeem_button.setDisabled(True)
            self.refund_button.setDisabled(True)
        else:
            self.redeem_button.setDisabled(False)
            self.refund_button.setDisabled(False)

    def fund(self,):
        outputs = [(TYPE_ADDRESS, self.contract.address, 1000)]
        try:
            tx = self.wallet.mktx(outputs, self.password, self.config,
                                  domain=self.fund_domain, change_addr=self.fund_change_address)
        except NotEnoughFunds:
            return self.show_critical(_("Not enough balance to fund smart contract."))
        except Exception as e:
            return self.show_critical(repr(e))
        for i,out in enumerate(tx.outputs()):
            if out[1] == self.contract.address:
                self.fund_txout_e.setText(str(i))
                self.fund_value_e.setText(str(out[2]))
                break
        else:
            raise RuntimeError("Created tx is incorrect!")
        self.fund_txid_e.setText(tx.txid())
        self.fund_txid_e.setCursorPosition(0)
        show_transaction(tx, self.main_window,
                         "Make splittable coin (master:%s)"%(self.entropy_address.to_ui_string()),
                         prompt_if_unsaved=True)
        self.changed_coin()

    def spend(self, mode):
        prevout_hash = self.fund_txid_e.text()
        prevout_n = int(self.fund_txout_e.text())
        value = int(self.fund_value_e.text())
        locktime = 0
        estimate_fee = lambda x:(1*x)
        out_addr = Address.from_string(self.redeem_address_e.text())

        # generate the special spend
        inp = self.contract.makeinput(prevout_hash, prevout_n, value, mode)

        inputs = [inp]
        invalue = value

        # add on other spends
        if self.option1_rb.isChecked():
            domain = []
        elif self.option2_rb.isChecked():
            domain = [self.fund_change_address]
        elif self.option3_rb.isChecked():
            domain = None
        else:
            raise RuntimeError
        other_coins = self.wallet.get_utxos(domain, exclude_frozen=True, mature=True, confirmed_only=False)
        for coin in other_coins:
            self.wallet.add_input_info(coin)
            inputs.append(coin)
            invalue += coin['value']

        outputs = [(TYPE_ADDRESS, out_addr, 0)]
        tx1 = Transaction.from_io(inputs,outputs,locktime)
        txsize = len(tx1.serialize(True))//2
        fee = estimate_fee(txsize)

        outputs = [(TYPE_ADDRESS, out_addr, invalue - fee)]
        tx = Transaction.from_io(inputs,outputs,locktime)
        self.contract.signtx(tx)
        self.wallet.sign_transaction(tx, self.password)
        self.contract.completetx(tx)

        if mode == 'refund':
            desc = "Spend splittable coin (replayable on any chain)"
        elif mode == 'redeem':
            desc = "Spend splittable coin (CDS chain only!)"
        show_transaction(tx, self.main_window,
                         desc,
                         prompt_if_unsaved=True)

    def search(self,):
        self.search_button.setIcon(QIcon(":icons/status_waiting"))
        self.search_button.setText(_("Searching..."))
        self.search_button.setDisabled(True)

        self.wallet.network.send([("blockchain.scripthash.listunspent",
                                  [self.contract.address.to_scripthash_hex()]),
                                  ],
                                 self.search_done_signal.emit)

    def search_done(self, response):
        error = response.get('error')
        result = response.get('result')
        params = response.get('params')

        if result and not error:
            # just grab first utxo
            utxo = result[0]
            self.fund_txid_e.setText(utxo['tx_hash'])
            self.fund_txid_e.setCursorPosition(0)
            self.fund_txout_e.setText(str(utxo['tx_pos']))
            self.fund_value_e.setText(str(utxo['value']))
            self.changed_coin()
            self.search_button.setIcon(QIcon(":icons/tab_coins"))
            self.search_button.setText(_("Found splittable coin!"))
            self.search_button.setDisabled(True)
            self.fund_button.setDisabled(True)
            return

        if error:
            self.show_error("Search request error: " + str(error))

        self.search_button.setIcon(QIcon())
        self.search_button.setText(_("Find splittable coin"))
        self.search_button.setDisabled(False)


from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from electroncash.bitcoin import ser_to_point, point_to_ser

def joinbytes(iterable):
    """Joins an iterable of bytes and/or integers into a single byte string"""
    return b''.join((bytes((x,)) if isinstance(x,int) else x) for x in iterable)

class SplitContract:
    """Contract for making coins that can only be spent on BCH chains supporting
    OP_CHECKDATASIGVERIFY, with backup clause for recovering dust on non-supporting
    chains."""
    def __init__(self, master_privkey):
        G = generator_secp256k1
        order = G.order()

        # make two derived private keys (integers between 1 and p-1 inclusive)

        # hard derivation (irreversible):
        x = int.from_bytes(hashlib.sha512(b'Split1' + master_privkey.to_bytes(32, 'big')).digest(), 'big')
        self.priv1 = 1 + (x % (order-1))
        x = int.from_bytes(hashlib.sha512(b'Split2' + master_privkey.to_bytes(32, 'big')).digest(), 'big')
        self.priv2 = 1 + (x % (order-1))

        # soft derivation (reversible):
        #self.priv1 = (0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa * master_privkey) % order
        #self.priv2 = (0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb * master_privkey) % order

        # generate compressed pubkeys
        self.pub1ser = point_to_ser(self.priv1 * G, True)
        self.pub2ser = point_to_ser(self.priv2 * G, True)

        self.keypairs = {
            self.pub1ser.hex() : (self.priv1.to_bytes(32, 'big'), True),
            self.pub2ser.hex() : (self.priv2.to_bytes(32, 'big'), True),
            }

        # params from ABC 0.18.2 unit tests
        cds_sig = bytes.fromhex('30440220256c12175e809381f97637933ed6ab97737d263eaaebca6add21bced67fd12a402205ce29ecc1369d6fc1b51977ed38faaf41119e3be1d7edfafd7cfaf0b6061bd07')
        cds_msg = b''
        cds_pubkey = bytes.fromhex('038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508')
        self.redeemscript = joinbytes([
            OpCodes.OP_IF,
                #this branch can only run on CDS-supporting chain
                len(cds_sig), cds_sig,
                len(cds_msg), cds_msg,
                len(cds_pubkey), cds_pubkey,
                OpCodes.OP_CHECKDATASIGVERIFY,
                len(self.pub1ser), self.pub1ser,
            OpCodes.OP_ELSE,
                #this branch can run on any chain
                len(self.pub2ser), self.pub2ser,
            OpCodes.OP_ENDIF,
            OpCodes.OP_CHECKSIG
            ])
        assert 76 < len(self.redeemscript) <= 255  # simplify push in scriptsig; note len is around 200.

        self.address = Address.from_multisig_script(self.redeemscript)

        # make dummy scripts of correct size for size estimation.
        self.dummy_scriptsig_redeem = '01'*(4 + 72 + len(self.redeemscript))
        self.dummy_scriptsig_refund = '00'*(4 + 72 + len(self.redeemscript))

    def makeinput(self, prevout_hash, prevout_n, value, mode):
        """
        Construct an unsigned input for adding to a transaction. scriptSig is
        set to a dummy value, for size estimation.

        (note: Transaction object will fail to broadcast until you sign and run `completetx`)
        """
        if mode == 'redeem':
            scriptSig = self.dummy_scriptsig_redeem
            pubkey = self.pub1ser
        elif mode == 'refund':
            scriptSig = self.dummy_scriptsig_refund
            pubkey = self.pub2ser
        else:
            raise ValueError(mode)

        txin = dict(
            prevout_hash = prevout_hash,
            prevout_n = prevout_n,
            sequence = 0xffffffff,
            scriptSig = scriptSig,

            type = 'unknown',
            address = self.address,
            scriptCode = self.redeemscript.hex(),
            num_sig = 1,
            signatures = [None],
            x_pubkeys = [pubkey.hex()],
            value = value,
            )
        return txin

    def signtx(self, tx):
        """generic tx signer for compressed pubkey"""
        tx.sign(self.keypairs)

    def completetx(self, tx):
        """
        Completes transaction by creating scriptSig. You need to sign the
        transaction before using this (see `signtx`). `secret` may be bytes
        (if redeeming) or None (if refunding).

        This works on multiple utxos if needed.
        """

        for txin in tx.inputs():
            # find matching inputs
            if txin['address'] != self.address:
                continue
            sig = txin['signatures'][0]
            if not sig:
                continue
            sig = bytes.fromhex(sig)

            if txin['scriptSig'] == self.dummy_scriptsig_redeem:
                script = [
                    len(sig), sig,
                    OpCodes.OP_1,
                    0x4c, len(self.redeemscript), self.redeemscript,
                    ]
            elif txin['scriptSig'] == self.dummy_scriptsig_refund:
                script = [
                    len(sig), sig,
                    OpCodes.OP_0,
                    0x4c, len(self.redeemscript), self.redeemscript,
                    ]
            else:
                # already completed..?
                continue
            txin['scriptSig'] = joinbytes(script).hex()
        # need to update the raw, otherwise weird stuff happens.
        tx.raw = tx.serialize()
