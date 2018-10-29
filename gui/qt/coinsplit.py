
import time
import webbrowser
import hashlib

from electroncash.i18n import _
from electroncash.address import OpCodes, Address, Script, hash160, ScriptOutput
from electroncash.transaction import Transaction,TYPE_ADDRESS
import electroncash.web as web

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from .util import *
from .qrtextedit import ShowQRTextEdit

from electroncash.util import print_error, print_stderr

from .transaction_dialog import show_transaction

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_dialog(*args, **kwargs):
    d = SplitDialog(*args, **kwargs)
    dialogs.append(d)
    d.show()

class SplitDialog(QDialog, MessageBoxMixin):
    def __init__(self, main_window, address, password):
        QDialog.__init__(self, parent=main_window)

        self.main_window = main_window
        self.address = address  # address to spend from
        self.password = password # save for funding

        self.wallet = main_window.wallet
        self.config = main_window.config

        # Extract private key
        index = self.wallet.get_address_index(address)
        key = self.wallet.keystore.get_private_key(index, password)
        privkey = int.from_bytes(key[0],'big')

        # Create contract derived from private key
        self.contract = SplitContract(privkey)

        self.setWindowTitle(_("OP_CHECKDATASIG Coin Splitting"))

        self.setMinimumWidth(800)

        vbox = QVBoxLayout()
        self.setLayout(vbox)
        l = QLabel(_("Master address") + ": " + address.to_ui_string())
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


        hbox = QHBoxLayout()
        vbox.addLayout(hbox)

        l = QLabel(_("TXID of funding:"))
        hbox.addWidget(l)

        b = QPushButton(_("Fund new"))
        #b.clicked.connect(lambda: XXX)
        hbox.addWidget(b)

        hbox.addStretch(1)


        self.fund_txid_e = QLineEdit()
        vbox.addWidget(self.fund_txid_e)


        hbox = QHBoxLayout()
        vbox.addLayout(hbox)

        b = QPushButton(_("Redeem with split (CDS chain)"))
        #b.clicked.connect(lambda: XXX)
        hbox.addWidget(b)

        b = QPushButton(_("Refund (any chain)"))
        #b.clicked.connect(lambda: XXX)
        hbox.addWidget(b)

        hbox.addStretch(1)


        l = QLabel(_("Redeem/refund options:"))
        vbox.addWidget(l)

        self.option1_rb = QRadioButton(_("Only spend spliting coin"))
        vbox.addWidget(self.option1_rb)
        self.option2_rb = QRadioButton(_("Include all coins from address") + " %.10s..."%(address.to_ui_string()))
        vbox.addWidget(self.option2_rb)
        self.option3_rb = QRadioButton(_("Include all coins from wallet") + ' "%s"'%(self.wallet.basename()))
        vbox.addWidget(self.option3_rb)

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
        d.show()
        d.exec_()


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
        p = curve_secp256k1.p()
        G = generator_secp256k1

        # make two derived private keys
        # hard derivation:
        x = int.from_bytes(hashlib.sha512(b'Split1' + master_privkey.to_bytes(32, 'big')).digest(), 'big')
        self.priv1 = 1 + (x % (p-1))
        x = int.from_bytes(hashlib.sha512(b'Split2' + master_privkey.to_bytes(32, 'big')).digest(), 'big')
        self.priv2 = 1 + (x % (p-1))

        # soft derivation:
        #self.priv1 = (0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa * master_privkey) % p
        #self.priv2 = (0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb * master_privkey) % p

        # generate compressed pubkeys
        self.pub1ser = point_to_ser(self.priv1 * G, True)
        self.pub2ser = point_to_ser(self.priv2 * G, True)

        OP_CHECKDATASIG = 0xba
        OP_CHECKDATASIGVERIFY = 0xbb
        cds_sig = b'\0'*70
        cds_msg = b'Split me baby one more time!'
        cds_pubkey = b'\x03' + b'\0'*32
        self.redeemscript = joinbytes([
            OpCodes.OP_IF,
                #this branch can only run on CDS-supporting chain
                len(cds_sig), cds_sig,
                len(cds_msg), cds_msg,
                len(cds_pubkey), cds_pubkey,
                OP_CHECKDATASIGVERIFY,
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
        self.dummy_scriptsig_redeem = '01'*(2 + 72 + len(self.redeemscript))
        self.dummy_scriptsig_refund = '00'*(2 + 72 + len(self.redeemscript))

    def makeinput(self, prevout_hash, prevout_n, value, mode):
        """
        Construct an unsigned input for adding to a transaction. scriptSig is
        set to a dummy value, for size estimation.

        (note: Transaction object will fail to broadcast until you sign and run `completetx`)
        """
        if mode == 'redeem':
            scriptSig = self.dummy_scriptsig_redeem
        elif mode == 'refund':
            scriptSig = self.dummy_scriptsig_refund
        else:
            raise ValueError(mode)

        txin = dict(
            prevout_hash = prevout_hash,
            prevout_n = prevout_n,
            sequence = 0,
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

    def signtx(self, tx, privatekey):
        """generic tx signer for compressed pubkey"""
        keypairs = {self.pub1ser.hex() : (self.priv1.to_bytes(32, 'big'), True),
                    self.pub2ser.hex() : (self.priv2.to_bytes(32, 'big'), True),
                    }
        tx.sign(keypairs)

    def completetx(self, tx, secret):
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
            sig = bytes.fromhex(sig)
            if not sig:
                continue
            # construct the correct scriptsig
            if secret:
                if txin['scriptSig'] != self.dummy_scriptsig_redeem:
                    continue
                script = [
                    len(secret), secret,
                    len(sig), sig,
                    OpCodes.OP_1,
                    0x4c, len(self.redeemscript), self.redeemscript,
                    ]
            else:
                if txin['scriptSig'] != self.dummy_scriptsig_refund:
                    continue
                script = [
                    len(sig), sig,
                    OpCodes.OP_0,
                    0x4c, len(self.redeemscript), self.redeemscript,
                    ]
            txin['scriptSig'] = joinbytes(script).hex()
