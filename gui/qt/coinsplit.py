
import time

from electroncash.i18n import _
from electroncash.address import Address, ScriptOutput
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
        self.address = address

        self.wallet = main_window.wallet
        self.config = main_window.config

        self.setWindowTitle(_("Coin Spit"))

        self.setMinimumWidth(800)

        vbox = QVBoxLayout()
        self.setLayout(vbox)
        l = QLabel(_("Address") + ": " + address.to_ui_string())
        l.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(l)

    def closeEvent(self, event):
        event.accept()
        try:
            dialogs.remove(self)
        except ValueError:
            pass

    def reject(self,):
        self.close()


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
        self.priv1 = (0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa * master_privkey) % p
        self.priv2 = (0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb * master_privkey) % p

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
                len(pub1ser), pub1ser
            OpCodes.OP_ELSE,
                #this branch can run on any chain
                len(pub2ser), pub2ser
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
