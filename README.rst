

.. note :: This project is out of date, but I'm keeping it up for posterity. The best way to split your coins nowadays is to get some already-split dust and use the official `Electron Cash <https://github.com/Electron-Cash/Electron-Cash>`_ (on BCH) and/or `ElectrumSV <https://github.com/electrumsv/electrumsv>`_ (on BSV). New users should avoid using this version due to phishing vulnerabilities in Electron Cash that have appeared in the last few months. Cheers! -Mark

CHECKDATASIG/MUL Coin splitter
==============================

::

  Licence: MIT Licence
  Author: Mark B. Lundeberg
  Language: Python

This is a special release of Electron Cash augmented with a coin-splitting tool
for the November 2018 Bitcoin Cash hard fork. The tool can be started via:

* Tools menu | Coin splitter, or,
* Addresses tab: right-click on an address | Split coins.

By using this tool, you can create transactions built on a history involving
the new OP_CHECKDATASIGVERIFY. Such transactions are impossible to replay on
other nodes / chains that do not support this opcode. In a secondary mode,
you can also create OP_MUL-based splitting, though with some limitations.

**A detailed usage guide can be found here:** `<doc/coinsplitter_user_guide.md>`_
(中文版请访问这个链接：`<doc/CoinSplitterUserGuide_CN.md>`_)

**Since Electron Cash 3.3.3, the mainline client has been checkpointed so as to only connect to BCH servers. In contrast, this release is being maintained up-to-date but with the checkpointing reverted, and with a healthy list of BSV servers included, so you can connect to both BCH and BSV. Enjoy!**

For the technically inclined / curious, the primary code additions appear in
`this file <gui/qt/coinsplit.py>`_ and `this file <gui/qt/coinsplitmul.py>`_.

*Standard instructions for Electron Cash (the base software) follow:*

Electron Cash - Lightweight Bitcoin Cash client
=====================================

::

  Licence: MIT Licence
  Author: Jonald Fyookball
  Language: Python
  Homepage: https://electroncash.org/


.. image:: https://d322cqt584bo4o.cloudfront.net/electron-cash/localized.svg
    :target: https://crowdin.com/project/electron-cash
    :alt: Help translate Electron Cash online





Getting started
===============

Electron Cash is a pure python application forked from Electrum. If you want to use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

If you downloaded the official package (tar.gz), you can run
Electron Cash from its root directory (called Electrum), without installing it on your
system; all the python dependencies are included in the 'packages'
directory. To run Electron Cash from its root directory, just do::

    ./electron-cash

You can also install Electron Cash on your system, by running this command::

    sudo apt-get install python3-setuptools
    python3 setup.py install

This will download and install the Python dependencies used by
Electron Cash, instead of using the 'packages' directory.

If you cloned the git repository, you need to compile extra files
before you can run Electron Cash. Read the next section, "Development
Version".



Development version
===================

Check out the code from Github::

    git clone https://github.com/Electron-Cash/Electron-Cash
    cd Electron-Cash

Run install (this should install dependencies)::

    python3 setup.py install

Compile the icons file for Qt::

    sudo apt-get install pyqt5-dev-tools
    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-requests gettext
    ./contrib/make_locale

For plugin development, see the `plugin documentation <plugins/README.rst>`_.

Running unit tests::

    pip install tox
    tox

Tox will take care of building a faux installation environment, and ensure that
the mapped import paths work correctly.

Creating Binaries
=================


To create binaries, create the 'packages/' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by Electron Cash.

The `make_packages` command may fail with some Ubuntu-packaged versions of
pip ("can't combine user with prefix."). To solve this, it is necessary to
upgrade your pip to the official version::

    pip install pip --user

Linux (source with packages)
----------------------------

Run the following to create the release tarball under `dist/`::

    ./setup.py sdist

Mac OS X / macOS
--------

See `contrib/osx/`.

Windows
-------

See `contrib/build-wine/`.

Android
-------

See `gui/kivy/Readme.txt` file.

iOS
-------

See `ios/`.
