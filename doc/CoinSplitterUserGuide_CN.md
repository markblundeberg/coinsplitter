# Coin Splitter User Guide

标签（空格分隔）： 教程

---

作者: *Mark B. Lundeberg*
翻译者：赵斌BTC.com
校准者：刘馥祎BTC.com
Repository: [https://github.com/markblundeberg/coinsplitter_checkdatasig][1]

> [TOC]

## 描述
该软件是Electron Cash的一种变体，它具有在2018年11月15日开始存在的两种不同比特币现金共识规则集之间拆分币（BCH、BSV）的附加功能。

该[工作原理][2]是创建一个币（即交易输出），可以通过在比特币脚本使用OP_IF分支的两种方式来花费：

 - 路径1，其执行包括新的操作码[OP_CHECKDATASIGVERIFY][3]，或者，
 - 路径0，执行方式与普通地址类似。
 
通过在路径1上花费币，您可以创建一个新的币，该币只能存在于支持OP_CHECKDATASIGVERIFY（下面称为CDS链）的链上。之后，可以使用路径0在其他链上退还币。该工具简化了用户操作且几乎是自动的过程。

不同的节点软件将遵循不同的链（在默认配置下）：

 - CDS链：ABC> 0.18.X，BU> 1.5.X，XT版本“K”。
 - 非CDS链：旧版ABC，BU，XT; 所有SV版本。

## 限制
此工具无法直接与硬件钱包一起使用。要使用硬件钱包拆分币，您应该将已经拆分的币（例如，使用此工具拆分的或从其他人获得的）发送到硬件钱包，然后将这些已经拆分的币与您的硬件钱包混合在一起。

此工具仅直接创建**单向拆分**。您可以立即开始使用拆分后的CDS链上的币进行交易，但不能使用非CDS链上的币进行交易。如果您确实在非CDS链上使用了相关的币，这意味着您正在创建冲突的交易，原则上可以在块重组期间重放回CDS链。因此，非CDS链上的币应保持不变，直到您确定不可能进行区块重组。或者，您可以通过要求其他人向您发送已与CDS链条不兼容的币进行双向拆分，并将其与您的非CDS币混合在一起; 这使您也可以立即进行非CDS交易。

**警告：**此工具已经过充分测试，但原则上它可能会丢失“拆分合约”地址上的资金。出于这个原因，只应向该地址发送一条小额交易（如默认的1000 satoshis）。当把这条小额交易和剩余金额混在一起时，即可完成拆分。

## 安装
您可以在[https://github.com/markblundeberg/coinsplitter_checkdatasig/releases][4]下载该工具的打包版本。 文件校验和已由我（Mark Lundeberg）签署，PGP密钥为0x7C6BEB5309693C85E3F51DFBDC1959C1BE5BF112。这些文件的使用方法与使用Electron Cash的方式相同。

来源+自述文件来自[https://github.com/markblundeberg/coinsplitter_checkdatasig][5]。

## 用法
该软件以与Electron Cash相同的方式启动，并且可以打开任何Electron Cash钱包。拆分工具本身仅适用于带私钥的钱包（不适用只有观察权限的钱包，也不适用于硬件钱包）。在拆分的过程中，您可以关闭对话框和/或钱包，因为脚本密钥是从钱包中的私钥（与对话框中指示的“主地址”相关联的密钥）导出的。

### 步骤：

 1. 打开一个钱包。
 2. 打开Network dialog以确保连接到节点软件支持OP_CHECKDATASIGVERIFY的服务器。建议的服务器：bch.imaginary.cash、electron.jochen-hoenicke.de、electroncash.ueo.ch、wallet.satoshiscoffeehouse.com、（还有很多）。
 3. 打开菜单**Tools | Coin Splitter**。
 4. 点击“**Fund split contract**...”按钮。它将打开交易预览页。该工具将0.00001 BCH（1000 satoshis，〜$ 0.005 USD）发送到特殊的P2SH地址（以3 ...或bitcoincash：p ...开头）。点击Broadcast。
 5. 现在点击“**Redeem with split (CDS chain)**”按钮，然后广播生成的交易。有两种变体：
i.只兑换分裂币 - 这会产生一个约660 satoshi的币，只能存在于CDS链上。您可以将此币与剩余的币混合以创建更多分裂的币。
ii.将币与所有钱包的币一起兑换。通过将所有钱包的资金组成一枚币，这可以降低拆分币的复杂性和费用。

此时，您现在拥有只能存在于CDS链上的币。如果您不打算在非CDS链上进行交易，那么该过程已经完成。如果您要进行非CDS链的交易，则需要确保块重组攻击无法撤消CDS链上的交易。**您的币在非CDS链上采取的任何行动理论上都可以重放到CDS链上！**对于偏执狂，最佳做法是等待至少200个区块（一天多一点），之后区块重组攻击在技术上变得不可行。

步骤＃4中创建的资金可能已经或可能未被重放到非CDS链上。如果已重放，则可以通过连接到非CDS服务器，重新打开Coin Splitting对话框，然后单击“Refund（any chain）”按钮来恢复660 satoshis 。同样，最好不要在至少约200个块中执行此操作。

### 您可以在分叉之前完成大部分步骤！
步骤1-4实际上可以在分叉之前执行。在这种情况下，可拆分币将存在于所有链上，就像您在分叉之后等待，然后确保交易在所有链上重放。您甚至可以执行步骤5并保存交易以供以后广播使用，但是如果您在此期间使用钱包，请注意，这可能会花费一些来自已保存交易的输入，从而使其无效。

### 隐私模式
如果您不想将钱包地址连接在一起，也可以通过右键单击“地址”选项卡中的地址来打开币拆分工具。这将创建一个按地址拆分合约，并提供仅组合保留在该地址上的币的选项。

### 拆分其他钱包（硬件/多签名/冷（仅限观看）/非Electron Cash）
该工具旨在与拥有私钥的标准非多签名钱包一起使用。这样做是为了准确地导出拆分合约，因此只要使用助记符恢复钱包就可以完全恢复。不幸的是，这意味着该工具无法直接与其他钱包类型一起使用。但是，间接方法仍然没有问题。

要使用此工具在硬件钱包中拆分币，您必须手动把钱打到硬件钱包里，然后再去硬件钱包内混币：

 1. 使用Electron Cash创建标准软件钱包 - 您可以将助记符保存在安全性较低的地方，因为您只需在此钱包中存储1000个satoshis。
 2. 打开分离币工具。
 3. **资金**！选择并复制拆分合约地址，bitcoincash:ppppppppp...用您的硬件钱包向拆分合约地址发送1000个sats。1000个sats也可以来自您拥任何其他钱包。由于费用/灰尘限制，不能发送低于888 satoshis。
 4. 当需要拆分时，再次打开钱包和splitter tool - 它应该找到你所做的1000个utxo。
 5. 从您的硬件钱包中获取一个接收地址bitcoincash:qzzzzzzzzz。将其输入到splitter tool的“output address”字段中。
 6. 花！将一个微小的拆分币发送到您的硬件钱包中。Electron Cash现在将为空。
 7. 扫（混币）！使用硬件钱包混合所有币（包括您刚制作的微小的拆分币）。结果将是一个包含整个钱包余额的拆分币。

上述方法可以确保您的硬件钱包币安全，因为在任何时候都不需要大额的从硬件钱包中转出。同样的逻辑适用于多重钱包，冷（仅限观看）钱包，以及任何种类的比特币现金钱包（非Electron Cash）。

### OP_MUL分离工具
在该工具的最新版本中，您还可以为另一种使用OP_MUL的拆分合约提供资金 - 这可以让您在post-hardforkSV链上单独拆分币，如果您真的小心一起使用OP_MUL此工具与OP_CHECKDATASIGVERIFY工具，您可以实现安全的双向拆分，不受任何类型的重放攻击。

OP_MUL方法的缺点是拆分合约地址上的资金无法在OP_MUL禁用的链上恢复。所以，你绝对不应该向地址发送超过1000个satoshis，因为它们将被锁定在ABC链上，直到有一天OP_MUL重新启用（这可能发生在2019年5月，但没有保证） 。

## 图片示例（通过截图）
### 从工具菜单
![工具菜单][6]

打开Coin splitter

![币分配工具][7]

初始状态

![初始状态][8]

单击“Create splittable coin”的结果 - 这里的钱包选择使用更改地址（标黄的输入）来创建值为0.00001 BCH（合约地址）的可拆分币，并将多余的币发送到另一个找零地址。

![此处输入图片的描述][9]

点击“Broadcast”后，我们看到已填写可拆分币信息（txid等），现在我们可以点击Redeem / Refund按钮。

![此处输入图片的描述][10]

如果关闭对话框和钱包然后重新打开，它会自动再次找到先前制作的可拆分币。这将在合约地址上找到所有币，并且即使它是通过除此对话框之外的某些方式创建的交易也可以工作。此地址是确定性的，因此只要您保存了钱包助记符，就可以恢复该地址。

![此处输入图片的描述][11]

单击“Redeem with split”，选中“combine all coins”选项。可拆分币（第一输入）与钱包中的所有币混合。合成的币输出币只能存在于CDS链上，并且放在第一个未使用的地址上。

![此处输入图片的描述][12]

在撰写本文时，没有CDS链（除了testnet - info） - 因此，广播此交易失败！如果我们尝试在非CDS节点上广播，则此错误代码也将在分叉日之后发生。（但我们可以退款，这在任何链上都是完全有效的。）

### 从地址列表拆分
![此处输入图片的描述][13]

在同一个钱包中，我们现在通过地址选项卡打开Split coins对话框。（与Electron Cash中一样，此选项卡可以通过“视图”菜单显示）。这将以更私密的模式打开coin splitter，不会在同一交易中将您的钱包地址混合在一起。

 ![此处输入图片的描述][14]
 
 与从“Tools”菜单打开时相比，可以看到几个差异：

 - “Master address”是我们选择的地址，而不是钱包的第一个地址。
 - 拆分合约地址完全不同。
 - 该对话框找不会查找已经存在的拆分币（因为它与其他对话框相比，它在查找不同的地址）
 - 出现了一个新的支出选项，默认选择该选项。

![此处输入图片的描述][15]

点击“Create splittable coin”，交易的输入和找零输出都对应于我们选择的地址。您选择了非零余额的地址，则此步骤才会成功！

![此处输入图片的描述][16]

单击“Redeem with split”的结果，选中“combine all coins from address”选项。可拆分币与地址上的所有币相混合 - 成为一枚币 - 来自存入交易的找零输出。钱包里其他地址的币被忽略了。同样，单输出币只能存在于CDS链上。但请注意，钱包里的其他币还没有分开！


  [1]: https://github.com/markblundeberg/coinsplitter_checkdatasig
  [2]: https://docs.google.com/document/d/12WNybIX4-l2p9Pap0XGRGwLe2DONi4IbyjD6rKnC8gU/edit#heading=h.3qbu0rp0d62w
  [3]: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/op_checkdatasig.md
  [4]: https://github.com/markblundeberg/coinsplitter_checkdatasig/releases
  [5]: https://github.com/markblundeberg/coinsplitter_checkdatasig
  [6]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/1-opening.png
  [7]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/2-initial-state.png
  [8]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/3.png
  [9]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/4.png
  [10]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/5.png
  [11]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/6.png
  [12]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/7.png
  [13]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/20.png
  [14]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/21.png
  [15]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/22.png
  [16]: https://raw.githubusercontent.com/markblundeberg/coinsplitter_checkdatasig/master/doc/img/23.png