import QtQuick 2.0
import QtQuick.Controls 2.2

AbstractScreen {
    property real commonSpacing: 5
    property int  commonTextSize: 16
    property int  commonLabelSize: 19

    Item {
        id: block1
        y: commonSpacing
        width: parent.width * 0.97
        height: parent.height * 0.3
        anchors.horizontalCenter: parent.horizontalCenter

        Label {
            id: labelKeyword
            font.pixelSize: commonLabelSize
            text: "Keyword"
            color: "grey"
        }

        // Keywords block
        Flow {
            id: keywordBlock
            y: getNextBottomPosition(labelKeyword, commonSpacing)
            width: parent.width
            height: getRemainHeight(block1, labelKeyword,commonSpacing) * 0.6
            flow: Flow.LeftToRight

            Flow {
                id: keywordList
                width: continuousWidth
                height: parent.height * 0.6
                flow: Flow.LeftToRight
                spacing: commonSpacing
                property var keywordItems: []
                property var keywords: []
                property int lastestIndex: -1
                property real continuousWidth: 0
                property var keywordComponent: Qt.createComponent("qrc:/CustomizeLabel.qml")

                function onItemDestroyed(item) {
                    item.selfRemove.disconnect(keywordList.onItemDestroyed)
                    var newItemsArray = []
                    keywords = []
                    for (var i in keywords) {
                        if (item != keywordItems[i]) {
                            newItemsArray.push(keywordItems[i])
                            keywords.push(keywordItems[i].text)
                         }
                    }

                    keywordItems = newItemsArray
                    lastestIndex -= 1

                    continuousWidth -= item.width
                    continuousWidth -= commonSpacing
                    insertKeyword.width = parent.width - keywordList.continuousWidth

                    item.destroy()
                }
            }

            TextField {
                id: insertKeyword
                width: parent.width
                height: parent.height * 0.6
                placeholderText: "Keyword"
                font.pixelSize: height * 0.4
                horizontalAlignment: Text.AlignLeft
                verticalAlignment: Text.AlignVCenter
                onAccepted: {
                    // dont process if text is empty
                    if (text == "")
                        return;

                    // dont process if exists
                    for (var i in keywordList.keywordItems) {
                        if (this.text == keywordList.keywordItems[i].text)
                            return;
                    }

                    // add new keyword to List
                    var keywordLabel = keywordList.keywordComponent.createObject(keywordList);
                    keywordLabel.text = insertKeyword.text
                    keywordLabel.height = keywordList.height
                    keywordLabel.destroyWhenDoubleClick = true
                    keywordLabel.selfRemove.connect(keywordList.onItemDestroyed)

                    keywordList.keywordItems.push(keywordLabel);
                    keywordList.keywords.push(keywordLabel.text);
                    keywordList.lastestIndex = keywordList.keywordItems.length - 1;

                    // clear for type new keyword
                    text = ""
                    keywordList.continuousWidth += keywordLabel.width + commonSpacing

                    // invisible insertKeyword if remain width is not enough
                    if (insertKeyword.width - keywordLabel.width - keywordList.spacing <= 0) {
                        insertKeyword.width = 0
                        insertKeyword.visible = false
                        insertKeyword.focus = false
                        return
                    }

                    insertKeyword.width = parent.width - keywordList.continuousWidth
                }

            }

        }

        CustomizeButton {
            id: searchBtn
            width: parent.width * 0.2
            height: getRemainHeight(parent, keywordBlock, commonSpacing)
            y: getNextBottomPosition(keywordBlock, commonSpacing)
            x: parent.width - width
            text: "Search"

            onControlDownChanged:  {
                if (controlDown != true)
                    return;

                if (insertKeyword.text != "") {
                    insertKeyword.accepted()
                }

                account.keywords = keywordList.keywords
                account.on_new_searchButton_clicked()
            }
        }
    }

    Rectangle {
        id: block2
        y: getNextBottomPosition(block1, commonSpacing)
        width: parent.width * 0.97
        height: getRemainHeight(parent, block1, commonSpacing) - commonSpacing
        anchors.horizontalCenter: parent.horizontalCenter

        Item {
            id: resultBlock
            width: parent.width
            height: parent.height

            property real realWidth:  (parent.width - commonSpacing)

            Rectangle {
                id: blockIds
                width: resultBlock.realWidth*0.6
                height: parent.height
                border.color: "grey"
                border.width: 1
                radius: 1

                Flickable {
                    id: docIdsScroll
                    width: parent.width * 0.95
                    height: parent.height * 0.95
                    contentHeight: docIdsContent.heightContinuous
                    anchors.horizontalCenter: parent.horizontalCenter
                    anchors.verticalCenter: parent.verticalCenter
                    clip: true

                    Rectangle {
                        id: docIdsContent
                        width: parent.width
                        height: heightContinuous

                        property var component: Qt.createComponent("qrc:/CustomizeLabel.qml")
                        property real heightContinuous: 0
                        property var docidItems: []
                        property var docids: account.docIds
                        property int lastestIndex: -1

                        onDocidsChanged: {
                            removeAllDocIds();

                            for (var i in docids) {
                                createDocId(docids[i])
                            }
                        }

                        function createDocId(docid) {
                            var item = component.createObject(docIdsContent);
                            item.text = docid
                            item.width = docIdsContent.width
                            item.height = 30 // fixed ???
                            item.radius = 0

                            docIdsContent.docidItems.push(item);
                            lastestIndex  = docIdsContent.docidItems.length - 1;

                            // change background color if lastestIndex is odd number
                            if (lastestIndex %2 == 1) {
                                item.color = "#494949"
                            }
                            else {
                                item.color = "#DBDBDB"
                            }

                            // caculate position if not first
                            if (lastestIndex > 0) {
                                item.y = getNextBottomPosition(docIdsContent.docidItems[lastestIndex-1], commonSpacing)
                            }

                            heightContinuous += item.height + commonSpacing

                            // reassign new height if height continuous greater than content height of scroll
                            if (heightContinuous > docIdsScroll.contentHeight)
                                docIdsContent.height = heightContinuous

                            console.log ("heightContinuous " + docIdsContent.heightContinuous);
                        }

                        function removeAllDocIds() {
                            for (var i in docidItems) {
                                docidItems[i].destroy()
                            }

                            docidItems = []
                            lastestIndex = 0;
                            heightContinuous = 0;
                        }
                    }

                }
            }

            Item {
                id: recDealProperties
                x: getNextRightPosition(blockIds, commonSpacing)
                width: getRemainWidth(parent, blockIds, commonSpacing)
                height: parent.height

                property real itemHeight: (height - commonSpacing * 5)/4
                property real itemWidth: width * 0.97
                property real pixelSizeCommon: itemHeight * 0.25


                TextField {
                    id: price
                    y: commonSpacing
                    width: parent.itemWidth
                    height: parent.itemHeight
                    anchors.horizontalCenter: parent.horizontalCenter
                    placeholderText: "Price"
                    font.pixelSize: parent.pixelSizeCommon
                    verticalAlignment: Text.AlignVCenter
                    validator: RegExpValidator { regExp: /[0-9\.]+/ }

                }

                TextField {
                    id: blockChainAddress
                    y: getNextBottomPosition(price, commonSpacing)
                    width: parent.itemWidth
                    height: parent.itemHeight
                    anchors.horizontalCenter: parent.horizontalCenter
                    placeholderText: "Wallet Address"
                    font.pixelSize: parent.pixelSizeCommon
                    horizontalAlignment: Text.AlignLeft
                    verticalAlignment: Text.AlignVCenter
                    validator: RegExpValidator { regExp: /[^\s\t]+/ }
                }

                TextField {
                    id: passphase
                    y: getNextBottomPosition(blockChainAddress, commonSpacing)
                    width: parent.itemWidth
                    height: parent.itemHeight
                    anchors.horizontalCenter: parent.horizontalCenter
                    placeholderText: "passphase"
                    font.pixelSize:parent.pixelSizeCommon
                    horizontalAlignment: Text.AlignLeft
                    verticalAlignment: Text.AlignVCenter
                    validator: RegExpValidator { regExp: /[^\s\t]+/ }
                    echoMode: TextInput.Password
                }

                CustomizeButton {
                    id: createDealBtn
                    y: getNextBottomPosition(passphase, commonSpacing)
                    width: parent.itemWidth
                    height: parent.itemHeight
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: "Create Deal"

                    onControlDownChanged: {
                        if (controlDown != true)
                            return;

                        // dont continuous process if any text field is empty
                        if (price.text == "" || blockChainAddress.text == "")
                            return;

                        account.dealPrice = parseInt(price.text);
                        account.blockchainAddr = blockChainAddress.text;
                        account.passphase = passphase.text;

                        var date = new Date(Date.now());
                        date.setDate (date.getDate() + 90);

                        account.dealExpiredTime = date;
                        account.on_new_createDealButton_clicked();
                    }
                }
            }
        }
    }
}
