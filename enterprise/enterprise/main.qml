import QtQuick 2.2
import QtQuick.Window 2.2
import QtQuick.Controls 1.2

ApplicationWindow {
    id: appWindow
    visible: true
    width: 1000
    height: 500

    property real commonspacing: 0.01
    property var screenList: ["Login.qml", "Register.qml",
                              "CreateDeal.qml", "DealManager.qml",
                              "BoardManager.qml", "Setting.qml"]

    property int loginIndex:0
    property int registerIndex:1
    property int createDealIndex:2
    property int dealMangerIndex:3
    property int boardManagerIndex:4
    property int settingIndex: 5
    property int currentScreenIndex: loginIndex

    // setting
    property alias proxyIp: proxyIp
    property alias proxyPort: proxyPort
    property alias fileServerIp: fileServerIp
    property alias fileServerPort: fileServerPort
    property alias blockchainIp: blockchainIp
    property alias blockchainPort: blockchainPort

    onCurrentScreenIndexChanged: {
        changeScreen(currentScreenIndex);
    }

    // Controller Obj interact with GUI qml
    Rectangle {
        anchors.fill: parent
        color: "#227279"

        onWidthChanged: {
            changeScreen(currentScreenIndex);
        }

        onHeightChanged: {
            changeScreen(currentScreenIndex);
        }

        Loader {
            id: loader
            anchors.centerIn: parent
            width: getLayoutWidth(loginIndex)
            height: getLayoutHeight(loginIndex)
            source: qsTr("qrc:/" + screenList[loginIndex])
        }

        // setting
        AbstractScreen {
            id: ipSettingBlock
            width: parent.width * 0.5
            height: parent.height * 0.2
            anchors.horizontalCenter: parent.horizontalCenter;

            property real commonSpacing:10
            property real commonHeightItem: (height-commonSpacing*2) / 3

            Item {
                id: block1
                width: parent.width
                height: ipSettingBlock.commonHeightItem

                Label {
                    id: proxyIpLB
                    width: parent.width * 0.2
                    height: ipSettingBlock.commonHeightItem

                    text: "proxy: "
                }

                TextField {
                    id: proxyIp
                    x: proxyIpLB.x + proxyIpLB.width + 5
                    width: parent.width * 0.5
                    font.pixelSize: height * 0.4
                    height: ipSettingBlock.commonHeightItem
                    text: "localhost"
                }

                Label {
                    id: proxyPortLb
                    x: proxyIp.x + proxyIp.width + 5
                    width: 5
                    height: ipSettingBlock.commonHeightItem
                    text: " : "
                }

                TextField {
                    id: proxyPort
                    x: proxyPortLb.x + proxyPortLb.width + 5
                    width: parent.width * 0.2
                    height: ipSettingBlock.commonHeightItem
                    font.pixelSize: height * 0.4
                    text: "3000"
                }
            }

            Item {
                id: block2
                y: ipSettingBlock.getNextBottomPosition (block1, ipSettingBlock.commonSpacing);
                width: parent.width
                height: ipSettingBlock.commonHeightItem

                Label {
                    id: fileServerIpLB
                    width: parent.width * 0.2
                    height: ipSettingBlock.commonHeightItem

                    text: "File Server: "
                }

                TextField {
                    id: fileServerIp
                    x: fileServerIpLB.x + fileServerIpLB.width + 5
                    width: parent.width * 0.5
                    font.pixelSize: height * 0.4
                    height: ipSettingBlock.commonHeightItem
                    text: "localhost"
                }

                Label {
                    id: fileServerPortLb
                    x: fileServerIp.x + fileServerIp.width + 5
                    width: 5
                    height: ipSettingBlock.commonHeightItem
                    text: " : "
                }

                TextField {
                    id: fileServerPort
                    x: fileServerPortLb.x + fileServerPortLb.width + 5
                    width: parent.width * 0.2
                    font.pixelSize: height * 0.4
                    height: ipSettingBlock.commonHeightItem
                    text: "7777"
                }
            }


            Item {
                y: ipSettingBlock.getNextBottomPosition (block2, ipSettingBlock.commonSpacing);
                width: parent.width
                height: ipSettingBlock.commonHeightItem

                Label {
                    id: blockchainIpLB
                    width: parent.width * 0.2
                    height: ipSettingBlock.commonHeightItem

                    text: "blockchain: "
                }

                TextField {
                    id: blockchainIp
                    x: blockchainIpLB.x + blockchainIpLB.width + 5
                    width: parent.width * 0.5
                    font.pixelSize: height * 0.4
                    height: ipSettingBlock.commonHeightItem
                    text: "192.168.1.74"
                }

                Label {
                    id: blockchainPortLb
                    x: blockchainIp.x + blockchainIp.width + 5
                    width: 5
                    height: ipSettingBlock.commonHeightItem
                    text: " : "
                }

                TextField {
                    id: blockchainPort
                    x: blockchainPortLb.x + blockchainPortLb.width + 5
                    width: parent.width * 0.2
                    font.pixelSize: height * 0.4
                    height: ipSettingBlock.commonHeightItem
                    text: "8545"
                }
            }

        }
    }


    function getLayoutWidth (screenIndex) {
        if (screenIndex == loginIndex) {
            return appWindow.width * 0.4
        }
        else if (screenIndex == registerIndex)
        {
            return appWindow.width * 0.4
        }
        else if (screenIndex == boardManagerIndex)
        {
            return appWindow.width
        }
        return 0;
    }

    function getLayoutHeight (screenIndex) {
        if (screenIndex == loginIndex) {
            return appWindow.height * 0.4
        }
        if (screenIndex == registerIndex)
        {
            return appWindow.height * 0.35
        }
        else if (screenIndex == boardManagerIndex)
        {
            return appWindow.height
        }

        return 0;
    }

    function changeScreen(screenIndex) {
        loader.width = getLayoutWidth(screenIndex);
        loader.height = getLayoutHeight(screenIndex);
        loader.source = qsTr("qrc:/" + screenList[screenIndex])
    }
}
