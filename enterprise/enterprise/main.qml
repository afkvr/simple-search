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
