import QtQuick 2.2
import QtQuick.Controls 1.2

AbstractScreen {
    id:root
    visible: true
    property real itemRatio: 0.18
    property real commonSpacing: root.height * 0.05

    Rectangle {
        anchors.fill: parent

        Item {
            id: block1
            y: commonSpacing
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width * 0.9
            height: parent.height * 0.5

            property real itemHeight: (height - commonSpacing)*0.4

            TextField {
                id: username
                width: parent.width
                height: block1.itemHeight
                placeholderText: "username"
                font.pixelSize: height * 0.4
                horizontalAlignment: Text.AlignLeft
                verticalAlignment: Text.AlignVCenter
                validator: RegExpValidator { regExp: /[^\s\t]+/ }

                onAccepted: {
                    if (text != "")
                        password.focus = true
                }
            }

            TextField {
                id: password
                y: getNextBottomPosition(username,commonSpacing)
                width: parent.width
                height: block1.itemHeight
                placeholderText: "password"
                font.pixelSize: height * 0.4
                horizontalAlignment: Text.AlignLeft
                verticalAlignment: Text.AlignVCenter
                echoMode: TextInput.Password

                onAccepted: {
                    console.log ("key on press")
                    login.loginHandle()
                }
            }
        }

        Rectangle {
            id: block2
            anchors.horizontalCenter: parent.horizontalCenter
            y: getNextBottomPosition(block1, commonSpacing)
            width: parent.width * 0.85
            height: getRemainHeight(parent, block1, commonSpacing)

            property real commonWidth:  (width - 10 * 2)*0.4
            property real commonHeight: height*0.5

            CustomizeButton {
                id: login
                text: "login"
                anchors.verticalCenter: parent.verticalCenter
                width: block2.commonWidth
                height: block2.commonHeight

                onControlDownChanged: {
                    if (controlDown != true)
                        return;

                    loginHandle()
                }

                function loginHandle() {
                    if (username.text == "" || password.text == "") {
                        username.text = ""
                        password.text = ""
                        username.focus = true
                        return;
                    }

                    account.usernameTxt = username.text
                    account.passwordTxt = password.text

                    if (!account.onLogin()) {
                        username.text = ""
                        password.text = ""
                        username.focus = true
                        return;
                    }

                    appWindow.currentScreenIndex = appWindow.boardManagerIndex
                }
            }

            Label {
                id: orlabel
                anchors.verticalCenter: parent.verticalCenter
                x: getNextRightPosition(login, commonSpacing)
                width: block2.commonWidth*0.5
                height: block2.commonHeight
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                text: "OR"
                color: "grey"
            }

            CustomizeButton {
                id: register
                x: getNextRightPosition(orlabel,commonSpacing)
                text: "register"
                anchors.verticalCenter: parent.verticalCenter
                width: block2.commonWidth
                height: block2.commonHeight

                onControlDownChanged: {
                    if (controlDown == true)
                        appWindow.currentScreenIndex = appWindow.registerIndex
                }
            }
        }
    }
}
