import QtQuick 2.7
import QtQuick.Controls 2.0

AbstractScreen {
    id:root
    visible: true
    property real itemRatio: 0.17
    property real commonSpacing: root.height * 0.03

    Rectangle {
        anchors.fill: parent

        Rectangle {
            id: block1
            y: commonSpacing
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width * 0.9
            height: parent.height * 0.7

            property real itemHeight: (height - commonSpacing*2)/3

            TextField {
                id: username
                width: parent.width
                height: block1.itemHeight
                placeholderText: "username"
                font.pixelSize: height * 0.3
                horizontalAlignment: Text.AlignLeft
                verticalAlignment: Text.AlignVCenter
                validator: RegExpValidator { regExp: /[^\s\t]+/ }
            }

            TextField {
                id: password
                y: getNextBottomPosition(username, commonSpacing)
                width: parent.width
                height: block1.itemHeight
                placeholderText: "password"
                font.pixelSize: height * 0.3
                horizontalAlignment: Text.AlignLeft
                verticalAlignment: Text.AlignVCenter
                validator: RegExpValidator { regExp: /[^\s\t]+/ }
                echoMode: TextInput.Password
            }

            TextField {
                id: confirmPassword
                y: getNextBottomPosition(password, commonSpacing)
                width: parent.width
                height: block1.itemHeight
                placeholderText: "confirm password"
                font.pixelSize: height * 0.3
                horizontalAlignment: Text.AlignLeft
                verticalAlignment: Text.AlignVCenter
                validator: RegExpValidator { regExp: /[^\s\t]+/ }
                echoMode: TextInput.Password
            }
        }

        Rectangle {
            id: block2
            anchors.horizontalCenter: parent.horizontalCenter
            y: getNextBottomPosition(block1,commonSpacing)
            width: parent.width * 0.9
            height: getRemainHeight(parent, block1,commonSpacing)

            property real commonWidth:  width
            property real commonHeight: height*0.7

            CustomizeButton {
                id: back
                text: " <- back"
                anchors.verticalCenter: parent.verticalCenter
                width: (block2.commonWidth-commonSpacing)/2
                height: block2.commonHeight

                onControlDownChanged: {
                        appWindow.currentScreenIndex = appWindow.loginIndex
                }
            }


            CustomizeButton {
                id: register
                text: "register"
                anchors.verticalCenter: parent.verticalCenter
                x: getNextRightPosition(back)
                width: (block2.commonWidth-commonSpacing)/2
                height: block2.commonHeight

                onControlDownChanged: {
                    if (controlDown == true) {
                        if (username.text == "" || password.text == "" || confirmPassword.text == "") {
                            return;
                        }

                        // reset passwords if not same
                        if (password.text != confirmPassword.text) {
                            password.text = ""
                            confirmPassword.text = ""
                            return;
                        }

                        account.usernameTxt = username.text
                        account.passwordTxt = password.text
                        if (!account.onRegister()) {
                            username.text = ""
                            password.text = ""
                            confirmPassword.text = ""
                            return;
                        }

                        appWindow.currentScreenIndex = appWindow.loginIndex
                    }
                }
            }
        }
    }
}
