import QtQuick 2.2
import QtQuick.Controls 1.2

Rectangle {
    color: "white"
    TabView {
        id: tabBar
        anchors.top: parent.top
        width: parent.width
        height: parent.height
        currentIndex: 0

        Tab {
            title: qsTr("CreateDeal")
            CreateDeal {

            }
        }
        Tab{
            title: qsTr("DealManager")
            DealManger {
            }
        }

        Tab {
            title: qsTr("Setting")
            Setting {
            }
        }
    }
}
