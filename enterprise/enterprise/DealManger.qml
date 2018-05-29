import QtQuick 2.0

AbstractScreen {
    id: root
    property var dealList: dealInfo.dealData
    property var dealItems: []

    property string dealItemBorderColor: "#5FBA7D"
    property var dealComponent: Qt.createComponent("DealItem.qml")

    Flickable {
        id:flickable
        width: parent.width * 0.95
        height: parent.height * 0.95
        contentHeight: content.height
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        clip:true

        property real spacing: 20
        property real itemWidth: (flickable.width - spacing)/2
        property real itemHeight: (flickable.height - spacing)/2

        Flow {
            id: content
            width: parent.width
            height: 0
            flow: Flow.LeftToRight
            spacing: 5
            property real continuousHeight: 0
        }
    }

    onDealListChanged:  {
        refestDealList()
    }

    Component.onCompleted: {
        dealInfo.updateDealOwnerData()
        dealInfo.updateDealData()
    }

    function refestDealList() {
        for (var i in dealItems)
            dealItems[i].destroy();

        dealItems  = []

        var date;
        for (var j in dealList) {
            var dealItem = dealComponent.createObject(content);
            var dealContent = dealList[j];

            dealItem.timeTxt = dealContent.time
            dealItem.priceTxt = "" + dealContent.price
            dealItem.keywordList = dealContent.keywords
            dealItem.dealOwnerData = dealInfo.getDealOwnerData(dealContent.timestamp)
            dealItem.dealID = dealContent.deal_id
            dealItem.payment_status = dealContent.payment_status

            dealItem.width = flickable.itemWidth
            dealItem.height = flickable.itemHeight
            dealItem.border.color = dealItemBorderColor

            dealItems.push(dealItem);
        }

        var length = 0
        if (dealList !== undefined)
            length = dealList.length;

        // caculate height of content
        content.height = (flickable.itemHeight + flickable.spacing) * (length/2)

        if (length%2) {
            content.height += (flickable.itemHeight + flickable.spacing)
        }

        console.log ("length " + length + " content height " + content.height);
    }
}
