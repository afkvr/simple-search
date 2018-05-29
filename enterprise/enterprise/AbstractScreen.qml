import QtQuick 2.2
import QtQuick.Window 2.2
import QtQuick.Controls 1.2

// all screens in application must extend AbstractScreen
// contain common property and functions
Rectangle {
    function getNextBottomPosition(item,commonSpacing) {
        if (item == undefined || item == null)
            return 0;

        return item.y + item.height + commonSpacing;
    }

    function getRemainHeight(parent,item,commonSpacing) {
        if (parent == undefined || parent == null)
            return 0;

        if (item == undefined || item == null)
            return 0;

        return parent.height - item.y - item.height - commonSpacing;
    }

    function getNextRightPosition(item) {
        if (item == undefined || item == null)
            return 0;

        return item.x + item.width + 10;
    }

    function getRemainWidth(parent, item, commonSpacing) {
        if (parent == undefined || parent == null)
            return 0;

        if (item == undefined || item == null)
            return 0;

        return parent.width - item.x - item.width - commonSpacing
    }
}
