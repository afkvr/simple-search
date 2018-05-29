#include "keymanager.h"
#include "mainwindow.h"
#include <QGuiApplication>
#include <QQmlContext>
#include <QQmlApplicationEngine>
#include <QDir>
#include <QString>

#include "dealmanager.h"

int main(int argc, char *argv[])
{
    //QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    //QCoreApplication::addLibraryPath("./");
    QGuiApplication app (argc, argv);

    QQmlApplicationEngine engine;

    MainWindow* mainWindow = new MainWindow();

    engine.load(QUrl(QStringLiteral("qrc:/main.qml")));
    if (engine.rootObjects().isEmpty())
        return -1;

    // Register qml Type
    QQmlContext* context = engine.rootContext();

    context->setContextProperty("account", mainWindow);
    context->setContextProperty("dealInfo", DealManager::getInstance());

    QString uriStr = "Manager";
    QByteArray ba = uriStr.toLatin1();
    const char *uri = ba.data();

    return app.exec();
}
