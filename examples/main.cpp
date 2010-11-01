#include <QApplication>
#include "mainwindow.h"

int main(int argc, char **argv)
{
    QApplication app(argc, argv);

    MainWindow win;
    win.show();

    return app.exec();
}
