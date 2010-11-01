#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtOAuth>

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

protected:
    void changeEvent(QEvent *e);

private slots:
    void sendRequestToken();
    void sendAccessToken();
    void readRequestReply(const QOAuth::ParamMap &reply);
    void readAccessReply(const QOAuth::ParamMap &reply);

    void validateUi();

    void restoreDefaults();
    void clearFields();

private:
    void requestTokenObtained();
    void accessTokenObtained();

    enum State {
        Idle,
        RequestTokenObtained,
        AccessTokenObtained
    };

    State currentState;

    void clearUi();
    void resetUi();
    void createConnections();
    Ui::MainWindow *ui;
    QOAuth::Interface *interface;
};

#endif // MAINWINDOW_H
