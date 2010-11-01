#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QtOAuth>
#include <QUrl>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    interface = new QOAuth::Interface(this);

    currentState = Idle;

    ui->setupUi(this);
    resetUi();
    createConnections();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::resetUi()
{
    ui->pushButtonAccessToken->setEnabled(false);
    ui->lineEditConsumerKey->setText(QLatin1String("key"));
    ui->lineEditConsumerSecret->setText(QLatin1String("secret"));
    ui->lineEditRequestURLRequestToken->setText(QLatin1String("http://term.ie/oauth/example/request_token.php"));
    ui->lineEditRequestURLAccessToken->setText(QLatin1String("http://term.ie/oauth/example/access_token.php"));
    ui->lineEditRequestToken->clear();
    ui->lineEditRequestTokenSecret->clear();
    ui->lineEditAccessToken->clear();
    ui->lineEditAccessTokenSecret->clear();
    ui->comboBoxSignatureMethod->setCurrentIndex(0);
    ui->comboBoxHttpMethodRequestToken->setCurrentIndex(0);
    ui->comboBoxHttpMethodAccessToken->setCurrentIndex(0);
}

void MainWindow::clearUi()
{
    ui->pushButtonRequestToken->setEnabled(false);
    ui->pushButtonAccessToken->setEnabled(false);
    ui->lineEditConsumerKey->clear();
    ui->lineEditConsumerSecret->clear();
    ui->lineEditRequestURLRequestToken->clear();
    ui->lineEditRequestURLAccessToken->clear();
    ui->lineEditRequestToken->clear();
    ui->lineEditRequestTokenSecret->clear();
    ui->lineEditAccessToken->clear();
    ui->lineEditAccessTokenSecret->clear();
    ui->comboBoxSignatureMethod->setCurrentIndex(0);
    ui->comboBoxHttpMethodRequestToken->setCurrentIndex(0);
    ui->comboBoxHttpMethodAccessToken->setCurrentIndex(0);
}

void MainWindow::validateUi()
{
    ui->pushButtonRequestToken->setEnabled(!ui->lineEditConsumerKey->text().isEmpty() &&
                                           !ui->lineEditConsumerSecret->text().isEmpty() &&
                                           !ui->lineEditRequestURLRequestToken->text().isEmpty());

    ui->pushButtonAccessToken->setEnabled(currentState != Idle &&
                                          !ui->lineEditConsumerKey->text().isEmpty() &&
                                          !ui->lineEditConsumerSecret->text().isEmpty() &&
                                          !ui->lineEditRequestURLAccessToken->text().isEmpty());
}

void MainWindow::createConnections()
{
    connect(ui->lineEditConsumerKey, SIGNAL(textChanged(QString)), this, SLOT(validateUi()));
    connect(ui->lineEditConsumerSecret, SIGNAL(textChanged(QString)), this, SLOT(validateUi()));
    connect(ui->lineEditRequestURLRequestToken, SIGNAL(textChanged(QString)), this, SLOT(validateUi()));
    connect(ui->lineEditRequestURLAccessToken, SIGNAL(textChanged(QString)), this, SLOT(validateUi()));

    connect(ui->pushButtonClearFields, SIGNAL(clicked()), this, SLOT(clearFields()));
    connect(ui->pushButtonRestoreDefaults, SIGNAL(clicked()), this, SLOT(restoreDefaults()));
    connect(ui->pushButtonQuit, SIGNAL(clicked()), qApp, SLOT(quit()));

    connect(ui->pushButtonRequestToken, SIGNAL(clicked()), this, SLOT(sendRequestToken()));
    connect(ui->pushButtonAccessToken, SIGNAL(clicked()), this, SLOT(sendAccessToken()));

    connect(interface, SIGNAL(requestTokenFinished(QOAuth::ParamMap)), this, SLOT(readRequestReply(QOAuth::ParamMap)));
    connect(interface, SIGNAL(accessTokenFinished(QOAuth::ParamMap)), this, SLOT(readAccessReply(QOAuth::ParamMap)));
}

void MainWindow::clearFields()
{
    clearUi();
    currentState = Idle;
}

void MainWindow::restoreDefaults()
{
    resetUi();
    currentState = Idle;
}

void MainWindow::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
    switch (e->type()) {
    case QEvent::LanguageChange:
        ui->retranslateUi(this);
        break;
    default:
        break;
    }
}

void MainWindow::sendRequestToken()
{
    interface->setConsumerKey(ui->lineEditConsumerKey->text().toLatin1());
    interface->setConsumerSecret(ui->lineEditConsumerSecret->text().toLatin1());
    interface->setSignatureMethod((QOAuth::SignatureMethod) ui->comboBoxSignatureMethod->currentIndex());
    QOAuth::HttpMethod method = (QOAuth::HttpMethod) ui->comboBoxHttpMethodRequestToken->currentIndex();
    QUrl requestUrl = QUrl(ui->lineEditRequestURLRequestToken->text());

    interface->requestToken(requestUrl, method);
}

void MainWindow::readRequestReply(const QOAuth::ParamMap &reply)
{
    ui->lineEditRequestToken->setText(reply.value(QOAuth::tokenParameterName()));
    ui->lineEditRequestTokenSecret->setText(reply.value(QOAuth::tokenSecretParameterName()));

    requestTokenObtained();
}

void MainWindow::requestTokenObtained()
{
    if (currentState == Idle) {
        currentState = RequestTokenObtained;
        ui->pushButtonAccessToken->setEnabled(true);
    }
}

void MainWindow::sendAccessToken()
{
    interface->setConsumerKey(ui->lineEditConsumerKey->text().toLatin1());
    interface->setConsumerSecret(ui->lineEditConsumerSecret->text().toLatin1());
    interface->setSignatureMethod((QOAuth::SignatureMethod) ui->comboBoxSignatureMethod->currentIndex());
    QOAuth::HttpMethod method = (QOAuth::HttpMethod) ui->comboBoxHttpMethodAccessToken->currentIndex();
    QUrl requestUrl = QUrl(ui->lineEditRequestURLAccessToken->text());

    interface->accessToken(requestUrl,
                           method,
                           ui->lineEditRequestToken_2->text().toLatin1(),
                           ui->lineEditRequestTokenSecret_2->text().toLatin1());
}

void MainWindow::readAccessReply(const QOAuth::ParamMap &reply)
{
    ui->lineEditAccessToken->setText(reply.value(QOAuth::tokenParameterName()));
    ui->lineEditAccessTokenSecret->setText(reply.value(QOAuth::tokenSecretParameterName()));

    accessTokenObtained();
}

void MainWindow::accessTokenObtained()
{
    if (currentState == RequestTokenObtained) {
        currentState = AccessTokenObtained;
    }
}

