/***************************************************************************
 *   Copyright (C) 2009 by Dominik Kapusta       <d@ayoy.net>              *
 *                                                                         *
 *   This library is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License as        *
 *   published by the Free Software Foundation; either version 2.1 of      *
 *   the License, or (at your option) any later version.                   *
 *                                                                         *
 *   This library is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *
 *   Lesser General Public License for more details.                       *
 *                                                                         *
 *   You should have received a copy of the GNU Lesser General Public      *
 *   License along with this library; if not, write to                     *
 *   the Free Software Foundation, Inc.,                                   *
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA          *
 ***************************************************************************/


#include "ft_interface.h"

#include <QtDebug>
#include <QtNetwork>
#include <QTimer>
#include <QTest>

#include <QtOAuth>
#include <interface_p.h>


bool MyEventLoop::timeout() const
{
    return m_timeout;
}

int MyEventLoop::exec( QEventLoop::ProcessEventsFlags flags )
{
    m_timeout = false;
    return QEventLoop::exec( flags );
}

void MyEventLoop::quitWithTimeout()
{
    QEventLoop::quit();
    m_timeout = true;
}


void QOAuth::Ft_Interface::init()
{
    m = new Interface;
}

void QOAuth::Ft_Interface::cleanup()
{
    delete m;
}

void QOAuth::Ft_Interface::requestToken_data()
{
    QTest::addColumn<uint>("timeout");
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("secret");
    QTest::addColumn<QString>("url");
    QTest::addColumn<int>("httpMethod");
    QTest::addColumn<int>("signMethod");
    QTest::addColumn<int>("error");
    QTest::addColumn<QByteArray>("requestToken");
    QTest::addColumn<QByteArray>("requestTokenSecret");

    // OAuth test server at http://term.ie/oauth/example
    QTest::newRow("HMAC-SHA1") << (uint) 10000
            << QByteArray( "key" )
            << QByteArray( "secret" )
            << QString( "http://term.ie/oauth/example/request_token.php" )
            << (int) GET
            << (int) HMAC_SHA1
            << (int) NoError
            << QByteArray( "requestkey" )
            << QByteArray( "requestsecret" );

    QTest::newRow("PLAINTEXT") << (uint) 10000
            << QByteArray( "key" )
            << QByteArray( "secret" )
            << QString( "http://term.ie/oauth/example/request_token.php" )
            << (int) GET
            << (int) PLAINTEXT
            << (int) NoError
            << QByteArray( "requestkey" )
            << QByteArray( "requestsecret" );

    // timeout seems to be untestable for a moment
    //  QTest::newRow("timeout") << (uint) 100
    //                           << QByteArray( "key" )
    //                           << QByteArray( "secret" )
    //                           << QString( "http://term.ie/oauth/example/request_token.php" )
    //                           << (int) QOAuth::GET
    //                           << (int) QOAuth::HMAC_SHA1
    //                           << (int) QOAuth::Timeout
    //                             << QByteArray()
    //                             << QByteArray();

}

void QOAuth::Ft_Interface::requestToken()
{
    QFETCH( uint, timeout );
    QFETCH( QByteArray, key );
    QFETCH( QByteArray, secret );
    QFETCH( QString, url );
    QFETCH( int, httpMethod );
    QFETCH( int, signMethod );
    QFETCH( int, error );
    QFETCH( QByteArray, requestToken );
    QFETCH( QByteArray, requestTokenSecret );

    m->setRequestTimeout( timeout );
    m->setConsumerKey( key );
    m->setConsumerSecret( secret );
    ParamMap map = m->requestToken( url, (HttpMethod) httpMethod, (SignatureMethod) signMethod );

    if ( m->error() != QOAuth::Timeout ) {
        QVERIFY( m->error() == error );
    } else {
        QWARN( "Request timeout" );
    }

    //check the reply if request finished with no errors
    if ( m->error() == NoError ) {
        QCOMPARE( map.value( tokenParameterName() ), requestToken );
        QCOMPARE( map.value( tokenSecretParameterName() ), requestTokenSecret );
    }
}

void QOAuth::Ft_Interface::requestTokenRSA_data()
{
    QTest::addColumn<uint>("timeout");
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("secret");
    QTest::addColumn<QString>("rsaKeyFile");
    QTest::addColumn<QString>("url");
    QTest::addColumn<int>("httpMethod");
    QTest::addColumn<int>("signMethod");
    QTest::addColumn<int>("error");
    QTest::addColumn<QByteArray>("requestToken");
    QTest::addColumn<QByteArray>("requestTokenSecret");

    // OAuth test server at http://term.ie/oauth/example
    QTest::newRow("noError") << (uint) 10000
            << QByteArray( "key" )
            << QByteArray( "secret" )
            << QString( "rsa-testkey.pem" )
            << QString( "http://term.ie/oauth/example/request_token.php" )
            << (int) GET
            << (int) RSA_SHA1
            << (int) NoError
            << QByteArray( "requestkey" )
            << QByteArray( "requestsecret" );
}

void QOAuth::Ft_Interface::requestTokenRSA()
{
    QFETCH( uint, timeout );
    QFETCH( QByteArray, key );
    QFETCH( QByteArray, secret );
    QFETCH( QString, rsaKeyFile );
    QFETCH( QString, url );
    QFETCH( int, httpMethod );
    QFETCH( int, signMethod );
    QFETCH( int, error );
    QFETCH( QByteArray, requestToken );
    QFETCH( QByteArray, requestTokenSecret );

    m->setRequestTimeout( timeout );
    m->setConsumerKey( key );
    m->setConsumerSecret( secret );
    m->setRSAPrivateKeyFromFile( rsaKeyFile );
    ParamMap map = m->requestToken( url, (HttpMethod) httpMethod, (SignatureMethod) signMethod );

    if ( m->error() != QOAuth::Timeout ) {
        QVERIFY( m->error() == error );
    } else {
        QWARN( "Request timeout" );
    }

    //check the reply if request finished with no errors
    if ( m->error() == NoError ) {
        QCOMPARE( map.value( tokenParameterName() ), requestToken );
        QCOMPARE( map.value( tokenSecretParameterName() ), requestTokenSecret );
    }
}


void QOAuth::Ft_Interface::accessToken_data()
{
    QTest::addColumn<uint>("timeout");
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("secret");
    QTest::addColumn<QByteArray>("token");
    QTest::addColumn<QByteArray>("tokenSecret");
    QTest::addColumn<QString>("url");
    QTest::addColumn<int>("httpMethod");
    QTest::addColumn<int>("signMethod");
    QTest::addColumn<int>("error");
    QTest::addColumn<QByteArray>("accessToken");
    QTest::addColumn<QByteArray>("accessTokenSecret");

    // OAuth test server at http://term.ie/oauth/example
    QTest::newRow("HMAC-SHA1") << (uint) 10000
            << QByteArray( "key" )
            << QByteArray( "secret" )
            << QByteArray( "requestkey" )
            << QByteArray( "requestsecret" )
            << QString( "http://term.ie/oauth/example/access_token.php" )
            << (int) GET
            << (int) HMAC_SHA1
            << (int) NoError
            << QByteArray( "accesskey" )
            << QByteArray( "accesssecret" );

    QTest::newRow("PLAINTEXT") << (uint) 10000
            << QByteArray( "key" )
            << QByteArray( "secret" )
            << QByteArray( "requestkey" )
            << QByteArray( "requestsecret" )
            << QString( "http://term.ie/oauth/example/access_token.php" )
            << (int) GET
            << (int) PLAINTEXT
            << (int) NoError
            << QByteArray( "accesskey" )
            << QByteArray( "accesssecret" );
}

void QOAuth::Ft_Interface::accessToken()
{
    QFETCH( uint, timeout );
    QFETCH( QByteArray, key );
    QFETCH( QByteArray, secret );
    QFETCH( QByteArray, token );
    QFETCH( QByteArray, tokenSecret );
    QFETCH( QString, url );
    QFETCH( int, httpMethod );
    QFETCH( int, signMethod );
    QFETCH( int, error );
    QFETCH( QByteArray, accessToken );
    QFETCH( QByteArray, accessTokenSecret );

    m->setRequestTimeout( timeout );
    m->setConsumerKey( key );
    m->setConsumerSecret( secret );
    ParamMap map = m->accessToken( url, (HttpMethod) httpMethod, token, tokenSecret,
                                   (SignatureMethod) signMethod );

    if ( m->error() != QOAuth::Timeout ) {
        QVERIFY( m->error() == error );
    } else {
        QWARN( "Request timeout" );
    }

    //check the reply if request finished with no errors
    if ( m->error() == NoError ) {
        QCOMPARE( map.value( tokenParameterName() ), accessToken );
        QCOMPARE( map.value( tokenSecretParameterName() ), accessTokenSecret );
    }
}


void QOAuth::Ft_Interface::accessTokenRSA_data()
{
    QTest::addColumn<uint>("timeout");
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("secret");
    QTest::addColumn<QByteArray>("token");
    QTest::addColumn<QByteArray>("tokenSecret");
    QTest::addColumn<QString>("rsaKeyFile");
    QTest::addColumn<QString>("url");
    QTest::addColumn<int>("httpMethod");
    QTest::addColumn<int>("signMethod");
    QTest::addColumn<int>("error");
    QTest::addColumn<QByteArray>("accessToken");
    QTest::addColumn<QByteArray>("accessTokenSecret");

    // OAuth test server at http://term.ie/oauth/example
    QTest::newRow("noError") << (uint) 10000
            << QByteArray( "key" )
            << QByteArray( "secret" )
            << QByteArray( "requestkey" )
            << QByteArray( "requestsecret" )
            << QString( "rsa-testkey.pem" )
            << QString( "http://term.ie/oauth/example/access_token.php" )
            << (int) GET
            << (int) RSA_SHA1
            << (int) NoError
            << QByteArray( "accesskey" )
            << QByteArray( "accesssecret" );

}

void QOAuth::Ft_Interface::accessTokenRSA()
{
    QFETCH( uint, timeout );
    QFETCH( QByteArray, key );
    QFETCH( QByteArray, secret );
    QFETCH( QByteArray, token );
    QFETCH( QByteArray, tokenSecret );
    QFETCH( QString, rsaKeyFile );
    QFETCH( QString, url );
    QFETCH( int, httpMethod );
    QFETCH( int, signMethod );
    QFETCH( int, error );
    QFETCH( QByteArray, accessToken );
    QFETCH( QByteArray, accessTokenSecret );

    m->setRequestTimeout( timeout );
    m->setConsumerKey( key );
    m->setConsumerSecret( secret );
    m->setRSAPrivateKeyFromFile( rsaKeyFile );
    ParamMap map = m->accessToken( url, (HttpMethod) httpMethod, token, tokenSecret,
                                   (SignatureMethod) signMethod );

    if ( m->error() != QOAuth::Timeout ) {
        QVERIFY( m->error() == error );
    } else {
        QWARN( "Request timeout" );
    }

    //check the reply if request finished with no errors
    if ( m->error() == NoError ) {
        QCOMPARE( map.value( tokenParameterName() ), accessToken );
        QCOMPARE( map.value( tokenSecretParameterName() ), accessTokenSecret );
    }
}


void QOAuth::Ft_Interface::accessResources_data()
{
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("secret");
    QTest::addColumn<QByteArray>("token");
    QTest::addColumn<QByteArray>("tokenSecret");
    QTest::addColumn<QString>("url");
    QTest::addColumn<int>("httpMethod");
    QTest::addColumn<int>("signMethod");
    QTest::addColumn<QByteArray>("param1");
    QTest::addColumn<QByteArray>("value1");
    QTest::addColumn<QByteArray>("param2");
    QTest::addColumn<QByteArray>("value2");
    QTest::addColumn<QByteArray>("param3");
    QTest::addColumn<QByteArray>("value3");
    QTest::addColumn<int>("parsingMode");
    QTest::addColumn<int>("error");

    // OAuth test server at http://term.ie/oauth/example
    QTest::newRow("HMAC-SHA1") << QByteArray( "key" )
            << QByteArray( "secret" )
            << QByteArray( "accesskey" )
            << QByteArray( "accesssecret" )
            << QString( "http://term.ie/oauth/example/echo_api.php" )
            << (int) GET
            << (int) HMAC_SHA1
            << QByteArray( "first" )
            << QByteArray( "first" )
            << QByteArray( "second" )
            << QByteArray( "second" )
            << QByteArray( "third" )
            << QByteArray( "third" )
            << (int) ParseForHeaderArguments
            << (int) NoError;

    QTest::newRow("PLAINTEXT") << QByteArray( "key" )
            << QByteArray( "secret" )
            << QByteArray( "accesskey" )
            << QByteArray( "accesssecret" )
            << QString( "http://term.ie/oauth/example/echo_api.php" )
            << (int) GET
            << (int) PLAINTEXT
            << QByteArray( "first" )
            << QByteArray( "first" )
            << QByteArray( "second" )
            << QByteArray( "second" )
            << QByteArray( "third" )
            << QByteArray( "third" )
            << (int) ParseForHeaderArguments
            << (int) NoError;
}

void QOAuth::Ft_Interface::accessResources()
{
    QFETCH( QByteArray, key );
    QFETCH( QByteArray, secret );
    QFETCH( QByteArray, token );
    QFETCH( QByteArray, tokenSecret );
    QFETCH( QString, url );
    QFETCH( int, httpMethod );
    QFETCH( int, signMethod );
    QFETCH( QByteArray, param1 );
    QFETCH( QByteArray, value1 );
    QFETCH( QByteArray, param2 );
    QFETCH( QByteArray, value2 );
    QFETCH( QByteArray, param3 );
    QFETCH( QByteArray, value3 );
    QFETCH( int, parsingMode );
    QFETCH( int, error );

    m->setConsumerKey( key );
    m->setConsumerSecret( secret );

    ParamMap map;
    map.insert( param1, value1 );
    map.insert( param2, value2 );
    map.insert( param3, value3 );

    QByteArray parameters = m->createParametersString( url, (HttpMethod) httpMethod, token, tokenSecret,
                                                       (SignatureMethod) signMethod, map, (ParsingMode) parsingMode );

    url.append( m->inlineParameters( map, ParseForInlineQuery ) );

    QNetworkAccessManager manager;
    MyEventLoop loop;

    connect( &manager, SIGNAL(finished(QNetworkReply*)), &loop, SLOT(quit()) );
    QTimer::singleShot( 10000, &loop, SLOT(quitWithTimeout()) );

    QNetworkRequest rq;
    rq.setUrl( QUrl( url ) );
    rq.setRawHeader( "Authorization", parameters );

    QNetworkReply *reply = manager.get( rq );
    loop.exec();

    if ( loop.timeout() ) {
        QWARN( "Request timeout" );
    } else {
        ParamMap replyMap = m->d_ptr->replyToMap( reply->readAll() );

        QCOMPARE( replyMap.value( param1 ), value1.toPercentEncoding() );
        QCOMPARE( replyMap.value( param2 ), value2.toPercentEncoding() );
        QCOMPARE( replyMap.value( param3 ), value3.toPercentEncoding() );

        QVERIFY( m->error() == error );
    }
}

void QOAuth::Ft_Interface::accessResourcesRSA_data()
{
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("secret");
    QTest::addColumn<QByteArray>("token");
    QTest::addColumn<QByteArray>("tokenSecret");
    QTest::addColumn<QString>("rsaKeyFile");
    QTest::addColumn<QString>("url");
    QTest::addColumn<int>("httpMethod");
    QTest::addColumn<int>("signMethod");
    QTest::addColumn<QByteArray>("param1");
    QTest::addColumn<QByteArray>("value1");
    QTest::addColumn<QByteArray>("param2");
    QTest::addColumn<QByteArray>("value2");
    QTest::addColumn<QByteArray>("param3");
    QTest::addColumn<QByteArray>("value3");
    QTest::addColumn<int>("parsingMode");
    QTest::addColumn<int>("error");

    // OAuth test server at http://term.ie/oauth/example
    QTest::newRow("noError") << QByteArray( "key" )
            << QByteArray( "secret" )
            << QByteArray( "accesskey" )
            << QByteArray( "accesssecret" )
            << QString( "rsa-testkey.pem" )
            << QString( "http://term.ie/oauth/example/echo_api.php" )
            << (int) GET
            << (int) RSA_SHA1
            << QByteArray( "first" )
            << QByteArray( "first" )
            << QByteArray( "second" )
            << QByteArray( "second" )
            << QByteArray( "third" )
            << QByteArray( "third" )
            << (int) ParseForHeaderArguments
            << (int) NoError;
}

void QOAuth::Ft_Interface::accessResourcesRSA()
{
    QFETCH( QByteArray, key );
    QFETCH( QByteArray, secret );
    QFETCH( QByteArray, token );
    QFETCH( QByteArray, tokenSecret );
    QFETCH( QString, rsaKeyFile );
    QFETCH( QString, url );
    QFETCH( int, httpMethod );
    QFETCH( int, signMethod );
    QFETCH( QByteArray, param1 );
    QFETCH( QByteArray, value1 );
    QFETCH( QByteArray, param2 );
    QFETCH( QByteArray, value2 );
    QFETCH( QByteArray, param3 );
    QFETCH( QByteArray, value3 );
    QFETCH( int, parsingMode );
    QFETCH( int, error );

    m->setConsumerKey( key );
    m->setConsumerSecret( secret );
    m->setRSAPrivateKeyFromFile( rsaKeyFile );

    ParamMap map;
    map.insert( param1, value1 );
    map.insert( param2, value2 );
    map.insert( param3, value3 );

    QByteArray parameters = m->createParametersString( url, (HttpMethod) httpMethod, token, tokenSecret,
                                                       (SignatureMethod) signMethod, map, (ParsingMode) parsingMode );

    url.append( m->inlineParameters( map, ParseForInlineQuery ) );

    QNetworkAccessManager manager;
    MyEventLoop loop;

    connect( &manager, SIGNAL(finished(QNetworkReply*)), &loop, SLOT(quit()) );
    QTimer::singleShot( 10000, &loop, SLOT(quitWithTimeout()) );

    QNetworkRequest rq;
    rq.setUrl( QUrl( url ) );
    rq.setRawHeader( "Authorization", parameters );

    QNetworkReply *reply = manager.get( rq );
    loop.exec();

    if ( loop.timeout() ) {
        QWARN( "Request timeout" );
    } else {
        ParamMap replyMap = m->d_ptr->replyToMap( reply->readAll() );

        QCOMPARE( replyMap.value( param1 ), value1.toPercentEncoding() );
        QCOMPARE( replyMap.value( param2 ), value2.toPercentEncoding() );
        QCOMPARE( replyMap.value( param3 ), value3.toPercentEncoding() );

        QVERIFY( m->error() == error );
    }
}


QTEST_MAIN(QOAuth::Ft_Interface)
