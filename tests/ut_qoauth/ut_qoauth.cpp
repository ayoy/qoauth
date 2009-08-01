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


#include "ut_qoauth.h"

#include <QtDebug>
#include <QTest>

#include "qoauth.h"
#include "qoauth_p.h"


void QOAuth::Ut_QOAuth::init()
{
  m = new QOAuth;
}

void QOAuth::Ut_QOAuth::cleanup()
{
  delete m;
}

void QOAuth::Ut_QOAuth::constructor()
{
  QVERIFY( m );
  QVERIFY( m->consumerKey().isEmpty() );
  QVERIFY( m->consumerSecret().isEmpty() );
  QVERIFY( m->error() == NoError );
  QVERIFY( m->requestTimeout() == 0 );
  QVERIFY( m->d_ptr );
}

void QOAuth::Ut_QOAuth::consumerKey()
{
  QByteArray consumerKey( "6d65216f4272d0d3932cdcf8951997c2" );

  m->d_ptr->consumerKey = consumerKey;
  QCOMPARE( m->consumerKey(), consumerKey );
}

void QOAuth::Ut_QOAuth::setConsumerKey()
{
  QByteArray consumerKey( "6d65216f4272d0d3932cdcf8951997c2" );

  m->setConsumerKey( consumerKey );
  QCOMPARE( m->d_ptr->consumerKey, consumerKey );
}

void QOAuth::Ut_QOAuth::consumerSecret()
{
  QByteArray consumerSecret( "5af4e09d887c4969211ba40e9dd8f873" );

  m->d_ptr->consumerSecret = consumerSecret;
  QCOMPARE( m->consumerSecret(), consumerSecret );
}

void QOAuth::Ut_QOAuth::setConsumerSecret()
{
  QByteArray consumerSecret( "5af4e09d887c4969211ba40e9dd8f873" );

  m->setConsumerSecret( consumerSecret );
  QCOMPARE( m->d_ptr->consumerSecret, consumerSecret );
}

void QOAuth::Ut_QOAuth::requestTimeout()
{
  uint timeout = 13986754;

  m->d_ptr->requestTimeout = timeout;
  QVERIFY( m->requestTimeout() == timeout );
}

void QOAuth::Ut_QOAuth::setRequestTimeout()
{
  uint timeout = 13986754;

  m->setRequestTimeout( timeout );
  QVERIFY( m->d_ptr->requestTimeout == timeout );
}

void QOAuth::Ut_QOAuth::error()
{
  m->d_ptr->error = Forbidden;
  QVERIFY( m->error() == Forbidden );
}

void QOAuth::Ut_QOAuth::requestToken_data()
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


  QTest::newRow("key empty") << (uint) 0
                             << QByteArray()
                             << QByteArray( "135432" )
                             << QString( "http://wtf&(^%)$&#.com" )
                             << (int) GET
                             << (int) HMAC_SHA1
                             << (int) ConsumerKeyEmpty
                             << QByteArray()
                             << QByteArray();


  QTest::newRow("secret empty") << (uint) 0
                                << QByteArray( "135432" )
                                << QByteArray()
                                << QString( "http://wtf&(^%)$&#.com" )
                                << (int) GET
                                << (int) HMAC_SHA1
                                << (int) ConsumerSecretEmpty
                                << QByteArray()
                                << QByteArray();

  QTest::newRow("httpMethod") << (uint) 0
                              << QByteArray( "135432" )
                              << QByteArray( "654316" )
                              << QString( "http://wtf&(^%)$&#.com" )
                              << (int) DELETE
                              << (int) HMAC_SHA1
                              << (int) UnsupportedHttpMethod
                              << QByteArray()
                              << QByteArray();

  QTest::newRow("signMethod") << (uint) 0
                              << QByteArray( "135432" )
                              << QByteArray( "654316" )
                              << QString( "http://wtf&(^%)$&#.com" )
                              << (int) GET
                              << 8
                              << (int) UnsupportedSignatureMethod
                              << QByteArray()
                              << QByteArray();

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

void QOAuth::Ut_QOAuth::requestToken()
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

  QVERIFY( m->error() == error );

  //check the reply if request finished with no errors
  if ( m->error() == NoError ) {
    QCOMPARE( map.value( tokenParameterName() ), requestToken );
    QCOMPARE( map.value( tokenSecretParameterName() ), requestTokenSecret );
  }
}

void QOAuth::Ut_QOAuth::accessToken_data()
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

  QTest::newRow("key empty") << (uint) 0
                             << QByteArray()
                             << QByteArray( "135432" )
                             << QByteArray( "token" )
                             << QByteArray( "tokensecret" )
                             << QString( "http://wtf&(^%)$&#.com" )
                             << (int) GET
                             << (int) HMAC_SHA1
                             << (int) ConsumerKeyEmpty
                             << QByteArray()
                             << QByteArray();


  QTest::newRow("secret empty") << (uint) 0
                                << QByteArray( "135432" )
                                << QByteArray()
                                << QByteArray( "token" )
                                << QByteArray( "tokensecret" )
                                << QString( "http://wtf&(^%)$&#.com" )
                                << (int) GET
                                << (int) HMAC_SHA1
                                << (int) ConsumerSecretEmpty
                                << QByteArray()
                                << QByteArray();

  QTest::newRow("httpMethod") << (uint) 0
                              << QByteArray( "135432" )
                              << QByteArray( "654316" )
                              << QByteArray( "token" )
                              << QByteArray( "tokensecret" )
                              << QString( "http://wtf&(^%)$&#.com" )
                              << (int) DELETE
                              << (int) HMAC_SHA1
                              << (int) UnsupportedHttpMethod
                              << QByteArray()
                              << QByteArray();

  QTest::newRow("signMethod") << (uint) 0
                              << QByteArray( "135432" )
                              << QByteArray( "654316" )
                              << QByteArray( "token" )
                              << QByteArray( "tokensecret" )
                              << QString( "http://wtf&(^%)$&#.com" )
                              << (int) GET
                              << 8
                              << (int) UnsupportedSignatureMethod
                              << QByteArray()
                              << QByteArray();

}

void QOAuth::Ut_QOAuth::accessToken()
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

  QVERIFY( m->error() == error );

  //check the reply if request finished with no errors
  if ( m->error() == NoError ) {
    QCOMPARE( map.value( tokenParameterName() ), accessToken );
    QCOMPARE( map.value( tokenSecretParameterName() ), accessTokenSecret );
  }
}

void QOAuth::Ut_QOAuth::createParametersString_data()
{
  QTest::addColumn<uint>("timeout");
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

  QTest::newRow("key empty") << (uint) 0
                             << QByteArray()
                             << QByteArray( "135432" )
                             << QByteArray( "token" )
                             << QByteArray( "tokensecret" )
                             << QString( "http://wtf&(^%)$&#.com" )
                             << (int) GET
                             << (int) HMAC_SHA1
                             << QByteArray()
                             << QByteArray()
                             << QByteArray()
                             << QByteArray()
                             << QByteArray()
                             << QByteArray()
                             << (int) ParseForInlineQuery
                             << (int) ConsumerKeyEmpty;


  QTest::newRow("secret empty") << (uint) 0
                                << QByteArray( "135432" )
                                << QByteArray()
                                << QByteArray( "token" )
                                << QByteArray( "tokensecret" )
                                << QString( "http://wtf&(^%)$&#.com" )
                                << (int) GET
                                << (int) HMAC_SHA1
                                << QByteArray()
                                << QByteArray()
                                << QByteArray()
                                << QByteArray()
                                << QByteArray()
                                << QByteArray()
                                << (int) ParseForInlineQuery
                                << (int) ConsumerSecretEmpty;

  QTest::newRow("signMethod") << (uint) 0
                              << QByteArray( "135432" )
                              << QByteArray( "654316" )
                              << QByteArray( "token" )
                              << QByteArray( "tokensecret" )
                              << QString( "http://wtf&(^%)$&#.com" )
                              << (int) GET
                              << 8
                              << QByteArray()
                              << QByteArray()
                              << QByteArray()
                              << QByteArray()
                              << QByteArray()
                              << QByteArray()
                              << (int) ParseForInlineQuery
                              << (int) UnsupportedSignatureMethod;


}

void QOAuth::Ut_QOAuth::createParametersString()
{
  QFETCH( uint, timeout );
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

  m->setRequestTimeout( timeout );
  m->setConsumerKey( key );
  m->setConsumerSecret( secret );
  ParamMap map;
  map.insert( param1, value1 );
  map.insert( param2, value2 );
  map.insert( param3, value3 );
  QByteArray parameters = m->createParametersString( url, (HttpMethod) httpMethod, token, tokenSecret,
                                                    (SignatureMethod) signMethod, map, (ParsingMode) parsingMode );

  QVERIFY( m->error() == error );
}

void QOAuth::Ut_QOAuth::inlineParameters_data()
{
  QTest::addColumn<QByteArray>("par1");
  QTest::addColumn<QByteArray>("val1");
  QTest::addColumn<QByteArray>("par2");
  QTest::addColumn<QByteArray>("val2");
  QTest::addColumn<QByteArray>("par3");
  QTest::addColumn<QByteArray>("val3");
  QTest::addColumn<int>("mode");
  QTest::addColumn<QByteArray>("result");

  QTest::newRow("empty") << QByteArray()
                         << QByteArray()
                         << QByteArray()
                         << QByteArray()
                         << QByteArray()
                         << QByteArray()
                         << (int) ParseForInlineQuery
                         << QByteArray( "?=&=&=" );

  QTest::newRow("easy") << QByteArray( "one" )
                        << QByteArray( "two" )
                        << QByteArray( "three" )
                        << QByteArray( "four" )
                        << QByteArray( "six" )
                        << QByteArray( "ten" )
                        << (int) ParseForRequestContent
                        << QByteArray( "one=two&six=ten&three=four" );

  QTest::newRow("tricky") << QByteArray( "arg1" )
                          << QByteArray( "%%**_+%%" )
                          << QByteArray( "arg2" )
                          << QByteArray()
                          << QByteArray( "arg2" )
                          << QByteArray( "&+=" )
                          << (int) ParseForInlineQuery
                          << QByteArray( "?arg1=%%**_+%%&arg2=&arg2=&+=" );

  QTest::newRow("wrong mode") << QByteArray( "arg1" )
                              << QByteArray( "%%**_+%%" )
                              << QByteArray( "arg2" )
                              << QByteArray()
                              << QByteArray( "arg2" )
                              << QByteArray( "&+=" )
                              << (int) ParseForHeaderArguments
                              << QByteArray( "" );

}

void QOAuth::Ut_QOAuth::inlineParameters()
{
  QFETCH( QByteArray, par1 );
  QFETCH( QByteArray, val1 );
  QFETCH( QByteArray, par2 );
  QFETCH( QByteArray, val2 );
  QFETCH( QByteArray, par3 );
  QFETCH( QByteArray, val3 );
  QFETCH( int, mode );
  QFETCH( QByteArray, result );

  ParamMap map;

  map.insert( par1, val1 );
  map.insert( par2, val2 );
  map.insert( par3, val3 );

  QByteArray query = m->inlineParameters( map, (ParsingMode) mode );

  QCOMPARE( query, result );
}

void QOAuth::Ut_QOAuth::setRSAPrivateKey_data()
{
  QTest::addColumn<QString>("key");
  QTest::addColumn<int>("error");

  QTest::newRow("correct")   <<
"-----BEGIN PRIVATE KEY-----\n"
"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V\n"
"A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d\n"
"7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ\n"
"hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H\n"
"X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm\n"
"uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw\n"
"rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z\n"
"zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn\n"
"qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG\n"
"WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno\n"
"cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+\n"
"3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8\n"
"AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54\n"
"Lw03eHTNQghS0A==\n"
"-----END PRIVATE KEY-----" << (int) NoError;
  QTest::newRow("empty key") << ""  << (int) ErrorDecode;

}

void QOAuth::Ut_QOAuth::setRSAPrivateKey()
{
  QFETCH( QString, key );
  QFETCH( int, error );

  m->setRSAPrivateKey( key );
  QCOMPARE( m->error(), error );
}

void QOAuth::Ut_QOAuth::setRSAPrivateKeyFromFile_data()
{
  QTest::addColumn<QString>("file");
  QTest::addColumn<int>("error");

  QTest::newRow("correct")           << "rsa-testkey.pem" << (int) NoError;
  QTest::newRow("empty file")        << "empty.file"      << (int) ErrorDecode;
  QTest::newRow("non-existent file") << "nosuch.file"     << (int) ErrorFile;

}

void QOAuth::Ut_QOAuth::setRSAPrivateKeyFromFile()
{
  QFETCH( QString, file );
  QFETCH( int, error );

  m->setRSAPrivateKeyFromFile( file );
  QCOMPARE( m->error(), error );
}


QTEST_MAIN(QOAuth::Ut_QOAuth)
