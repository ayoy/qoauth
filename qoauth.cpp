/***************************************************************************
 *   Copyright (C) 2008-2009 by Dominik Kapusta       <d@ayoy.net>         *
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


#include "qoauth.h"
#include "qoauth_p.h"

#include <QtCrypto>

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QDateTime>
#include <QtDebug>
#include <QEventLoop>
#include <QTimer>

const QByteArray QOAuth::OAuthVersion = "1.0";

const QNetworkRequest::Attribute QOAuthPrivate::RequestType =
    (QNetworkRequest::Attribute) QNetworkRequest::User;


const QByteArray QOAuth::ParamConsumerKey     = "oauth_consumer_key";
const QByteArray QOAuth::ParamNonce           = "oauth_nonce";
const QByteArray QOAuth::ParamSignature       = "oauth_signature";
const QByteArray QOAuth::ParamSignatureMethod = "oauth_signature_method";
const QByteArray QOAuth::ParamTimestamp       = "oauth_timestamp";
const QByteArray QOAuth::ParamVersion         = "oauth_version";
const QByteArray QOAuth::ParamToken           = "oauth_token";
const QByteArray QOAuth::ParamTokenSecret     = "oauth_token_secret";
const QByteArray QOAuth::ParamAccessToken     = "oauth_access_token";

QOAuthPrivate::QOAuthPrivate( QObject *parent ) :
    QObject( parent ),
    consumerKey( QByteArray() ),
    consumerSecret( QByteArray() ),
    accessToken( QByteArray() ),
    manager( new QNetworkAccessManager( this ) ),
    loop( new QEventLoop( this ) ),
    error( QOAuth::NoError )
{
  connect( manager, SIGNAL(finished(QNetworkReply*)), loop, SLOT(quit()) );
  connect( manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(parseReply(QNetworkReply*)) );
}

QByteArray QOAuthPrivate::httpMethodToString( QOAuth::HttpMethod method )
{
  switch ( method ) {
  case QOAuth::GET:
    return "GET";
  case QOAuth::POST:
    return "POST";
  default:
    qWarning() << __PRETTY_FUNCTION__ << "Unrecognized method";
    return QByteArray();
  }
}

QByteArray QOAuthPrivate::signatureMethodToString( QOAuth::SignatureMethod method )
{
  switch ( method ) {
  case QOAuth::HMAC_SHA1:
    return "HMAC-SHA1";
  case QOAuth::RSA_SHA1:
    return "RSA-SHA1";
  case QOAuth::PLAINTEXT:
    return "PLAINTEXT";
  default:
    qWarning() << __PRETTY_FUNCTION__ << "Unrecognized method";
    return QByteArray();
  }
}

QOAuth::ParamMap QOAuthPrivate::replyToMap( const QByteArray &data )
{
  // split reply to name=value strings
  QList<QByteArray> replyParams = data.split( '&' );
  // we'll store them in a map
  QOAuth::ParamMap parameters;

  QByteArray replyParam;
  QByteArray key;
  int separatorIndex;

  // iterate through name=value pairs
  foreach ( replyParam, replyParams ) {
    // find occurrence of '='
    separatorIndex = replyParam.indexOf( '=' );
    // key is on the left
    key = replyParam.left( separatorIndex );
    // value is on the right
    parameters.insert( key , replyParam.right( replyParam.length() - separatorIndex - 1 ) );
  }

  return parameters;
}

void QOAuthPrivate::parseReply( QNetworkReply *reply )
{
  int returnCode = reply->attribute( QNetworkRequest::HttpStatusCodeAttribute ).toInt();

  switch ( returnCode ) {
  case QOAuth::NoError:
    replyParams = replyToMap( reply->readAll() );
    if ( !replyParams.contains( QOAuth::ParamToken ) ) {
      qWarning() << __PRETTY_FUNCTION__ << "oauth_token not present in reply!";
    }
    if ( !replyParams.contains( QOAuth::ParamTokenSecret ) ) {
      qWarning() << __PRETTY_FUNCTION__ << "oauth_token_secret not present in reply!";
    }

  case QOAuth::BadRequest:
  case QOAuth::Unauthorized:
  case QOAuth::Forbidden:
    error = returnCode;
    break;
  default:
    error = QOAuth::OtherError;
  }

  reply->close();
}

QByteArray QOAuthPrivate::paramsToString( const QOAuth::ParamMap &parameters, QOAuth::ParsingMode mode )
{
  QByteArray middleString;
  QByteArray endString;
  switch ( mode ) {
  // equals to QOAuth::ParseForInlineQuery
  case QOAuth::ParseForSignatureBaseString:
    middleString = "=";
    endString = "&";
    break;
  case QOAuth::ParseForHeaderArguments:
    middleString = "=\"";
    endString = "\",";
    break;
  default:
    qWarning() << __PRETTY_FUNCTION__ << "Unrecognized mode";
    return QByteArray();
  }

  QByteArray parameter;
  QByteArray parametersString;

  foreach( parameter, parameters.uniqueKeys() ) {
    QList<QByteArray> values = parameters.values( parameter );
    if ( values.size() > 1 ) {
      qSort( values.begin(), values.end() );
    }
    QByteArray value;
    foreach ( value, values ) {
      parametersString.append( parameter );
      parametersString.append( middleString );
      parametersString.append( value );
      parametersString.append( endString );
    }
  }
  parametersString.chop(1);

  return parametersString;
}


QOAuth::QOAuth( QObject *parent ) :
    QObject( parent ),
    d_ptr( new QOAuthPrivate( this ) )
{
  Q_D(QOAuth);

  d->q_ptr = this;
}

QOAuth::~QOAuth()
{
}

QByteArray QOAuth::consumerKey() const
{
  Q_D(const QOAuth);

  return d->consumerKey;
}

void QOAuth::setConsumerKey( const QByteArray &consumerKey )
{
  Q_D(QOAuth);

  d->consumerKey = consumerKey;
}

QByteArray QOAuth::consumerSecret() const
{
  Q_D(const QOAuth);

  return d->consumerSecret;
}

void QOAuth::setConsumerSecret( const QByteArray &consumerSecret )
{
  Q_D(QOAuth);

  d->consumerSecret = consumerSecret;
}

int QOAuth::error() const
{
  Q_D(const QOAuth);

  return d->error;
}

QOAuth::ParamMap QOAuth::requestToken( const QString &requestUrl, HttpMethod httpMethod, SignatureMethod signatureMethod,
                                       uint timeout, const ParamMap &params )
{
  Q_D(QOAuth);

  return d->sendRequest( requestUrl, httpMethod, signatureMethod,
                         QByteArray(), QByteArray(), timeout, params );
}

QOAuth::ParamMap QOAuth::accessToken( const QString &requestUrl, HttpMethod httpMethod, SignatureMethod signatureMethod,
                                      const QByteArray &token, const QByteArray &tokenSecret,
                                      uint timeout, const ParamMap &params )
{
  Q_D(QOAuth);

  return d->sendRequest( requestUrl, httpMethod, signatureMethod,
                         token, tokenSecret, timeout, params );

}

QOAuth::ParamMap QOAuthPrivate::sendRequest( const QString &requestUrl, QOAuth::HttpMethod httpMethod, QOAuth::SignatureMethod signatureMethod,
                                             const QByteArray &token, const QByteArray &tokenSecret,
                                             uint timeout, const QOAuth::ParamMap &params )
{
  if ( consumerKey.isEmpty() ) {
    qWarning() << __PRETTY_FUNCTION__ << "consumer key is empty, make sure that you set it with QOAuth::setConsumerKey()";
    return QOAuth::ParamMap();
  }
  if ( consumerSecret.isEmpty() ) {
    qWarning() << __PRETTY_FUNCTION__ << "consumer secret is empty, make sure that you set it with QOAuth::setConsumerSecret()";
    return QOAuth::ParamMap();
  }

  // temporarily only HMAC-SHA1 is supported
  if ( signatureMethod != QOAuth::HMAC_SHA1 ) {
    qWarning() << __PRETTY_FUNCTION__ << "Sorry, we're currently supporting only HMAC-SHA1 method...";
    return QOAuth::ParamMap();
  }

  QCA::Initializer init;

  if( !QCA::isSupported( "hmac(sha1)" ) ) {
    qFatal( "HMAC(SHA1) is not supported!" );
  }

  QOAuth::ParamMap parameters = params;
  // create signature
  QByteArray signature = createSignature( requestUrl, httpMethod, signatureMethod,
                                             token, tokenSecret, &parameters );

  // add signature to parameters
  parameters.insert( QOAuth::ParamSignature, signature );

  QByteArray authorizationHeader;
  QNetworkRequest request;

  if ( httpMethod == QOAuth::GET ) {
    authorizationHeader = paramsToString( parameters, QOAuth::ParseForHeaderArguments );
    // create the authorization header
    request.setRawHeader( "Authorization", "OAuth " + authorizationHeader );
  } else if ( httpMethod == QOAuth::POST ) {
    authorizationHeader = paramsToString( parameters, QOAuth::ParseForInlineQuery );
    // create a network request
    request.setHeader( QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded" );
  }

  request.setUrl( QUrl( requestUrl ) );

  // fire up a single shot timer if timeout was specified
  if ( timeout > 0 ) {
    QTimer::singleShot( timeout, loop, SLOT(quit()) );
    // if the request finishes on time, the error value is overriden
    // if not, it remains equal to QOAuth::Timeout
    error = QOAuth::Timeout;
  }

  // send the request
  if ( httpMethod == QOAuth::GET ) {
    manager->get( request );
  } else if ( httpMethod == QOAuth::POST ) {
    manager->post( request, authorizationHeader );
  }

  // start the event loop and wait for the response
  loop->exec();

  return replyParams;
}

QByteArray QOAuth::createParametersString( const QString &requestUrl, QOAuth::HttpMethod httpMethod, QOAuth::SignatureMethod signatureMethod,
                                           const QByteArray &token, const QByteArray &tokenSecret,
                                           const QOAuth::ParamMap &params, QOAuth::ParsingMode mode )
{
  Q_D(QOAuth);

  QOAuth::ParamMap parameters = params;
  QByteArray signature = d->createSignature( requestUrl, httpMethod, signatureMethod,
                                             token, tokenSecret, &parameters );
  parameters.insert( QOAuth::ParamSignature, signature );
  QByteArray parametersString = d->paramsToString( parameters, mode );

  return parametersString;
}

QByteArray QOAuthPrivate::createSignature( const QString &requestUrl, QOAuth::HttpMethod httpMethod,
                                           QOAuth::SignatureMethod signatureMethod, const QByteArray &token,
                                           const QByteArray &tokenSecret, QOAuth::ParamMap *params )
{
  QCA::Initializer init;

  if( !QCA::isSupported( "hmac(sha1)" ) ) {
    qFatal( "HMAC(SHA1) is not supported!" );
  }

  // create nonce
  QCA::InitializationVector iv( 16 );
  QByteArray nonce = iv.toByteArray().toBase64().toPercentEncoding();

  // create timestamp
  uint time = QDateTime::currentDateTime().toTime_t();
  QByteArray timestamp = QByteArray::number( time );

  // create signature base string
  // 1. create the method string
  QByteArray httpMethodString = httpMethodToString( httpMethod );
  // 2. prepare percent-encoded request URL
  QByteArray percentRequestUrl = requestUrl.toAscii().toPercentEncoding();
  // 3. prepare percent-encoded parameters string
  params->insert( QOAuth::ParamConsumerKey, consumerKey );
  params->insert( QOAuth::ParamNonce, nonce );
  params->insert( QOAuth::ParamSignatureMethod,
                  signatureMethodToString( signatureMethod ) );
  params->insert( QOAuth::ParamTimestamp, timestamp );
  params->insert( QOAuth::ParamVersion, QOAuth::OAuthVersion );
  if ( !token.isEmpty() ) {
    params->insert( QOAuth::ParamToken, token );
  }

  QByteArray parametersString = paramsToString( *params, QOAuth::ParseForSignatureBaseString );
  QByteArray percentParametersString = parametersString.toPercentEncoding();

  // 4. create signature base string
  QByteArray signatureBaseString;
  signatureBaseString.append( httpMethodString + "&" );
  signatureBaseString.append( percentRequestUrl + "&" );
  signatureBaseString.append( percentParametersString );

  // create key for HMAC-SHA1 hashing
  QByteArray key( consumerSecret + "&" + tokenSecret );

  // create HMAC-SHA1 digest in Base64
  QCA::MessageAuthenticationCode hmac( "hmac(sha1)", QCA::SymmetricKey( key ) );
  QCA::SecureArray array( signatureBaseString );
  hmac.update( array );
  QCA::SecureArray resultArray = hmac.final();
  QByteArray digest = resultArray.toByteArray().toBase64();
  // percent-encode the digest
  QByteArray signature = digest.toPercentEncoding();
  return signature;
}
