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

/*!
  \class QOAuth qoauth.h <QtOAuth>
  \brief This class provides means for interaction with network services supporting
         OAuth authorization scheme.

  The QOAuth class is meant to enable OAuth support in applications in as simple way
  as possible. It provides 3 methods, two of which serve for authorization purposes:
    \li \ref requestToken(),
    \li \ref accessToken(),

  and the third one helps with creation of requests for Protected Resources:
    \li \ref createParametersString().

  \section sec_auth_scheme OAuth authorization scheme

  According to <a href=http://oauth.net/core/1.0/#consumer_req_param>
  OAuth 1.0 Core specification</a>, <em>the OAuth protocol enables websites or applications
  (Consumers) to access Protected Resources from a web service (Service Provider) via an
  API, without requiring Users to disclose their Service Provider credentials to the
  Consumers</em>. Simply, OAuth is a way of connecting an application to the Service
  Provider's API without needing to provide User's login or password. The authorization
  is based on an exchange of a Token (user-specific) together with a Consumer Key
  (application-specific), encrypted with a combination of so called Token Secret and
  Customer Secret. Getting access to Protected Resources consists in three basic steps:
  <ol>
    <li>obtaining an unauthorized Request Token from the Service Provider,</li>
    <li>asking the User to authorize the Request Token,</li>
    <li>exchanging the Request Token for an Access Token.</li>
  </ol>
  Details are covered in <a href=http://oauth.net/core/1.0/#anchor9>Section 6</a> of the
  OAuth 1.0 Core Specification. As the authorization procedure is quite complex, the QOAuth
  library helps to simplify it by doing all the dirty work behind the scenes.

  \section sec_req_token OAuth authorization with QOAuth

  First step of OAuth authorization can be done in one line using QOAuth library.
  Consult the example:

  \include requestToken.cpp

  After the unauthorized Request Token is received, User has to authorize it using
  Service Provider-defined method. This is beyond the scope of this library. Once User
  authorizes the Request Token, it can be exchanged for an Access Token, authorizing the
  application to access User's Protected Resources. This can be done with another one line:

  \include accessToken.cpp

  Once the Access Token is received, the application is authorized.

  \section sec_acc_res Requesting Protected Resources with QOAuth

  In order to access Protected Resources, the application has to send a request containing
  arguments including Customer Key and Access Token, and encrypt them with Customer Secret
  and Token Secret. The process of constructing such a request can be reduced to another
  one-line call with QOAuth:

  \include accessResources.cpp

  \section sec_capabilities Capabilities

  Out of 3 signature methods supported by OAuth protocol, QOAuth library supports only
  HMAC-SHA1 at the moment. This is subject to change in future releases.
*/


/*!
  \enum QOAuth::SignatureMethod
  \brief This enum type describes the signature method used by the request.

  There are 3 different signature methods defined by the
  <a href=http://oauth.net/core/1.0/#signing_process>OAuth protocol</a>. This enum
  is used to specify the method used by a specific request. Hence, one of its values
  must be passed as a parameter in any of the \ref requestToken(), \ref accessToken() or
  \ref createParametersString() method.

  \note The current implementation of the library supports only HMAC-SHA1 signature algorithm.
*/

/*!
  \var QOAuth::HMAC_SHA1
  \brief Sets the signature method to HMAC-SHA1
*/

/*!
  \var QOAuth::RSA_SHA1
  \brief Sets the signature method to RSA-SHA1 (not implemented yet)
*/

/*!
  \var QOAuth::PLAINTEXT
  \brief Sets the signature method to PLAINTEXT (not implemented yet)
*/

/*!
  \enum QOAuth::HttpMethod
  \brief This enum type specifies the HTTP method used for creating
         a <a href=http://oauth.net/core/1.0/#anchor14>Signature Base String</a>
         and/or sending a request.

  The HTTP method has to be specified in QOAuth class for two reasons:
  \li to know what type of request should be prepared and sent
      (\ref requestToken() and \ref accessToken()),
  \li to prepare a correct signature, as the Signature Base String contains a parameter
      specifying the HTTP method used for request (\ref createParametersString()).

  \note For \ref requestToken() and \ref accessToken() methods only \ref GET and
        \ref POST methods are allowed.
*/

/*!
  \var QOAuth::GET
  \brief Sets the HTTP method to GET
*/

/*!
  \var QOAuth::POST
  \brief Sets the HTTP method to POST
*/

/*!
  \var QOAuth::HEAD
  \brief Sets the HTTP method to HEAD
*/

/*!
  \var QOAuth::PUT
  \brief Sets the HTTP method to PUT
*/

/*!
  \var QOAuth::DELETE
  \brief Sets the HTTP method to DELETE
*/

/*!
  \enum QOAuth::ParsingMode
  \brief This enum type specifies the method of parsing parameters into
         a parameter string.

  When creating a parameters string for a custom request using
  \ref createParametersString() the parsing mode must be defined in order
  to prepare the string correctly.

  According to what is stated in <a href=http://oauth.net/core/1.0/#consumer_req_param>
  OAuth 1.0 Core specification</a>, parameters can be passed in a request to
  the Service Provider in 3 different ways. When using \ref createParametersString(),
  choose the one that suits you by setting \a ParsingMode appropriatelly.

  \sa createParametersString()
*/

/*!
  \var QOAuth::ParseForInlineQuery
  \brief Inlne query format (parameters appended to the request URL)
*/

/*!
  \var QOAuth::ParseForSignatureBaseString
  \brief <a href=http://oauth.net/core/1.0/#anchor14>Signature Base String</a> format, meant for internal use.
*/

/*!
  \var QOAuth::ParseForHeaderArguments
  \brief HTTP request header format (parameters to be put inside a request header)
*/

/*!
  \enum QOAuth::ErrorCode
  \brief This enum type defines error types that are assigned to the \ref error property

  This error codes collection contains both network-related errors and those that
  can occur when incorrect arguments are provided to any of the class's methods.

  \sa error
*/

/*!
  \var QOAuth::NoError
  \brief No error occured (so far :-) )
*/

/*!
  \var QOAuth::BadRequest
  \brief Represents HTTP status code \c 400 (Bad Request)
*/

/*!
  \var QOAuth::Unauthorized
  \brief Represents HTTP status code \c 401 (Unauthorized)
*/

/*!
  \var QOAuth::Forbidden
  \brief Represents HTTP status code \c 403 (Forbidden)
*/

/*!
  \var QOAuth::Timeout
  \brief Represents a request timeout error
*/

/*!
  \var QOAuth::ConsumerKeyEmpty
  \brief Consumer key has not been provided
*/

/*!
  \var QOAuth::ConsumerSecretEmpty
  \brief Consumer secret has not been provided
*/

/*!
  \var QOAuth::UnsupportedSignatureMethod
  \brief The signature method is not supported by the library
*/

/*!
  \var QOAuth::UnsupportedHttpMethod
  \brief The HTTP method is not supported by the request. Note that \ref requestToken()
         and \ref accessToken() accept only HTTP GET and POST requests.
*/

/*!
  \var QOAuth::OtherError
  \brief A network-related error not specified above
*/


/*!
  \typedef QOAuth::ParamMap
  \brief A typedef of a data structure to store request paramters
*/


/*!
  \brief The supported OAuth scheme version.
*/
const QByteArray QOAuth::OAuthVersion = "1.0";

//! \brief The <em>consumer key</em> request parameter string
const QByteArray QOAuth::ParamConsumerKey     = "oauth_consumer_key";
//! \brief The <em>nonce</em> request parameter string
const QByteArray QOAuth::ParamNonce           = "oauth_nonce";
//! \brief The <em>signature</em> request parameter string
const QByteArray QOAuth::ParamSignature       = "oauth_signature";
//! \brief The <em>signature method</em> request parameter string
const QByteArray QOAuth::ParamSignatureMethod = "oauth_signature_method";
//! \brief The <em>timestamp</em> request parameter string
const QByteArray QOAuth::ParamTimestamp       = "oauth_timestamp";
//! \brief The <em>version</em> request parameter string
const QByteArray QOAuth::ParamVersion         = "oauth_version";
//! \brief The <em>token</em> request parameter string
const QByteArray QOAuth::ParamToken           = "oauth_token";
//! \brief The <em>token secret</em> request parameter string
const QByteArray QOAuth::ParamTokenSecret     = "oauth_token_secret";
//! \brief The <em>access token</em> request parameter string
const QByteArray QOAuth::ParamAccessToken     = "oauth_access_token";

QOAuthPrivate::QOAuthPrivate( QObject *parent ) :
    QObject( parent ),
    consumerKey( QByteArray() ),
    consumerSecret( QByteArray() ),
    accessToken( QByteArray() ),
    manager( new QNetworkAccessManager( this ) ),
    loop( new QEventLoop( this ) ),
    requestTimeout(0),
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
  case QOAuth::HEAD:
    return "HEAD";
  case QOAuth::PUT:
    return "PUT";
  case QOAuth::DELETE:
    return "DELETE";
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

  // prepend with "OAuth " when asked to creating an HTTP header
  if ( mode == QOAuth::ParseForHeaderArguments ) {
    parametersString.prepend( "OAuth " );
  }

  return parametersString;
}


/*!
  \brief Creates a new QOAuth class instance with the given \a parent
*/

QOAuth::QOAuth( QObject *parent ) :
    QObject( parent ),
    d_ptr( new QOAuthPrivate( this ) )
{
  Q_D(QOAuth);

  d->q_ptr = this;
}

/*!
  \brief Destroys the QOAuth object
*/

QOAuth::~QOAuth()
{
}

/*!
  \property QOAuth::consumerKey
  \brief This property holds the consumer key

  The consumer key is used by the application to identify itself to the Service Provider

  Access functions:
  \li <b>QByteArray consumerKey() const</b>
  \li <b>void setConsumerKey( const QByteArray &consumerKey )</b>
*/

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

/*!
  \property QOAuth::consumerSecret
  \brief This property holds the consumer secret

  The consumerSecret is used by the application for signing outgoing requests

  Access functions:
  \li <b>QByteArray consumerSecret() const</b>
  \li <b>void setConsumerSecret( const QByteArray &consumerSecret )</b>
*/

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

/*!
  \property QOAuth::requestTimeout
  \brief This property holds the timeout value for issued network requests.

  The QOAuth class can send network requests when asked to do so by calling either
  requestToken() or accessToken() method. By defining the \a requestTimeout, requests
  can have the time constraint applied, after which they fail. The \a requestTimeout
  value is initially set to \c 0, which in this case means that no timeout is applied
  to outgoing requests.

  Access functions:
  \li <b>uint requestTimeout() const</b>
  \li <b>void setRequestTimeout( uint requestTimeout )</b>
*/

uint QOAuth::requestTimeout() const
{
  Q_D(const QOAuth);

  return d->requestTimeout;
}

void QOAuth::setRequestTimeout( uint requestTimeout )
{
  Q_D(QOAuth);

  d->requestTimeout = requestTimeout;
}


/*!
  \property QOAuth::error
  \brief This property holds the error code

  The error code is initially set to \ref NoError, and its value is updated with every
  request, i.e. \ref requestToken(), \ref accessToken() or \ref createParametersString().

  Access functions:
  \li <b>int error() const</b>

  \sa ErrorCode
*/

int QOAuth::error() const
{
  Q_D(const QOAuth);

  return d->error;
}

/*!
  This method constructs and sends a request for obtaining an unauthorized Request Token
  from the Service Provider. This is the first step of the OAuth authentication flow,
  according to <a href=http://oauth.net/core/1.0/#anchor9>OAuth 1.0 Core specification</a>.
  At the moment only HMAC-SHA1 signature method is supported. The HMAC-SHA1
  <a href=http://oauth.net/core/1.0/#anchor14>Signature Base String</a> is created
  using the given \a requestUrl and \a httpMethod. The optional request parameters
  specified by the Service Provider can be passed in the \a params ParamMap.

  The Signature Base String contains the \ref consumerKey and uses \ref consumerSecret
  for encrypting the message, so it's necessary to provide them both before issuing this
  request. The method will check if both \ref consumerKey and \ref consumerSecret are
  provided, and fail if any of them is missing.

  When the signature is created, the appropriate request is sent to the Service Provider
  (namely, the \a requestUrl). Depending on the type of the request, the parameters are
  passed according to the <a href=http://oauth.net/core/1.0/#consumer_req_param>
  Consumer Request Parametes</a> section of the OAuth specification, i.e.:
  \li for GET requests, in the HTTP Authorization header, as defined in
      <a href=http://oauth.net/core/1.0/#auth_header>OAuth HTTP Authorization Scheme</a>,
  \li for POST requests, as a request body with \c content-type set to
      \c application/x-www-form-urlencoded.

  Once the request is sent, a local event loop is executed and set up to wait for the request
  to complete. If the \ref requestTimeout property is set to a non-zero value, its vaue
  is applied as a request timeout, after which the request is aborted.

  \returns If request succeded, the method returns all the data passed in the Service
  Provider response (including a Request Token and Token Secret), formed in a ParamMap.
  If request fails, the \ref error property is set to an appropriate value, and an empty
  ParamMap is returned.

  \sa accessToken(), error
*/

QOAuth::ParamMap QOAuth::requestToken( const QString &requestUrl, HttpMethod httpMethod,
                                       SignatureMethod signatureMethod, const ParamMap &params )
{
  Q_D(QOAuth);

  return d->sendRequest( requestUrl, httpMethod, signatureMethod,
                         QByteArray(), QByteArray(), params );
}

/*!
  This method constructs and sends a request for exchanging a Request Token (obtained
  previously with a call to \ref requestToken()) for an Access Token, that authorizes the
  application to access Protected Resources. This is the third step of the OAuth
  authentication flow, according to <a href=http://oauth.net/core/1.0/#anchor9>OAuth 1.0
  Core specification</a>. At the moment only HMAC-SHA1 signature method is supported.
  The HMAC-SHA1 <a href=http://oauth.net/core/1.0/#anchor14>Signature Base String</a>
  is created using the given \a requestUrl, \a httpMethod, \a token and \a tokenSecret.
  The optional request parameters specified by the Service Provider can be passed in the
  \a params ParamMap.

  The Signature Base String contains the \ref consumerKey and uses \ref consumerSecret
  for encrypting the message, so it's necessary to provide them both before issuing
  this request. The method will check if both \ref consumerKey and \ref consumerSecret
  are provided, and fail if any of them is missing.

  When the signature is created, the appropriate request is sent to the Service Provider
  (namely, the \a requestUrl). Depending on the type of the request, the parameters are
  passed according to the <a href=http://oauth.net/core/1.0/#consumer_req_param>
  Consumer Request Parametes</a> section of the OAuth specification, i.e.:
  \li for GET requests, in the HTTP Authorization header, as defined in
      <a href=http://oauth.net/core/1.0/#auth_header>OAuth HTTP Authorization Scheme</a>,
  \li for POST requests, as a request body with \c content-type set to
      \c application/x-www-form-urlencoded.

  Once the request is sent, a local event loop is executed and set up to wait for the request
  to complete. If the \ref requestTimeout property is set to a non-zero value, its vaue
  is applied as a request timeout, after which the request is aborted.

  \returns If request succeded, the method returns all the data passed in the Service
  Provider response (including an authorized Access Token and Token Secret), formed in
  a ParamMap. This request ends the authorization process, and the obtained Access Token
  and Token Secret should be kept by the application and provided with every future request
  authorized by OAuth, e.g. using \ref createParametersString(). If request fails, the
  \ref error property is set to an appropriate value, and an empty ParamMap is returned.

  \sa requestToken(), createParametersString(), error
*/

QOAuth::ParamMap QOAuth::accessToken( const QString &requestUrl, HttpMethod httpMethod, const QByteArray &token,
                                      const QByteArray &tokenSecret, SignatureMethod signatureMethod,
                                      const ParamMap &params )
{
  Q_D(QOAuth);

  return d->sendRequest( requestUrl, httpMethod, signatureMethod,
                         token, tokenSecret, params );

}

/*!
  This method generates a parameters string required to access Protected Resources using
  OAuth authorization. According to <a href=http://oauth.net/core/1.0/#anchor13>OAuth 1.0
  Core specification</a>, every outgoing request for accessing Protected Resources must
  contain information like consumer key and Access Token, and has to be signed using one
  of the supported signature methods.

  At the moment only HMAC-SHA1 signature method is supported by the library. The HMAC-SHA1
  <a href=http://oauth.net/core/1.0/#anchor14>Signature Base String</a> is created using
  the given \a requestUrl, \a httpMethod, \a token and \a tokenSecret. The optional
  request parameters specified by the Service Provider can be passed in the \a params
  \ref ParamMap.

  The Signature Base String contains the \ref consumerKey and uses \ref consumerSecret
  for encrypting the message, so it's necessary to provide them both before issuing
  this request. The method will check if both \ref consumerKey and \ref consumerSecret
  are provided, and fail if any of them is missing.

  The \a mode parameter specifies the format of the parameter string.

  \returns The parsed parameters string, depending on \a mode and \a httpMethod is:
    \li prepended with <em>'?'</em> and ready to be appended to the \a requestUrl - when
        <tt>mode == QOAuth::ParseForInlineQuery</tt> and <tt>httpMethod == QOAuth::GET</tt>
    \li ready to be passed as a request body - when <tt>mode == QOAuth::ParseForInlineQuery</tt> and
        <tt>httpMethod != QOAuth::GET</tt>
    \li ready to be passed as a value for \c Authorization HTTP header field - when
        <tt>mode == QOAuth::ParseForHeaderArguments</tt>.
*/

QByteArray QOAuth::createParametersString( const QString &requestUrl, QOAuth::HttpMethod httpMethod, QOAuth::SignatureMethod signatureMethod,
                                           const QByteArray &token, const QByteArray &tokenSecret,
                                           const QOAuth::ParamMap &params, QOAuth::ParsingMode mode )
{
  Q_D(QOAuth);

  d->error = NoError;

  // copy parameters to a writable object
  QOAuth::ParamMap parameters = params;
  // calculate the signature
  QByteArray signature = d->createSignature( requestUrl, httpMethod, signatureMethod,
                                             token, tokenSecret, &parameters );

  // return an empty bytearray when signature wasn't created
  if ( d->error != NoError ) {
    return QByteArray();
  }

  // append it to parameters
  parameters.insert( QOAuth::ParamSignature, signature );
  // convert the map to bytearray, according to requested mode
  QByteArray parametersString = d->paramsToString( parameters, mode );

  // add a query separator, this will be a query part of the URL
  if ( httpMethod == GET && mode == ParseForInlineQuery ) {
    parametersString.prepend( '?' );
  }

  return parametersString;
}

QOAuth::ParamMap QOAuthPrivate::sendRequest( const QString &requestUrl, QOAuth::HttpMethod httpMethod, QOAuth::SignatureMethod signatureMethod,
                                             const QByteArray &token, const QByteArray &tokenSecret, const QOAuth::ParamMap &params )
{
  if ( httpMethod != QOAuth::GET && httpMethod != QOAuth::POST ) {
    qWarning() << __PRETTY_FUNCTION__ << "requestToken() and accessToken() accept only GET and POST methods";
    error = QOAuth::UnsupportedHttpMethod;
    return QOAuth::ParamMap();
  }

  error = QOAuth::NoError;

  QOAuth::ParamMap parameters = params;
  // create signature
  QByteArray signature = createSignature( requestUrl, httpMethod, signatureMethod,
                                             token, tokenSecret, &parameters );

  // if signature wasn't created, return an empty map
  if ( error != QOAuth::NoError ) {
    return QOAuth::ParamMap();
  }

  // add signature to parameters
  parameters.insert( QOAuth::ParamSignature, signature );

  QByteArray authorizationHeader;
  QNetworkRequest request;

  if ( httpMethod == QOAuth::GET ) {
    authorizationHeader = paramsToString( parameters, QOAuth::ParseForHeaderArguments );
    // create the authorization header
    request.setRawHeader( "Authorization", authorizationHeader );
  } else if ( httpMethod == QOAuth::POST ) {
    authorizationHeader = paramsToString( parameters, QOAuth::ParseForInlineQuery );
    // create a network request
    request.setHeader( QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded" );
  }

  request.setUrl( QUrl( requestUrl ) );

  // fire up a single shot timer if timeout was specified
  if ( this->requestTimeout > 0 ) {
    QTimer::singleShot( requestTimeout, loop, SLOT(quit()) );
    // if the request finishes on time, the error value is overriden
    // if not, it remains equal to QOAuth::Timeout
    error = QOAuth::Timeout;
  }

  // clear the reply container and send the request
  replyParams.clear();
  QNetworkReply *reply;
  if ( httpMethod == QOAuth::GET ) {
    reply = manager->get( request );
  } else if ( httpMethod == QOAuth::POST ) {
    reply = manager->post( request, authorizationHeader );
  }

  // start the event loop and wait for the response
  loop->exec();

  // if request completed successfully, error is different than QOAuth::Timeout
  // if it failed, we have to abort the request
  if ( error == QOAuth::Timeout ) {
    reply->abort();
  }

  return replyParams;
}

QByteArray QOAuthPrivate::createSignature( const QString &requestUrl, QOAuth::HttpMethod httpMethod,
                                           QOAuth::SignatureMethod signatureMethod, const QByteArray &token,
                                           const QByteArray &tokenSecret, QOAuth::ParamMap *params )
{
  if ( consumerKey.isEmpty() ) {
    qWarning() << __PRETTY_FUNCTION__ << "consumer key is empty, make sure that you set it with QOAuth::setConsumerKey()";
    error = QOAuth::ConsumerKeyEmpty;
    return QByteArray();
  }
  if ( consumerSecret.isEmpty() ) {
    qWarning() << __PRETTY_FUNCTION__ << "consumer secret is empty, make sure that you set it with QOAuth::setConsumerSecret()";
    error = QOAuth::ConsumerSecretEmpty;
    return QByteArray();
  }

  // temporarily only HMAC-SHA1 is supported
  if ( signatureMethod != QOAuth::HMAC_SHA1 ) {
    qWarning() << __PRETTY_FUNCTION__ << "Sorry, we're currently supporting only HMAC-SHA1 method...";
    error = QOAuth::UnsupportedSignatureMethod;
    return QByteArray();
  }


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
  // append token only if it is defined (requestToken() doesn't use a token at all)
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
