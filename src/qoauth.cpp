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
  \mainpage

  \section sec_what What is the purpose of QOAuth?

  The main motivation to create this library was to provide an interface to OAuth
  protocoll for (Qt-based) C++ applications in an easy way. This is very early version
  of the library, and it lacks some functionality, but in the same time it is capable
  of sending OAuth authorization requests as well as preparing requests for accessing
  User's Protected Resources.

  \section sec_lic License and Authors

  The project is licensed under <a href=http://www.gnu.org/licenses/lgpl-2.1.html>GNU LGPL
  license</a> version 2.1 or later. The work is done by Dominik Kapusta (d at ayoy dot net).

  \section sec_inst How to install?

  \subsection ssec_deps Dependencies

  There are a few things necessary to get OAuth library working:

  <ol>
    <li>Qt libraries, version 4.4 or higher,</li>
    <li>QCA (Qt Cryptographic Architecture), available from
        <a href=http://delta.affinix.com/qca>Delta XMPP Project</a>, version 2.0.0
        or higher,</li>
    <li>OpenSSL plugin to QCA (qca-ossl), available from QCA page, and requiring OpenSSL.</li>
  </ol>

  \b Note: KDE4 users meet all the requirements out of the box.

  \subsection ssec_inst Installation

  The source code repository is hosted on <a href=http://github.com/ayoy/qoauth>GitHub</a>
  and the code can be checked out from there easily using git:
  \verbatim
    $ git clone git://github.com/ayoy/qoauth.git \endverbatim

  To compile the code, follow the simple procedure:

  \verbatim
    $ qmake
    $ make
    $ sudo make install \endverbatim

  \subsection ssec_use Usage

  Configuring your project to work with QOAuth library is extremely simple. Firstly,
  append a line to your project file:
  \verbatim
    CONFIG += oauth \endverbatim

  Then include the following header in your code:
  \verbatim
    #include <QtOAuth> \endverbatim

  \section sec_bugs Bugs and issues

  Please file all the bug reports to the QOAuth bug tracking system at
  <a href="http://ayoy.lighthouseapp.com/projects/32547-qoauth/tickets?q=all">
  lighthouseapp.com</a>. If you wish to contribute, you're extremely welcome
  to fork a <a href=http://github.com/ayoy/qoauth>GitHub</a> repository and
  add your input there.

*/

/*!
  \class QOAuth::QOAuth qoauth.h <QtOAuth>
  \brief This class provides means for interaction with network services supporting
         OAuth authorization scheme.

  The QOAuth class is meant to enable OAuth support in applications in as simple way
  as possible. It provides 4 basic methods, two of which serve for authorization purposes:
    \li \ref requestToken(),
    \li \ref accessToken(),

  and the other two help with creation of requests for accessing Protected Resources:
    \li \ref createParametersString(),
    \li \ref inlineParameters().

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
    <li>exchanging the Request Token for the Access Token.</li>
  </ol>
  Details are covered in <a href=http://oauth.net/core/1.0/#anchor9>Section 6</a> of the
  OAuth 1.0 Core Specification. As the authorization procedure is quite complex, the QOAuth
  library helps to simplify it by doing all the dirty work behind the scenes.

  \section sec_req_token OAuth authorization with QOAuth

  First step of OAuth authorization can be done in one line using QOAuth library.
  Consult the example:

  \include requestToken.cpp

  Once the unauthorized Request Token is received, User has to authorize it using
  Service Provider-defined method. This is beyond the scope of this library. Once User
  authorizes the Request Token, it can be exchanged for an Access Token that authorizes the
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


QByteArray QOAuth::supportedOAuthVersion()
{
  return QOAuthPrivate::OAuthVersion;
}

QByteArray QOAuth::tokenParameterName()
{
  return QOAuthPrivate::ParamToken;
}

QByteArray QOAuth::tokenSecretParameterName()
{
  return QOAuthPrivate::ParamTokenSecret;
}


/*!
  \brief The supported OAuth scheme version.
*/
const QByteArray QOAuth::QOAuthPrivate::OAuthVersion = "1.0";

//! \brief The <em>token</em> request parameter string
const QByteArray QOAuth::QOAuthPrivate::ParamToken           = "oauth_token";
//! \brief The <em>token secret</em> request parameter string
const QByteArray QOAuth::QOAuthPrivate::ParamTokenSecret     = "oauth_token_secret";

//! \brief The <em>consumer key</em> request parameter string
const QByteArray QOAuth::QOAuthPrivate::ParamConsumerKey     = "oauth_consumer_key";
//! \brief The <em>nonce</em> request parameter string
const QByteArray QOAuth::QOAuthPrivate::ParamNonce           = "oauth_nonce";
//! \brief The <em>signature</em> request parameter string
const QByteArray QOAuth::QOAuthPrivate::ParamSignature       = "oauth_signature";
//! \brief The <em>signature method</em> request parameter string
const QByteArray QOAuth::QOAuthPrivate::ParamSignatureMethod = "oauth_signature_method";
//! \brief The <em>timestamp</em> request parameter string
const QByteArray QOAuth::QOAuthPrivate::ParamTimestamp       = "oauth_timestamp";
//! \brief The <em>version</em> request parameter string
const QByteArray QOAuth::QOAuthPrivate::ParamVersion         = "oauth_version";

QOAuth::QOAuthPrivate::QOAuthPrivate( QObject *parent ) :
    QObject( parent ),
    consumerKey( QByteArray() ),
    consumerSecret( QByteArray() ),
    manager( new QNetworkAccessManager( this ) ),
    loop( new QEventLoop( this ) ),
    requestTimeout(0),
    error( NoError )
{
  connect( manager, SIGNAL(finished(QNetworkReply*)), loop, SLOT(quit()) );
  connect( manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(parseReply(QNetworkReply*)) );
}

QByteArray QOAuth::QOAuthPrivate::httpMethodToString( HttpMethod method )
{
  switch ( method ) {
  case GET:
    return "GET";
  case POST:
    return "POST";
  case HEAD:
    return "HEAD";
  case PUT:
    return "PUT";
  case DELETE:
    return "DELETE";
  default:
    qWarning() << __FUNCTION__ << "- Unrecognized method";
    return QByteArray();
  }
}

QByteArray QOAuth::QOAuthPrivate::signatureMethodToString( SignatureMethod method )
{
  switch ( method ) {
  case HMAC_SHA1:
    return "HMAC-SHA1";
  case RSA_SHA1:
    return "RSA-SHA1";
  case PLAINTEXT:
    return "PLAINTEXT";
  default:
    qWarning() << __FUNCTION__ << "- Unrecognized method";
    return QByteArray();
  }
}

QOAuth::ParamMap QOAuth::QOAuthPrivate::replyToMap( const QByteArray &data )
{
  // split reply to name=value strings
  QList<QByteArray> replyParams = data.split( '&' );
  // we'll store them in a map
  ParamMap parameters;

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

void QOAuth::QOAuthPrivate::parseReply( QNetworkReply *reply )
{
  int returnCode = reply->attribute( QNetworkRequest::HttpStatusCodeAttribute ).toInt();

  switch ( returnCode ) {
  case NoError:
    replyParams = replyToMap( reply->readAll() );
    if ( !replyParams.contains( QOAuthPrivate::ParamToken ) ) {
      qWarning() << __FUNCTION__ << "- oauth_token not present in reply!";
    }
    if ( !replyParams.contains( QOAuthPrivate::ParamTokenSecret ) ) {
      qWarning() << __FUNCTION__ << "- oauth_token_secret not present in reply!";
    }

  case BadRequest:
  case Unauthorized:
  case Forbidden:
    error = returnCode;
    break;
  default:
    error = OtherError;
  }

  reply->close();
}

QByteArray QOAuth::QOAuthPrivate::paramsToString( const ParamMap &parameters, ParsingMode mode )
{
  QByteArray middleString;
  QByteArray endString;

  switch ( mode ) {
  case ParseForInlineQuery:
  case ParseForSignatureBaseString:
    middleString = "=";
    endString = "&";
    break;
//    // percent encode in place
//    middleString = "%3D";
//    endString = "%26";
//    break;
  case ParseForHeaderArguments:
    middleString = "=\"";
    endString = "\",";
    break;
  default:
    qWarning() << __FUNCTION__ << "- Unrecognized mode";
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
//      if ( mode == QOAuth::QOAuth::ParseForSignatureBaseString ||
//           mode == QOAuth::QOAuth::ParseForInlineQuery ) {
//        // encode for Signature Base String and for the query string
//        parametersString.append( value.toPercentEncoding() );
//      } else {
//        parametersString.append( value );
//      }
    }
  }

  parametersString.chop(1);

  // prepend with "OAuth " when asked to create an HTTP header
  if ( mode == ParseForHeaderArguments ) {
    parametersString.prepend( "OAuth " );
  }

  return parametersString;
}


/*!
  \brief Creates a new QOAuth class instance with the given \a parent
*/

QOAuth::QOAuth::QOAuth( QObject *parent ) :
    QObject( parent ),
    d_ptr( new QOAuthPrivate( this ) )
{
  Q_D(QOAuth);

  d->q_ptr = this;
}

/*!
  \brief Destroys the QOAuth object
*/

QOAuth::QOAuth::~QOAuth()
{
  delete d_ptr;
}

/*!
  \property QOAuth::QOAuth::consumerKey
  \brief This property holds the consumer key

  The consumer key is used by the application to identify itself to the Service Provider

  Access functions:
  \li <b>QByteArray consumerKey() const</b>
  \li <b>void setConsumerKey( const QByteArray &consumerKey )</b>
*/

QByteArray QOAuth::QOAuth::consumerKey() const
{
  Q_D(const QOAuth);

  return d->consumerKey;
}

void QOAuth::QOAuth::setConsumerKey( const QByteArray &consumerKey )
{
  Q_D(QOAuth);

  d->consumerKey = consumerKey;
}

/*!
  \property QOAuth::QOAuth::consumerSecret
  \brief This property holds the consumer secret

  The consumerSecret is used by the application for signing outgoing requests

  Access functions:
  \li <b>QByteArray consumerSecret() const</b>
  \li <b>void setConsumerSecret( const QByteArray &consumerSecret )</b>
*/

QByteArray QOAuth::QOAuth::consumerSecret() const
{
  Q_D(const QOAuth);

  return d->consumerSecret;
}

void QOAuth::QOAuth::setConsumerSecret( const QByteArray &consumerSecret )
{
  Q_D(QOAuth);

  d->consumerSecret = consumerSecret;
}

/*!
  \property QOAuth::QOAuth::requestTimeout
  \brief This property holds the timeout value in milliseconds for issued network requests.

  The QOAuth class can send network requests when asked to do so by calling either
  requestToken() or accessToken() method. By defining the \a requestTimeout, requests
  can have the time constraint applied, after which they fail, setting \ref error to
  \ref Timeout. The \a requestTimeout value is initially set to \c 0, which in this
  case means that no timeout is applied to outgoing requests.

  Access functions:
  \li <b>uint requestTimeout() const</b>
  \li <b>void setRequestTimeout( uint requestTimeout )</b>
*/

uint QOAuth::QOAuth::requestTimeout() const
{
  Q_D(const QOAuth);

  return d->requestTimeout;
}

void QOAuth::QOAuth::setRequestTimeout( uint msec )
{
  Q_D(QOAuth);

  d->requestTimeout = msec;
}


/*!
  \property QOAuth::QOAuth::error
  \brief This property holds the error code

  The error code is initially set to \ref NoError, and its value is updated with every
  request, i.e. \ref requestToken(), \ref accessToken() or \ref createParametersString().

  Access functions:
  \li <b>int error() const</b>

  \sa ErrorCode
*/

int QOAuth::QOAuth::error() const
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

QOAuth::ParamMap QOAuth::QOAuth::requestToken( const QString &requestUrl, HttpMethod httpMethod,
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

QOAuth::ParamMap QOAuth::QOAuth::accessToken( const QString &requestUrl, HttpMethod httpMethod, const QByteArray &token,
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

  \returns The parsed parameters string, that depending on \a mode and \a httpMethod is:

  <table>
    <tr><td>\b \a mode </td>                                   <td>\b \a httpMode </td>     <td>\b outcome </td></tr>
    <tr><td rowspan=2><tt>QOAuth::ParseForInlineQuery</tt></td><td><tt>QOAuth::GET</tt></td><td>prepended with a <em>'?'</em> and ready to be appended to the \a requestUrl</td></tr>
    <tr>                                                       <td><em>others</em></td>     <td>ready to be posted as a request body</td></tr>
    <tr><td><tt>QOAuth::ParseForHeaderArguments</tt></td>      <td>irrelevant</td>          <td>ready to be set as an argument for the \c Authorization HTTP header</td></tr>
    <tr><td><tt>QOAuth::ParseForSignatureBaseString</tt></td>  <td>irrelevant</td>          <td><em>meant for internal use</em></td></tr>
  </table>

  \sa inlineParameters()
*/

QByteArray QOAuth::QOAuth::createParametersString( const QString &requestUrl, HttpMethod httpMethod, const QByteArray &token,
                                           const QByteArray &tokenSecret, SignatureMethod signatureMethod,
                                           const ParamMap &params, ParsingMode mode )
{
  Q_D(QOAuth);

  d->error = NoError;

  // copy parameters to a writable object
  ParamMap parameters = params;
  // calculate the signature
  QByteArray signature = d->createSignature( requestUrl, httpMethod, signatureMethod,
                                             token, tokenSecret, &parameters );

  // return an empty bytearray when signature wasn't created
  if ( d->error != NoError ) {
    return QByteArray();
  }

  // append it to parameters
  parameters.insert( QOAuthPrivate::ParamSignature, signature );
  // convert the map to bytearray, according to requested mode
  QByteArray parametersString = d->paramsToString( parameters, mode );

  // add a query separator, this will be a query part of the URL
  if ( httpMethod == GET && mode == ParseForInlineQuery ) {
    parametersString.prepend( '?' );
  }

  return parametersString;
}

/*!
  This method is provided for convenience. It generates an inline query string out of
  given parameter map and prepends it with '?'. The resulting string can be appended
  directly to a request URL as a query string.

  Use this method together with createParametersString(), when you request a header
  parameters string (QOAuth::ParseForHeaderArguments) together with HTTP GET method.
  In such case, apart from header arguments, you must provide a query string containing
  custom request parameters (i.e. not OAuth-related). Pass the custom parameters map
  to this method to receive a query string to be appended to the URL.

  \sa createParametersString()
*/

QByteArray QOAuth::QOAuth::inlineParameters( const ParamMap &params )
{
  Q_D(QOAuth);

  QByteArray query = d->paramsToString( params, ParseForInlineQuery );
  return query.prepend( '?' );
}

QOAuth::ParamMap QOAuth::QOAuthPrivate::sendRequest( const QString &requestUrl, HttpMethod httpMethod,
                                                     SignatureMethod signatureMethod, const QByteArray &token,
                                                     const QByteArray &tokenSecret, const ParamMap &params )
{
  if ( httpMethod != GET && httpMethod != POST ) {
    qWarning() << __FUNCTION__ << "- requestToken() and accessToken() accept only GET and POST methods";
    error = UnsupportedHttpMethod;
    return ParamMap();
  }

  error = NoError;

  ParamMap parameters = params;
  // create signature
  QByteArray signature = createSignature( requestUrl, httpMethod, signatureMethod,
                                             token, tokenSecret, &parameters );

  // if signature wasn't created, return an empty map
  if ( error != NoError ) {
    return ParamMap();
  }

  // add signature to parameters
  parameters.insert( QOAuthPrivate::ParamSignature, signature );

  QByteArray authorizationHeader;
  QNetworkRequest request;

  if ( httpMethod == GET ) {
    authorizationHeader = paramsToString( parameters, ParseForHeaderArguments );
    // create the authorization header
    request.setRawHeader( "Authorization", authorizationHeader );
  } else if ( httpMethod == POST ) {
    authorizationHeader = paramsToString( parameters, ParseForInlineQuery );
    // create a network request
    request.setHeader( QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded" );
  }

  request.setUrl( QUrl( requestUrl ) );

  // fire up a single shot timer if timeout was specified
  if ( requestTimeout > 0 ) {
    QTimer::singleShot( requestTimeout, loop, SLOT(quit()) );
    // if the request finishes on time, the error value is overriden
    // if not, it remains equal to QOAuth::QOAuth::Timeout
    error = Timeout;
  }

  // clear the reply container and send the request
  replyParams.clear();
  QNetworkReply *reply;
  if ( httpMethod == GET ) {
    reply = manager->get( request );
  } else if ( httpMethod == POST ) {
    reply = manager->post( request, authorizationHeader );
  }

  // start the event loop and wait for the response
  loop->exec();

  // if request completed successfully, error is different than QOAuth::QOAuth::Timeout
  // if it failed, we have to abort the request
  if ( error == Timeout ) {
    reply->abort();
  }

  return replyParams;
}

QByteArray QOAuth::QOAuthPrivate::createSignature( const QString &requestUrl, HttpMethod httpMethod,
                                                   SignatureMethod signatureMethod, const QByteArray &token,
                                                   const QByteArray &tokenSecret, ParamMap *params )
{
  if ( consumerKey.isEmpty() ) {
    qWarning() << __FUNCTION__ << "- consumer key is empty, make sure that you set it with QOAuth::QOAuth::setConsumerKey()";
    error = ConsumerKeyEmpty;
    return QByteArray();
  }
  if ( consumerSecret.isEmpty() ) {
    qWarning() << __FUNCTION__ << "- consumer secret is empty, make sure that you set it with QOAuth::QOAuth::setConsumerSecret()";
    error = ConsumerSecretEmpty;
    return QByteArray();
  }

  // temporarily only HMAC-SHA1 is supported
  if ( signatureMethod != HMAC_SHA1 ) {
    qWarning() << __FUNCTION__ << "- Sorry, we currently support only HMAC-SHA1 method...";
    error = UnsupportedSignatureMethod;
    return QByteArray();
  }


  QCA::Initializer init;

  if( !QCA::isSupported( "hmac(sha1)" ) ) {
    qFatal( "HMAC(SHA1) is not supported!" );
  }

  // create nonce
  QCA::InitializationVector iv( 16 );
  QByteArray nonce = iv.toByteArray().toHex();

  // create timestamp
  uint time = QDateTime::currentDateTime().toTime_t();
  QByteArray timestamp = QByteArray::number( time );

  // create signature base string
  // 1. create the method string
  QByteArray httpMethodString = httpMethodToString( httpMethod );
  // 2. prepare percent-encoded request URL
  QByteArray percentRequestUrl = requestUrl.toAscii().toPercentEncoding();
  // 3. prepare percent-encoded parameters string
  params->insert( QOAuthPrivate::ParamConsumerKey, consumerKey );
  params->insert( QOAuthPrivate::ParamNonce, nonce );
  params->insert( QOAuthPrivate::ParamSignatureMethod,
                  signatureMethodToString( signatureMethod ) );
  params->insert( QOAuthPrivate::ParamTimestamp, timestamp );
  params->insert( QOAuthPrivate::ParamVersion, QOAuthPrivate::OAuthVersion );
  // append token only if it is defined (requestToken() doesn't use a token at all)
  if ( !token.isEmpty() ) {
    params->insert( QOAuthPrivate::ParamToken, token );
  }

  QByteArray parametersString = paramsToString( *params, ParseForSignatureBaseString );
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
