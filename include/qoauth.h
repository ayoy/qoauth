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


#ifndef QOAUTH_H
#define QOAUTH_H

#include <QObject>
#include <QMultiMap>

#include "qoauth_global.h"

class QOAuthPrivate;

class QOAUTH_EXPORT QOAuth : public QObject
{
  Q_OBJECT

  Q_PROPERTY( QByteArray consumerKey READ consumerKey WRITE setConsumerKey )
  Q_PROPERTY( QByteArray consumerSecret READ consumerSecret WRITE setConsumerSecret )
  Q_PROPERTY( uint requestTimeout READ requestTimeout WRITE setRequestTimeout )
  Q_PROPERTY( int error READ error )

public:
  enum SignatureMethod {
    HMAC_SHA1,
    RSA_SHA1,
    PLAINTEXT
  };

  enum HttpMethod {
    GET,
    POST,
    HEAD,
    PUT,
    DELETE
  };
  
  enum ParsingMode {
    ParseForInlineQuery,
    ParseForSignatureBaseString = ParseForInlineQuery,
    ParseForHeaderArguments
  };

  enum ErrorCode {
    NoError = 200,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    Timeout = 1,
    ConsumerKeyEmpty,
    ConsumerSecretEmpty,
    UnsupportedSignatureMethod,
    UnsupportedHttpMethod,
    OtherError
  };

  typedef QMultiMap<QByteArray,QByteArray> ParamMap;

  static const QByteArray OAuthVersion;

  static const QByteArray ParamConsumerKey;
  static const QByteArray ParamNonce;
  static const QByteArray ParamSignature;
  static const QByteArray ParamSignatureMethod;
  static const QByteArray ParamTimestamp;
  static const QByteArray ParamVersion;
  static const QByteArray ParamToken;
  static const QByteArray ParamTokenSecret;
  static const QByteArray ParamAccessToken;

  QOAuth( QObject *parent = 0 );
  virtual ~QOAuth();

  QByteArray consumerKey() const;
  void setConsumerKey( const QByteArray &consumerKey );

  QByteArray consumerSecret() const;
  void setConsumerSecret( const QByteArray &consumerSecret );

  uint requestTimeout() const;
  void setRequestTimeout( uint requestTimeout );

  int error() const;

  ParamMap requestToken( const QString &requestUrl, HttpMethod httpMethod,
                         SignatureMethod signatureMethod = HMAC_SHA1, const ParamMap &params = ParamMap() );

  ParamMap accessToken( const QString &requestUrl, HttpMethod httpMethod, const QByteArray &token,
                        const QByteArray &tokenSecret, SignatureMethod signatureMethod = HMAC_SHA1,
                        const ParamMap &params = ParamMap() );

  QByteArray createParametersString( const QString &requestUrl, QOAuth::HttpMethod httpMethod, QOAuth::SignatureMethod signatureMethod,
                                     const QByteArray &token, const QByteArray &tokenSecret,
                                     const QOAuth::ParamMap &params, QOAuth::ParsingMode mode );

protected:
  QOAuthPrivate *d_ptr;

private:
  Q_DECLARE_PRIVATE(QOAuth)
};

#endif // QOAUTH_H
