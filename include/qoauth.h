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


/*!
  \file qoauth.h

  This file is a part of libqoauth. You should not include it directly in your
  application. Instead please use <tt>\#include <QtOAuth></tt>.
*/

#ifndef QOAUTH_H
#define QOAUTH_H

#include <QObject>
#include <QMultiMap>

#include "qoauth_global.h"

namespace QOAuth {

class QOAuthPrivate;

typedef QMultiMap<QByteArray,QByteArray> ParamMap;


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
    ParseForHeaderArguments,
    ParseForSignatureBaseString
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

  static const QByteArray OAuthVersion;

  static const QByteArray ParamToken;
  static const QByteArray ParamTokenSecret;

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

  QByteArray createParametersString( const QString &requestUrl, QOAuth::HttpMethod httpMethod, const QByteArray &token,
                                     const QByteArray &tokenSecret, QOAuth::SignatureMethod signatureMethod,
                                     const ParamMap &params, QOAuth::ParsingMode mode );

  QByteArray inlineParameters( const ParamMap &params );

protected:
  QOAuthPrivate * const d_ptr;

private:  
  Q_DECLARE_PRIVATE(QOAuth)

#ifdef UNIT_TEST
  friend class Ut_QOAuth;
  friend class Ft_QOAuth;
#endif
};

} // namespace QOAuth

#endif // QOAUTH_H
