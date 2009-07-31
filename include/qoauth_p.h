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


#ifndef QOAUTH_P_H
#define QOAUTH_P_H

#include "qoauth.h"
#include <QObject>

class QNetworkAccessManager;
class QNetworkReply;
class QEventLoop;

namespace QOAuth {

class QOAuth;


class QOAuthPrivate : public QObject
{
  Q_OBJECT
  Q_DECLARE_PUBLIC(QOAuth)

public:
  enum Operation {
    RequestToken,
    Authorize,
    Authenticate,
    AccessToken
  };

  static const QByteArray ParamConsumerKey;
  static const QByteArray ParamNonce;
  static const QByteArray ParamSignature;
  static const QByteArray ParamSignatureMethod;
  static const QByteArray ParamTimestamp;
  static const QByteArray ParamVersion;


  QOAuthPrivate( QObject *parent = 0 );
  QByteArray httpMethodToString( QOAuth::HttpMethod method );
  QByteArray signatureMethodToString( QOAuth::SignatureMethod method );
  ParamMap replyToMap( const QByteArray &data );
  QByteArray paramsToString( const ParamMap &parameters, QOAuth::ParsingMode mode );


  QByteArray createSignature( const QString &requestUrl, QOAuth::HttpMethod httpMethod,
                              QOAuth::SignatureMethod signatureMethod, const QByteArray &token,
                              const QByteArray &tokenSecret, ParamMap *params );

  ParamMap sendRequest( const QString &requestUrl, QOAuth::HttpMethod httpMethod, QOAuth::SignatureMethod signatureMethod,
                                const QByteArray &token, const QByteArray &tokenSecret, const ParamMap &params );


  QByteArray consumerKey;
  QByteArray consumerSecret;

  ParamMap replyParams;

  QNetworkAccessManager *manager;
  QEventLoop *loop;

  uint requestTimeout;
  int error;


public slots:
  void parseReply( QNetworkReply *reply );

protected:
  QOAuth *q_ptr;
};

} // namespace QOAuth

#endif // QOAUTH_P_H
