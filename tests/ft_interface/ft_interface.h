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


#ifndef FT_INTERFACE_H
#define FT_INTERFACE_H

#include <QObject>
#include <QEventLoop>

class MyEventLoop : public QEventLoop
{
    Q_OBJECT
public:
    bool timeout() const;
    int exec( ProcessEventsFlags flags = AllEvents );
public slots:
    void quitWithTimeout();
private:
    bool m_timeout;
};

namespace QOAuth {

class Interface;

class Ft_Interface : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void init();
    void cleanup();

    void requestToken_data();
    void requestToken();

    void requestTokenRSA_data();
    void requestTokenRSA();

    void accessToken_data();
    void accessToken();

    void accessTokenRSA_data();
    void accessTokenRSA();

    void accessResources_data();
    void accessResources();

    void accessResourcesRSA_data();
    void accessResourcesRSA();

private:
    Interface *m;
};

} // namespace QOAuth

#endif // FT_INTERFACE_H
