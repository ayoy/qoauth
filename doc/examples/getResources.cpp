QByteArray url( "http://example.com/get_photo" );
// create a request parameters map
QOAuth::ParamMap map;
map.insert( "file", "flower_48.jpg" );
map.insert( "size", "small" );

// construct the parameters string
QByteArray content =
    qoauth->createParametersString( requestUrl, QOAuth::GET, QOAuth::HMAC_SHA1,
                                    token, tokenSecret, map,
                                    QOAuth::ParseForInlineQuery );
// append parameters string to the URL
url.append( content );
QNetworkRequest request( QUrl( url ) );
// etc...
