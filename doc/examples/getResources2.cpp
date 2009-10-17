QByteArray url( "http://example.com/get_photo" );
// create a request parameters map
QOAuth::ParamMap map;
map.insert( "file", "flower_48.jpg" );
map.insert( "size", "small" );

// construct the authorization header
QByteArray header =
    qoauth->createParametersString( requestUrl, QOAuth::GET, QOAuth::HMAC_SHA1,
                                    token, tokenSecret, map,
                                    QOAuth::ParseForHeaderArguments );
// append parameters string to the URL
// alternatively you can use QOAuth::ParseForRequestContent if you want
// to use the output as a POST request content (remember then of passing
// QOAuth::POST above).
url.append( qoauth->inlineParameters( map, QOAuth::ParseForInlineQuery ) );
QNetworkRequest request( QUrl( url ) );
request.setRawHeader( "Authorization", header );
// etc...
