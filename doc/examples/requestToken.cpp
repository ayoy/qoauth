QByteArray token;
QByteArray tokenSecret;

QOAuth qoauth = new QOAuth;
// set the consumer key and secret
qoauth->setConsumerKey( "75b3d557c9268c49cfdf041a" );
qoauth->setConsumerSecret( "fd12803fbf0760d34cd2ceb9955199ce" );

// send a request for an unauthorized token
QOAuth::ParamMap reply =
    qoauth->requestToken( "http://example.com/request_token",
                          QOAuth::GET, QOAuth::HMAC_SHA1 );

// if no error occurred, read the received token and token secret
if ( qoauth->error() == QOAuth::NoError ) {
  token = reply.value( QOAuth::ParamToken );
  tokenSecret = reply.value( QOAuth::ParamTokenSecret );
}

