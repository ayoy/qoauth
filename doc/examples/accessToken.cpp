// if necessary, create a map of additional arguments required by the Service Provider
QOAuth::ParamMap otherArgs;
otherArgs.insert( "misc_arg1", "value1" );
otherArgs.insert( "misc_arg2", "value2" );

// send a request to exchange Request Token for an Access Token
QOAuth::ParamMap reply =
    qoauth->accessToken( "http://example.com/access_token", QOAuth::POST, token,
                         tokenSecret, QOAuth::HMAC_SHA1, otherArgs );

// if no error occurred, read the Access Token (and other arguments, if applicable)
if ( qoauth->error() == QOAuth::NoError ) {
  token = reply.value( QOAuth::tokenParameterName() );
  tokenSecret = reply.value( QOAuth::tokenSecretParameterName() );
  otherInfo = reply.value( "misc_arg3" );
}
