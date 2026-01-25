/* Disable server functionality */  
#undef MBEDTLS_SSL_SRV_C  
  
/* Disable DTLS and related features */  
#undef MBEDTLS_SSL_PROTO_DTLS  
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY  
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY  
#undef MBEDTLS_SSL_DTLS_SRTP  
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE  
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID