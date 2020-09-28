openssl s_client  -tls1_3     -connect 127.0.0.1:444 -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256  -debug -tlsextdebug -msg  -sess_out sess.pem -keylogfile secrets.txt -no_ticket -psk 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
PAUSE

