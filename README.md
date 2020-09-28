# TLS-SE

TLS-SE is an implentation of TLS1.3 in Secure Element according to the IETF draft draft-urien-tls-se (https://datatracker.ietf.org/doc/draft-urien-tls-se/)

tls_se.java is the TLS-SE implementation for javacard 3.04

server.java is a simple TCP/IP demonstration server for TLS-SE

Ethereum Certfificate for tls-se.java: Tx= 0x5b7ee4d93cc93f9561b2c3e1d79447827df798de14e394ce484f9b7d6e8530fd nonce=20

The command file load_tls_se_304.bat downloads the TLS-SE capfile (tlsse.cap) in a Javacard 3.04

The command file test_tls_se.bat runs an off-line test for TLS-SE smartcard

The command file run_server_tls_se.bat starts a TLS-SE server (i.e. servertlsse.jar)

The command file openssl_client_tls13_psk.bat runs an openssl TLS1.3 client.

The command file make_tls_se_304.bat compile tls-se.java and produces the tlsse.cap file. It requires a java compiler (JDK 1.6) and an oracle javacard 3.04 dev kit.

![TLS_IM Device](https://github.com/purien/TLS-SE/blob/master/tls_im_device.jpg)
