# TLS-SE
TLS-SE is an implentation of TLS1.3 in Secure Element according to the IETF draft draft-urien-tls-se, https://datatracker.ietf.org/doc/draft-urien-tls-se/
### tls_se.java
The TLS-SE implementation for javacard 3.04
https://github.com/purien/TLS-SE/blob/master/src/tls_se.java
### server.java 
A simple TCP/IP demonstration server for TLS-SE
https://github.com/purien/TLS-SE/blob/master/src/server.java
Ethereum Certfificate for tls-se.java: Tx= 0x5b7ee4d93cc93f9561b2c3e1d79447827df798de14e394ce484f9b7d6e8530fd nonce=20
### load_tls_se_304.bat
This command file   downloads the TLS-SE capfile (tlsse.cap) in a Javacard 3.04
### test_tls_se.bat
This command file runs an off-line test for TLS-SE smartcard
### run_server_tls_se.bat
This command file  starts a TLS-SE server (i.e. servertlsse.jar)
### openssl_client_tls13_psk.bat
This command file runs an openssl TLS1.3 client.
### make_tls_se_304.bat
This command file compiles tls-se.java and produces the tlsse.cap file. It requires a java compiler (JDK 1.6) and an oracle javacard 3.04 dev kit.
### TLS-SE device for IoT
TLS-SE device for IoT provides a serial interface with a TLS-SE javacard. Firmware integrity is checked by remote attestation algorithm (bMAC). MCU is identified by static and dynamic PUF.
![TLS-SE Device](https://github.com/purien/TLS-SE/blob/master/tls_se_device.jpg)
