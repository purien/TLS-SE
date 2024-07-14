# TLS-SE
TLS-SE is an implentation of TLS1.3 in Secure Element according to the IETF draft draft-urien-tls-se, https://datatracker.ietf.org/doc/draft-urien-tls-se/
### tls_se.java
The TLS-SE implementation for javacard 3.04
https://github.com/purien/TLS-SE/blob/master/src/tls_se.java
### Ethereum Certificate for tls-se.java
Tx= 0x5b7ee4d93cc93f9561b2c3e1d79447827df798de14e394ce484f9b7d6e8530fd nonce=20
https://etherscan.io/tx/0x5b7ee4d93cc93f9561b2c3e1d79447827df798de14e394ce484f9b7d6e8530fd
### server.java 
A simple TCP/IP demonstration server for TLS-SE
https://github.com/purien/TLS-SE/blob/master/src/server.java
### load_tls_se_304.bat
This command file   downloads the TLS-SE capfile (tlsse.cap) in a Javacard 3.04
### test_tls_se.bat
This command file runs an off-line test for TLS-SE smartcard
### run_server_tls_se.bat
This command file  starts a TLS-SE server (i.e. servertlsse.jar)
### openssl_client_tls13_psk.bat
This command file runs an openssl TLS1.3 client.
### make_tls_se_304.bat
This command file compiles tls-se.java and produces the tlsse.cap file. 
It requires a java compiler (JDK 1.6) and an oracle javacard 3.04 dev kit.
Javacard dev kit: https://www.oracle.com/java/technologies/javacard-sdk-downloads.html
### im.java
The TLS-IM implementation in javacard, of the the IETF draft https://tools.ietf.org/html/draft-urien-tls-im-00
### make_im
This command file compiles im.java and produces the im.cap file. 
### load_im.bat
This command file downloads the IM capfile (im.cap) in a Javacard
### i2c_v1.ino
This Arduino sketch implements all procedure required by the TLS-IM draft. It has been tested with Arduino Uno R3, Arduino ATMEGA2560 and ESP8266.
### TLS-SE device for IoT
TLS-SE device for IoT provides a serial interface with a TLS-SE javacard. 
Device firmware integrity is checked by remote attestation algorithm (bMAC).
https://github.com/purien/bMAC/blob/master/README.md
Device MCU is identified by static and dynamic PUF.
https://github.com/purien/DynamicPuf/blob/master/README.md

![TLS-SE Device](https://github.com/purien/TLS-SE/blob/master/tls_se_device.jpg)

![TLS-SE Device](https://github.com/purien/TLS-SE/blob/master/sucette_s.jpg)

### TLS-IM-SE Javacard Board
This board designed with EAGLE implements a TLS1.3 server using a javacard according to draft TLS-IM and TLS-SE

![TLS-IM-SE Javacard Board](https://github.com/purien/TLS-SE/blob/master/tls-im-se-javacard_board.jpg)

### TLS-SE LeMonolith Board
This board designed with EAGLE implements a TLS1.3 server using a javacard according to IETF draft TLS-SE

![TLS-IM-SE LeMonoltih Board](https://github.com/purien/TLS-SE/blob/master/LeMonolith001.jpg)

### TLS-IM-SE Javacards I2C Bus Board
This board designed with EAGLE implements a TLS1.3 server using a set of javacard over I2C bus according to draft TLS-SE

![TLS-IM-SE Javacards I2C Board](https://github.com/purien/TLS-SE/blob/master/i2cgrid01s.jpg)

### TLS-IM SE050 Board
This board implements a TLS1.3 server using a NXP SE050 secure element

![TLS-IM SE050 Board](https://github.com/purien/TLS-SE/blob/master/tls-im_SE050_board.jpg)





