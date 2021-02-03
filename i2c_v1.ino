/* i2c_v1.ino*/
/* Copyright (C) 2021 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 * This software is an example of I2C interface for secure element SE050
 * Tested with Arduino UNO R3, ATMEGA256, ESP8266
 * Securiry procedures for TLS1.3 as defined in 
 * https://tools.ietf.org/html/draft-urien-tls-im-04
 */


#if defined(ESP8266) || defined(ESP32)
#include <ESP8266WiFi.h>

#define SE_VDD    D5
#define SE_SDA    D6
#define SE_SCL    D7
#define BAUDRATE  76800
#define I2C_CLK   400000

#else
// #define SE_VDD    22
#define SE_VDD    5
#define BAUDRATE  115200
#define I2C_CLK 100000
#endif
#include <Wire.h>

//UM11225,NXP SE05x T=1 Over I2C Specification
//HD shall start the frame with I2C start condition and end with I2C stop condition. 
//HD shall not use repeated start to send/receive any frame. 
//HD shall send the complete T=1 frame in one fragment (in one I2C write cycle).



// CRC: ISO/IEC 13239
// C CODE: iso-15693-3, Annex D1
// See https://stackoverflow.com/questions/18330692/iso-iec13239-crc16-implementation

// In ...\hardware\arduino\avr\libraries\Wire\src\Wire.h change line 28 to:
// #define BUFFER_LENGTH 128
// In ...\hardware\arduino\avr\libraries\Wire\src\utility\twi.h change line 32 to:
// #define TWI_BUFFER_LENGTH 128

// UNO        SDA=A4 SCL=A5
// ATMEGA2560 SDA=20 SCL=21
// ESP8266 SDA=D2 SCL=D1, Wire.begin([SDA], [SCL]).  D5 D6 D7
// LEONARDO Leonardo  SDA=2 SCL=3


//Tx: 5A 00/40 LEN INFO CRC
//Rx: A5 00/40 LEN INFO CRC

//5A CF  00  CRC  Soft Reset Request
//A5 EF LEN  ATR  CRC

#define ID_FSK   0xF0 
#define ID_DSK   0xD0
#define ID_PRIV  0x10
#define ID_PUB   0x20
#define ID_EKEY  0xE0
#define ID_PRIV1 0x11
#define ID_PUB1  0x12
#define ID_PRIV2 0x21
#define ID_PUB2  0x22

#define MAXI2C  128

char i2c_rxbuf[128]   ;
bool i2c_fdebug=true  ;
bool t1_ns=false      ;
int i2c_ptrx=0;
#define SE_ADR    0x48


char testcrc[6]= {1,2,3,4,0x91,0x39};
uint16_t crc16(char *data, int len) ;


const char mypsk[32]   PROGMEM = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
const char mypriv[32]  PROGMEM = {0x2E, 0x86, 0xBD, 0xD6, 0xD3, 0xB2, 0x41, 0xDD, 0xBD, 0x00, 0x99, 0x9F, 0x6A, 0x0A, 0xC1, 0xCB, 0x54, 0x6D, 0x2B, 0xFB,\
                                  0x55, 0x74, 0x4D, 0xCA, 0x40, 0xF0, 0x26, 0x8A, 0xC2, 0xBF, 0x73, 0x38};

const char mypub[65]  PROGMEM ={0x04, 0x5C, 0x8C, 0x90, 0xD0, 0x85, 0x9D, 0xD9, 0x6C, 0x72, 0x2A, 0x58, 0x9C, 0x4B, 0x62, 0x04, 0x7F, 0xF0, 0x13, 0x23,\
                                0xCC, 0x74, 0x38, 0x3E, 0x0E, 0x8E, 0xB8, 0x0B, 0xEA, 0x4E, 0xA4, 0x5E, 0x55, 0xB8, 0x54, 0x99, 0xAB, 0xD3, 0x9D, 0x71,\
                                0x98, 0x85, 0xE8, 0x74, 0xED, 0x3F, 0x63, 0x27, 0x96, 0x0D, 0x51, 0x9B, 0xA2, 0x54, 0x23, 0xC3, 0xFB, 0xDC, 0x14, 0xE6,\
                                0xFD, 0x0C, 0xD5, 0xED, 0xEE};

const char mypriv1[32] PROGMEM = {0x44, 0x33, 0x9F, 0x29, 0x9B, 0x09, 0xAD, 0x74, 0x3B, 0x9F, 0x69, 0xD3, 0x36, 0x54, 0x05, 0x7C, 0xA5, 0x04, 0x19, 0xD6,\
                                  0x4F, 0xCC, 0x82, 0x35, 0xFB, 0x3C, 0x5D, 0x86, 0x25, 0x69, 0xD6, 0x9C};
                                  
const char mypub1[65] PROGMEM = {0x04, 0xF0, 0xC2, 0xA4, 0x94, 0x2A, 0xB1, 0xAA, 0x0F, 0x4A, 0x45, 0x58, 0xE2, 0x3F, 0x5C, 0xD1, 0xF0, 0xBC, 0x7A, 0x15,\
                                 0x44, 0xD1, 0x2E, 0x32, 0xEA, 0x67, 0x4F, 0xE5, 0xE5, 0x42, 0xB5, 0x04, 0x93, 0x40, 0xC5, 0x9A, 0x83, 0x87, 0x8C, 0x9D,\
                                 0xA5, 0xE6, 0x9B, 0x8F, 0x7D, 0xCA, 0x78, 0x5C, 0xAD, 0xFD, 0xF0, 0x3D, 0x26, 0xA5, 0xDE, 0xB8, 0xC1, 0xD5, 0xBB, 0x9C, \
                                 0x26, 0xC3, 0x6F, 0x43, 0x41};

const char mypriv2[32] PROGMEM = {0xCF, 0xEB, 0xA5, 0xFB, 0x77, 0x9C, 0x84, 0xED, 0x89, 0xEF, 0x36, 0x4B, 0x89, 0x2E, 0x91, 0x6F, 0x52, 0xCE, 0x6B, 0xC2,\
                                  0x0F, 0x3A, 0x85, 0x61, 0x29, 0xEE, 0xDE, 0x4D, 0x1D, 0x07, 0xBD, 0xCB};
const char mypub2[65] PROGMEM =  {0x04, 0x37, 0x23, 0x20, 0x40, 0x74, 0x10, 0x08, 0xCF, 0x07, 0x8D, 0x96, 0xBC, 0x8E, 0xAF, 0xC7, 0x63, 0x65, 0xFC, 0x6A,\
                                  0x98, 0xAF, 0x30, 0x20, 0x3B, 0x60, 0x22, 0x73, 0x98, 0x13, 0x67, 0x7F, 0xA2, 0x6C, 0x1E, 0x01, 0x4A, 0x5F, 0x8C, 0xFA,\
                                  0x67, 0xDD, 0x0D, 0xB7, 0xF9, 0x7B, 0x91, 0x20, 0x23, 0xB8, 0x60, 0x63, 0xE3, 0xB9, 0xBE, 0xAD, 0xC9, 0x5D, 0x9F, 0x1C,\
                                  0x9C, 0xCD, 0x12, 0x09, 0xB6};

const char myFSK[65] PROGMEM =   {0x00,0x20,0x0E,0x74,0x6C,0x73,0x31,0x33,0x20,0x66,0x69,0x6E,0x69,0x73,0x68,0x65,0x64,0x00,0x01};



const char mysha0[32] PROGMEM =  {0xE3,0xB0,0xC4,0x42,0x98,0xFC,0x1C,0x14,0x9A,0xFB,0xF4,0xC8,0x99,0x6F,0xB9,0x24,0x27,0xAE,0x41,0xE4,0x64,0x9B,0x93,0x4C,0xA4,0x95,0x99,0x1B,0x78,0x52,0xB8,0x55};


const char myG[65] PROGMEM = {0x04,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,\
                                   0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};
                        

const char myEK[65] PROGMEM ={0x04,\
     0x38 ,0xa0 ,0x70 ,0x80 ,0xaa ,0x63 ,0x50 ,0xa2 ,0xc2 ,0x84 ,0x29 ,0xe8 ,0x21, 0x1a ,0x84 ,0x0a ,\
     0x2c ,0xed ,0x57 ,0x56 ,0x06 ,0xfb ,0x1c ,0xe0 ,0xb3 ,0x6b ,0x23 ,0xe2 ,0x53, 0x77 ,0xc5 ,0x78 ,\
     0xbe ,0xea ,0x2f ,0xe7 ,0x47 ,0xd4 ,0x22 ,0xe7 ,0xda ,0x35 ,0x24 ,0xd8 ,0xed, 0x5e ,0x02 ,0x2d ,\
     0x1b ,0xea ,0x9f ,0xb3 ,0x2f ,0x20 ,0x2b ,0xff ,0x91 ,0xb8 ,0x2d ,0x6c ,0x91, 0xf6 ,0x16 ,0x64};

const char myhash[32] PROGMEM = {\
       0xE4,0x79,0x37,0x0A,0xF6,0xF7,0x43,0xA3,0xC2,0xAB,0xBC,0xBA,0x4B,0x67,0xBD,0x01,
       0x6C,0xD0,0x20,0x7D,0x2A,0xDF,0xCC,0x52,0x60,0xEB,0xCB,0xAF,0x01,0x75,0xED,0xB9};

bool i2c_tx(char pcb,int len,char *buf, int dt)
{ uint16_t mycrc=0;
  buf[0]= 0x5A;
  if (pcb == (char)0)
  {
  if (t1_ns) { t1_ns=false; pcb = (char)0x40;}
  else      t1_ns=true;  
  }
  buf[1]= pcb ;
  buf[2]= 0xFF & len;
  mycrc= crc16(buf,len+3);
  buf[3+len]= 0xFF & mycrc ;
  buf[4+len]= 0xFF & (mycrc >> 8);

  if (i2c_fdebug)
  myPrintf("Tx",buf,5+len);
  
  i2c_ptrx=0;

  int nb,c,pt=0;
  nb= 5+len;

  if (nb > MAXI2C)
  {
  if (i2c_fdebug) Serial.print("Tx Size Error");
  return false;  
  }
  

  while(nb > 0)
  {
  if (nb > MAXI2C)
  {
  Wire.beginTransmission(SE_ADR);
  Wire.write(buf+pt,MAXI2C);
  c=Wire.endTransmission(false) ;
  nb-=MAXI2C;
  pt+=MAXI2C;
  }
  else
  {
  Wire.beginTransmission(SE_ADR);
  Wire.write(buf+pt,nb);
  c=Wire.endTransmission();
  nb=0;
  }
 
  if (c != 0) 
  { if (i2c_fdebug) {Serial.print("Tx Error: ");Serial.println(c);}
    return false;
  }
  }

  int v=0;
  nb=3;
  
int tt=0,dt0=1;
Wire.requestFrom(SE_ADR,nb);

while(Wire.available() != nb) 
{ delay(dt0);
  Wire.requestFrom(SE_ADR,nb);
  tt += dt0;
  if (tt > dt) 
  { if (i2c_fdebug) Serial.println("I2C Timeout !");
    return false;
  }
}

if (i2c_fdebug)
{Serial.print("dt= ");Serial.println(tt);}

while(Wire.available()>0) 
{ v= Wire.read();
  i2c_rxbuf[i2c_ptrx] = v & 0xFF ;
  i2c_ptrx++;
  nb--;
}

//if (i2c_fdebug) myPrintf("Rx",i2c_rxbuf,i2c_ptrx);
  
nb= (0xFF & i2c_rxbuf[2]) +2;

while (nb>0)
{

if (nb > MAXI2C)
{ Wire.requestFrom(SE_ADR,MAXI2C);
  nb-=MAXI2C;
}

else
{ Wire.requestFrom(SE_ADR,nb);
  nb=0;
}
while(Wire.available() >0) 
{ //if (i2c_fdebug) Serial.println(Wire.available());
  v= Wire.read();
  i2c_rxbuf[i2c_ptrx] = v & 0xFF ;
  i2c_ptrx++;
}
}


mycrc = crc16(i2c_rxbuf,i2c_ptrx-2);
if (i2c_fdebug)
{myPrintf("rx",i2c_rxbuf,i2c_ptrx);
 // myPrintf("crc",(char *)&mycrc,2); 
}

if ( (i2c_rxbuf[i2c_ptrx-2] != (char)(0xFF & mycrc) ) || (i2c_rxbuf[i2c_ptrx-1] != (char)(0xFF & (mycrc>>8))) )
{ if (i2c_fdebug) Serial.println("Error CRC !");
  return false;
}

if (i2c_rxbuf[0] != (char)0xA5)
{ if (i2c_fdebug) Serial.println("Error NAD !");
  return false;
}

// 1 0 0 N(R) 0 0 Error code
if ( ( (i2c_rxbuf[1] & (char)0xE0) == (char)0x80 ) && ( (i2c_rxbuf[1] & (char)0x3) != (char)0 ))
{ if (i2c_fdebug) { Serial.print("Error PCB= ");Serial.println(i2c_rxbuf[1] & 3);}
  return false;
}

bool ft1=false ;
if ( (i2c_rxbuf[1] == (char)0x00) || (i2c_rxbuf[1] == (char)0x40) ) ft1=true;

if (i2c_fdebug) Serial.println("Success");

if (i2c_ptrx == 5) 
{ if (i2c_fdebug) Serial.println("Tx: LEN=0");
  return false;
}

if (!ft1) return false;
if (i2c_ptrx < 7) return false ;

//if (i2c_fdebug) Serial.println("T=1");

memmove(i2c_rxbuf,i2c_rxbuf+3,i2c_ptrx-5);
len = i2c_ptrx -5;
i2c_ptrx=len     ;

if ( (i2c_rxbuf[len-2] != (char)0x90) || (i2c_rxbuf[len-1] != (char)0x00) )
{if (i2c_fdebug) Serial.println("ISO7816 Error SW");
 return false;
}

if (i2c_rxbuf[0] != (char)0x41)
return true;

//if (i2c_fdebug) Serial.println("Tag=41");


// 41 82 00 xx ...SW1 SW2
int pr=1;
if ( (i2c_rxbuf[1] & (char)0x80) == (char)0x80 )
pr= 1+(i2c_rxbuf[1] & 0x0F);
len = 0xFF & i2c_rxbuf[pr];

//if (i2c_fdebug) Serial.println(len);
//if (i2c_fdebug) Serial.println(pr);
//if (i2c_fdebug) Serial.println(i2c_ptrx);

if ( (pr+1+len) != (i2c_ptrx-2) ) return true;
memmove(i2c_rxbuf,i2c_rxbuf+pr+1,len+2);
i2c_ptrx= len+2;
return true;
}

uint16_t crc16(char *data, int len)
{
  uint16_t current_crc_value = 0xFFFF ;
  for (int i = 0; i < len; i++ )
  {
    current_crc_value ^= ((uint16_t)data[i] & 0xFF);
    for (int j = 0; j < 8; j++)
    {
      if ((current_crc_value & 1) != 0)
      current_crc_value = (current_crc_value >> 1) ^ (uint16_t)0x8408;
      
      else
      current_crc_value = current_crc_value >> 1;
     }
  }
  current_crc_value = ~current_crc_value;

  return current_crc_value & 0xFFFF;
}

int se_apdu(char *apdu, int len)
{
  memmove(i2c_rxbuf+3,apdu,len);
  return len;
}

int se_gena(int id, int curveid)
{ char Apdu[14]= {0x80,0x01,0x61,0x00,0x09,0x41,0x04,0x00,0x00,0x00,0x0A,0x42,0x01,0x03};
  
  Apdu[10]= (char)(0xFF & id);
  int pt=3;
  memmove(i2c_rxbuf+pt,Apdu,sizeof(Apdu));
  return pt-3;
}

int se_set_pub(int id, int curveid, char * key, int lenk)
{ char Apdu[16]= {0x80,0x01,0x21,0x00,0x4C,0x41,0x04,0x00,0x00,0x00,0x10,0x42,0x01,0x03,0x44,0x41} ;

  Apdu[4]=  (char)(0xFF &(11 + lenk));
  Apdu[10]= (char)(0xFF & id) ;
  Apdu[15]= (char)(0xFF & lenk)   ;
  Apdu[13]= (char)(0xFF & curveid);
  int pt=3;
  memmove(i2c_rxbuf+pt,Apdu,sizeof(Apdu));
  pt+= sizeof(Apdu);
  memmove(i2c_rxbuf+pt,key,lenk);
  pt+= lenk ;
  return pt-3;
}

int se_set_priv(int id, int curveid, char * key, int lenk)
{ char Apdu[16]= {0x80,0x01,0x41,0x00,0x2B,0x41,0x04,0x00,0x00,0x00,0x10,0x42,0x01,0x03,0x43,0x20} ;

  Apdu[4]=   (char)(0xFF &(11 + lenk));
  Apdu[10]=  (char)(0xFF & id)  ;
  Apdu[15] = (char)(0xFF & lenk);
  Apdu[13] = (char)(0xFF & curveid);
  int pt=3;
  memmove(i2c_rxbuf+pt,Apdu,sizeof(Apdu));
  pt+= sizeof(Apdu);
  memmove(i2c_rxbuf+pt,key,lenk);
  pt+= lenk ;
  return pt-3;
}



int se_set_skey(int id, char *key, int lenk)
{ char Setk[13]= {0x80,0x01,0x05,0x00,0x28,0x41,0x04,0x00,0x00,0x00,0xF0,0x43,0x20};
  Setk[12]= (char)(lenk &0xFF);
  Setk[10]= (char)(id & 0xFF);
  Setk[4] = (char)(0xFF & (lenk+8));
  int pt=3;
  memmove(i2c_rxbuf+pt,Setk,sizeof(Setk));
  pt+=sizeof(Setk);
  memmove(i2c_rxbuf+pt,key,lenk);
  pt+= lenk;
  return pt-3; 
 
}

int se_set_eskey(int id, char *key, int lenk)
{ char Setk[13]= {0x80,0x81,0x05,0x00,0x28,0x41,0x04,0x00,0x00,0x00,0xF0,0x43,0x20};
  Setk[12]= (char)(lenk &0xFF);
  Setk[10]= (char)(id & 0xFF);
  Setk[4] = (char)(0xFF & (lenk+8));
  int pt=3;
  memmove(i2c_rxbuf+pt,Setk,sizeof(Setk));
  pt+=sizeof(Setk);
  memmove(i2c_rxbuf+pt,key,lenk);
  pt+= lenk;
  return pt-3; 
 }

int se_rnd(int nr)
{ char Rnd[9]= {0x80, 0x04,0x00,0x49,0x04,0x41,0x02,0x00,0x20};
  Rnd[8]= (char)(0xFF & nr);
  memmove(i2c_rxbuf+3,Rnd,sizeof(Rnd));
  return sizeof(Rnd);
}

int se_getekey(int id)
{ char Getekey[11]=   {0x80,0x02,0x00,0x00,0x06,0x41,0x04,0x00,0x00,0x00,0xE0};
  Getekey[10] = (char)(0xff & id) ;
  memmove(i2c_rxbuf+3,Getekey,sizeof(Getekey));
  return sizeof(Getekey);
}  


int se_genekey(int id)
{
 char Genekey[14]=  {0x80,0x81,0x61,0x00,0x09,0x41,0x04,0x00,0x00,0x00,0xE0,0x42,0x01,0x03};
 Genekey[10]= (char)(0xFF & id);
 memmove(i2c_rxbuf+3,Genekey,sizeof(Genekey));
 return sizeof(Genekey);
}


int se_delete(int id)
{  char  Delete[11]= {0x80,0x04,0x00,0x28,0x06,0x41,0x04,0x00,0x00,0x00,0xE0};
   Delete[10] = (char)(id & 0xFF) ;
   memmove(i2c_rxbuf+3,Delete,sizeof(Delete));
   return sizeof(Delete);
}

int se_select()
{ char  Select[]   = {0x00 ,0xA4 ,0x04 ,0x00 ,0x10 ,0xA0 ,0x00 ,0x00 ,0x03 ,0x96 ,0x54 ,0x53 ,0x00 ,0x00 ,0x00 ,0x01 ,0x03 ,0x00 ,0x00 ,0x00 ,0x00};
  memmove(i2c_rxbuf+3,Select,sizeof(Select));
  return sizeof(Select);
}

int se_ecdsa(int id,char * data, int len)
{ char Ecdsa[] = {0x80,0x03,0x0C,0x09,0x2B,0x41,0x04,0x00,0x00,0x00,0x10,0x42,0x01,0x21,0x43,0x20};

  Ecdsa[10]= (char)(0xFF & id);
  int pt=0;
  if ((5+sizeof(Ecdsa)+ len) > sizeof(i2c_rxbuf))
  return -1;
  memmove(i2c_rxbuf+3,Ecdsa,sizeof(Ecdsa));
  pt=3+sizeof(Ecdsa);
  memmove(i2c_rxbuf+pt,data,len);
  pt+= len ;
  
  i2c_rxbuf[7]= (char)((pt-8) & 0xFF) ;
  return pt-3; 
}

int se_ecdh(int id,char *data, int len)
{ char Ecdh[13] = {0x80,0x03,0x01,0x0F,0x49,0x41,0x04,0x00,0x00,0x00,0xE0,0x42,0x41};
  int pt=0;
  
  Ecdh[10] = (char)(0xFF & id);
  if ((5+sizeof(Ecdh)+ len) > sizeof(i2c_rxbuf))
  return -1;
  memmove(i2c_rxbuf+3,Ecdh,sizeof(Ecdh));
  pt=3+sizeof(Ecdh);
  memmove(i2c_rxbuf+pt,data,len);
  pt+= len ;
  
  i2c_rxbuf[7]= (char)((pt-8) & 0xFF) ;
  return pt-3; 
  
}

int se_hmac(int id,char *data, int len)
{ char Fhmac[16]= {0x80,0x03,0x0D,0x45,0x2B,0x41,0x04,0x00,0x00,0x00,0xF0,0x42,0x01,0x19,0x43,0x20};
  int pt=0;

  Fhmac[10]= (char)(0xFF & id);
  Fhmac[15]= (char)(0xFF &len);
  
  if ((5+sizeof(Fhmac)+ len) > sizeof(i2c_rxbuf))
  return -1;
  memmove(i2c_rxbuf+3,Fhmac,sizeof(Fhmac));
  pt=3+sizeof(Fhmac);
  memmove(i2c_rxbuf+pt,data,len);
  pt+= len ;
  
  i2c_rxbuf[7]= (char)((pt-8) & 0xFF) ;
  return pt-3; 
  
}

int se_derive_secret_tls13(int id,char *salt,int lens,int len, char * label, char *data, int lendata,char *secret)
{ char Hkdf[14]= {0x80,0x03,0x00,0x2D,0x3E,0x41,0x04,0x00,0x00,0x00,0xD0,0x42,0x01,0x04};
// 80 03 00 2D 
  int pt=0,lent,leni;
  char *buf;
  
  Hkdf[10]= (char)(0xFF & id);
  
  lent=  (int)strlen(label); // 32
  leni=  4+lent+lendata    ; // 4 + 32 + 32 = 68

  if (i2c_fdebug)
  { Serial.print("TLS13 = ");Serial.println(5+sizeof(Hkdf)+ 2+lens+2+leni+4);}
  
  if ((5+sizeof(Hkdf)+ 2+lens+2+leni+4) > sizeof(i2c_rxbuf))
  return -1;

  memmove(i2c_rxbuf+3,Hkdf,sizeof(Hkdf));
  pt= 3+ sizeof(Hkdf);
  i2c_rxbuf[pt++]=(char)0x43;
  i2c_rxbuf[pt++]= (char)(0xff & lens);
  if (lens !=0) memmove(i2c_rxbuf+pt,salt,lens);
  pt+= lens;
  i2c_rxbuf[pt++]=(char)0x44;
  i2c_rxbuf[pt++]=(char)(0xff & leni);

  buf= i2c_rxbuf+pt;
  
  ///////////////////////////////
  buf[0] = (char)(0xFF & (len >> 8));
  buf[1] = (char)(0xFF & len);
  buf[2] = (char)(0xFF & lent);
  if (lent != 0) memmove(buf+3,label,lent);
  buf[3+lent]= (char)(lendata & 0xFF) ;
  if (lendata !=0)
  memmove(buf+4+lent,data,lendata);
  lent = 5+lent+lendata;
  /////////////////////////////////
  
  pt+=leni;
  i2c_rxbuf[pt++]=(char)0x45;
  i2c_rxbuf[pt++]=(char)0x02;
  i2c_rxbuf[pt++]=(char)0x00;
  i2c_rxbuf[pt++]=(char)(0xFF & len);

  i2c_rxbuf[7]= (char)((pt-8) & 0xFF) ;

  if (!i2c_tx((char)0x00,pt-3,i2c_rxbuf,1000))
  return -1;
  
  memmove(secret,i2c_rxbuf,i2c_ptrx-2);
    
  return i2c_ptrx-2; 
  
 }

int se_hkdf(int id,char *salt,int lens, char* info, int leni)
{ char Hkdf[14]= {0x80,0x03,0x00,0x2D,0x3E,0x41,0x04,0x00,0x00,0x00,0xD0,0x42,0x01,0x04};
  int pt=0;
   
  Hkdf[10]= (char)(0xFF & id);
  
  if ((5+sizeof(Hkdf)+ 2+lens+2+leni+4) > sizeof(i2c_rxbuf))
  return -1;
  memmove(i2c_rxbuf+3,Hkdf,sizeof(Hkdf));
  pt= 3+ sizeof(Hkdf);
  i2c_rxbuf[pt++]=(char)0x43;
  i2c_rxbuf[pt++]=(char)(0xff & lens);
  memmove(i2c_rxbuf+pt,salt,lens);
  pt+= lens;
  i2c_rxbuf[pt++]=(char)0x44;
  i2c_rxbuf[pt++]=(char)(0xff & leni);
  memmove(i2c_rxbuf+pt,info,leni);
  pt+=leni;
  i2c_rxbuf[pt++]=(char)0x45;
  i2c_rxbuf[pt++]=(char)0x02;
  i2c_rxbuf[pt++]=(char)0x00;
  i2c_rxbuf[pt++]=(char)0x20;

  i2c_rxbuf[7]= (char)((pt-8) & 0xFF) ;
  
  return pt-3; 
}




void myPrintf(char *str, char *vli, int size)
{ int i;
  char buf[128];

  if (size <= 0) return ;
  
  sprintf(buf, "%s: %d", str,size);
  Serial.println(buf);
  buf[0] = 0;
  for (i = 0; i < size; ++i)
  {
    sprintf(&buf[strlen(buf)], "%02X", 0xFF & (unsigned)vli[i]);
    if (i % 32 == 31)
    {  Serial.println(buf);
      buf[0] = 0;
    }
  }

  i--;
  if ((i % 32) != 31)
     Serial.println(buf);
}

void test_crc()
{
uint16_t  mycrc= crc16(testcrc, 4);
myPrintf("crc",(char *)&mycrc,2)  ;
}

#if defined(ESP8266) || defined(ESP32)
char * mem2ram(const char * s, char *d, int len)
#else
char * mem2ram(const PROGMEM char * s, char *d, int len)
#endif
{ int i;
   for(i=0;i<len;i++)
   d[i]=pgm_read_byte_far(s+i);
   return d;
}



void perso()
{ 
//char fsk[32]={0xFC, 0xA2, 0x46, 0x90, 0xD1, 0x7D, 0xDE, 0x3F, 0x72, 0x7D, 0x29, 0xD2, 0x18, 0x6A, 0x5F, 0x83, 0xE1, 0xAE, 0xBD, 0x48,\
//0x89, 0xA4, 0x84, 0x17, 0x93, 0x13, 0x91, 0x68, 0xA6, 0x5B, 0xFC, 0xB0};

//char dsk[32]={0xE8, 0xE7, 0xAC, 0x08, 0x71, 0x58, 0xFC, 0x84, 0x40, 0xE4, 0x1A, 0x12, 0x98, 0x9F, 0x91, 0x94, 0x78, 0x37, 0x64, 0xCD,\
//0x5F, 0xC3, 0x65, 0x64, 0x02, 0x80, 0x37, 0xF2, 0xC8, 0x20, 0x6E, 0x96};

int nb=0;
char data[65];

nb = se_select(); i2c_tx((char)0x00,nb,i2c_rxbuf,1000);


nb = se_delete(ID_FSK);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb = se_delete(ID_DSK);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb = se_delete(ID_PRIV);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb = se_delete(ID_PUB);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb = se_delete(ID_PRIV1);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb = se_delete(ID_PUB1);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb = se_delete(ID_PRIV2);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb = se_delete(ID_PUB2);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb = se_delete(0xFF);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);


nb= se_set_priv(ID_PRIV, 3,mem2ram(mypriv,data,32),32) ;i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb= se_set_pub(ID_PUB,   3,mem2ram(mypub,data,65), 65) ;i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb= se_set_priv(ID_PRIV1,3,mem2ram(mypriv1,data,32),32);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb= se_set_pub(ID_PUB1,  3,mem2ram(mypub1,data,65), 65);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb= se_set_priv(ID_PRIV2,3,mem2ram(mypriv2,data,32),32);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb= se_set_pub(ID_PUB2,  3,mem2ram(mypub2,data,65), 65);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);

nb= se_set_eskey(0xFF,mem2ram(mypsk,data,32),32);i2c_tx((char)0x00,nb,i2c_rxbuf,1000) ;
se_derive_secret_tls13(0xFF,NULL,0,32,"tls13 derived",mem2ram(mysha0,data,32),32,data);
myPrintf("dsk",data,32);
nb= se_set_skey(ID_DSK,data,32);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);

nb=se_derive_secret_tls13(0xFF,NULL,0,32,"tls13 ext binder",mem2ram(mysha0,data,32),32,data);
myPrintf("bsk",data,nb);
nb= se_delete(0xFF);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb= se_set_eskey(0xFF,data,32);i2c_tx((char)0x00,nb,i2c_rxbuf,1000) ;

nb= se_hmac(0xFF,mem2ram(myFSK,data,19),19); i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
myPrintf("fsk",i2c_rxbuf,i2c_ptrx-2);
memmove(data,i2c_rxbuf,32);
nb= se_set_skey(ID_FSK,data,32);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
nb= se_delete(0xFF);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);

}

void setup() {
  
Serial.begin(BAUDRATE);

 pinMode(SE_VDD,OUTPUT)  ;
 digitalWrite(SE_VDD,LOW);
 delay(100);
 
 #if defined(ESP8266) || defined(ESP32)
 Wire.begin(SE_SDA,SE_SCL);
 #else
 Wire.begin();
 #endif
 Wire.setClock(I2C_CLK);
 digitalWrite(SE_VDD,HIGH);
 delay(100);

 i2c_fdebug=false;
 perso();
 //digitalWrite(SE_VDD,LOW);
 //return;

 test_crc();

 int nb;
 char data[65];
 for (int i=0;i<32;i++) data[i]= 1+i ;

 // HOT RESET, return ATR
 i2c_tx((char)0xCF,0,i2c_rxbuf,1000);
 myPrintf("i2c_atr",i2c_rxbuf,i2c_ptrx);
 t1_ns=false;
 nb = se_select(); i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 myPrintf("select",i2c_rxbuf,i2c_ptrx);
  
 nb= se_ecdsa(ID_PRIV,data,32);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 myPrintf("ecdsa",i2c_rxbuf,i2c_ptrx-2);
 
 nb = se_delete(ID_EKEY) ;i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 nb = se_genekey(ID_EKEY);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 nb = se_getekey(ID_EKEY);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 myPrintf("ekey",i2c_rxbuf,i2c_ptrx-2);

 //C17ACEA9DEFFB7E537312678464E7538640B893A4CFBF7807D9DFA96D9180838
 nb = se_ecdh(ID_PRIV1,mem2ram(myEK,data,65),65); i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 myPrintf("dh",i2c_rxbuf,i2c_ptrx-2);
 memmove(data,i2c_rxbuf,32);
 //206D85B01FCEA8EA0C44FEE20475FB012F9C0AF0C1B29A54CA04B753AEF62F18
 nb= se_hmac(ID_DSK,data,32); i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 myPrintf("hmac_dh",i2c_rxbuf,i2c_ptrx-2);

 //6B1BF24F43B60DE0597561289D840AA15E83ADA24E7E6C04AB3B10BFAE4D4591
 nb= se_hmac(ID_FSK,mem2ram(myhash,data,32),32); i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 myPrintf("fmac",i2c_rxbuf,i2c_ptrx-2);
 
 nb= se_rnd(32);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 myPrintf("rnd",i2c_rxbuf,i2c_ptrx-2);

 nb=se_hkdf(ID_DSK,"1234",4, "abcd",4);i2c_tx((char)0x00,nb,i2c_rxbuf,1000);
 myPrintf("hkdf",i2c_rxbuf,i2c_ptrx-2);

 digitalWrite(SE_VDD,LOW);

}

void loop() 
{
  // put your main code here, to run repeatedly:
}
