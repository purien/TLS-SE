/* tls_se.java */

/* Copyright (C) 2020 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 *
 * This software is an implementation of TLS13 SEcure Element in Javacard 3.0.4
 * 
 * This software is free use as long as the following conditions are aheared to.  
 * The following conditions apply to all code found in this distribution.
 * 
 * Copyright remains Pascal Urien's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Pascal Urien should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes TLS-SE software written by
 *     Pascal Urien (pascal.urien@gmail.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY PASCAL URIEN ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/////////////////////////
// tls_se Version 1.11 //
/////////////////////////

package com.ethertrust.tlsse ;

import javacard.framework.*;
import javacard.security.* ;
import javacardx.crypto.*  ;
//import org.globalplatform.GPSystem;

/**
 */

public class tls_se extends Applet
{  
	final static byte  INS_BINARY_WRITE  = (byte)  0xD0        ;
	final static byte  INS_BINARY_READ   = (byte)  0xB0        ;
	final static byte  INS_SIGN          = (byte)  0x80        ;
	final static byte  INS_CLEAR_KEYPAIR = (byte)  0x81        ;
	final static byte  INS_GEN_KEYPAIR   = (byte)  0x82        ;
	final static byte  INS_GET_KEY_PARAM = (byte)  0x84        ;
	final static byte  INS_HMAC          = (byte)  0x85        ;
	final static byte  INS_GET_STATUS    = (byte)  0x87        ;
	final static byte  INS_SET_KEY_PARAM = (byte)  0x88        ;
	final static byte  INS_INIT_CURVE    = (byte)  0x89        ;
	final static byte  INS_ECDHE         = (byte)  0x8A        ;
	final static byte  INS_SEND          = (byte)  0xD8        ;
	final static byte  INS_TEST          = (byte)  0xDA;
	final static byte  INS_RND           = (byte)  0x8B        ;
	
	final static byte        INS_SELECT     = (byte) 0xA4 ;
	public final static byte INS_VERIFY     = (byte) 0x20 ;
	public final static byte INS_CHANGE_PIN = (byte) 0x24 ;
	
	public final static short N_KEYS     = (short) 4;
	public final static byte[] VERSION= {(byte)1,(byte)1};
	
	KeyPair[] ECCkp       = null  ;
	Signature ECCsig      = null  ;
	MessageDigest sha256  = null  ;
	MessageDigest sha0    = null  ;
	MessageDigest sha1    = null  ;
	MessageDigest sha2    = null  ;
	RandomData rng        = null  ;
	KeyAgreement ECCkeyAgreement = null  ;
	
    short status=0                                      ;
	byte [] DB = null                                   ;
	byte [] RX = null                                   ;
	public final static short RXSIZE = (short)512       ;
	short [] VS = null;
	public final static short VSSIZE = (short)32 ;
	
	public final static short MAXRXSIZE= (short)240;
	
	final static byte   SW1M    =  (byte)0x9F;    // MORE STATUS
	final static short  LMASK   =  (short)0x0F00; // MASK FOR TLS LENGTH
	
	// VS array variables
	final static short  RXPTR  =  (short)0;
	final static short  TXLEN  =  (short)1;
	final static short  TXSW   =  (short)2;
	final static short  STATE  =  (short)3;
	final static short  MODE   =  (short)4;
	final static short  SIDLEN =  (short)5;
	final static short  SEQ1   =  (short)6;
	final static short  SEQ2   =  (short)7;
    final static short  STATE_RECV  =  (short)8;
	final static short  RECV_WAITING_LEN =  (short)9;
	final static short  RECV_REQUEST_LEN =  (short)10;
	
	// TLS STATE
	final static short  S_READY       = (short)0;
	final static short  S_EXTENSION   = (short)1;
	final static short  S_SFINISHED   = (short)2;
	final static short  S_CCS         = (short)3;
	final static short  S_CFINISHED   = (short)5;
	final static short  S_OPEN        = (short)6;
	final static short  S_RECV_WAITING  = (short)20;
	final static short  S_OFF           = (short)15;
	
	
	// ALLOCATION in DB Array
	final static short  DBX_SIZE      = (short)64;
	final static short  DB_BUFX       = (short)160;
	final static short  DB_S0         = (short)(160+DBX_SIZE);
	final static short  DB_S1         = (short)(DB_S0+32);
	final static short  DB_S2         = (short)(DB_S1+32);
	final static short  DB_IV1        = (short)(DB_S2+32);
	final static short  DB_IV2        = (short)(DB_IV1+12);
	final static short  DBSIZE        = (short)(DB_IV2+12);
	
	final static short  DB_DH         =  DB_S0;
	final static short  DB_PK         = (short)0;
	final static short  DB_SID        = (short)(DB_PK+65);

    // TLS1.3 parameters
	final static short  MY_CIPHER= (short)0x1304; //AES128-CCM
	final static short  MY_CURVE=  (short)23;  //SECP256k1
	final static byte   MY_EC_FORMAT = (byte)0; // FULL
	final static short  MY_VERSION =(short)0x0304; // TLS 1.3
	final static short  MY_SIGNATURE =(short)0x0403; //ECDSA
	final static byte[] MY_IDENTITY= {(byte)'C',(byte)'l',(byte)'i',(byte)'e',(byte)'n',(byte)'t',(byte)'_',(byte)'i',(byte)'d',(byte)'e',(byte)'n',(byte)'t',(byte)'i',(byte)'t',(byte)'y'};
	
	
	final static byte[] s_hs_traffic = {(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'s',(byte)' ',(byte)'h',(byte)'s',(byte)' ',(byte)'t',(byte)'r',(byte)'a',(byte)'f',(byte)'f',(byte)'i',(byte)'c'};
	final static byte[] c_hs_traffic = {(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'c',(byte)' ',(byte)'h',(byte)'s',(byte)' ',(byte)'t',(byte)'r',(byte)'a',(byte)'f',(byte)'f',(byte)'i',(byte)'c'};
	final static byte[] tls13_key =    {(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'k',(byte)'e',(byte)'y'};
	final static byte[] tls13_iv =     {(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'i',(byte)'v'};  
	final static byte[] tls13_derived= {(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'d',(byte)'e',(byte)'r',(byte)'i',(byte)'v',(byte)'e',(byte)'d'};
	final static byte[] s_ap_traffic = {(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'s',(byte)' ',(byte)'a',(byte)'p',(byte)' ',(byte)'t',(byte)'r',(byte)'a',(byte)'f',(byte)'f',(byte)'i',(byte)'c'};
	final static byte[] c_ap_traffic = {(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'c',(byte)' ',(byte)'a',(byte)'p',(byte)' ',(byte)'t',(byte)'r',(byte)'a',(byte)'f',(byte)'f',(byte)'i',(byte)'c'};
	final static byte[] tls13_finished ={(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'f',(byte)'i',(byte)'n',(byte)'i',(byte)'s',(byte)'h',(byte)'e',(byte)'d'};
	final static byte[] sha256_zero={(byte)0xE3,(byte)0xB0,(byte)0xC4,(byte)0x42,(byte)0x98,(byte)0xFC,(byte)0x1C,(byte)0x14,(byte)0x9A,(byte)0xFB,(byte)0xF4,(byte)0xC8,(byte)0x99 ,(byte)0x6F ,(byte)0xB9,(byte)0x24,(byte)0x27 ,(byte)0xAE,(byte)0x41,(byte)0xE4,(byte)0x64,(byte)0x9B,(byte)0x93,(byte)0x4C,(byte)0xA4,(byte)0x95,(byte)0x99,(byte)0x1B,(byte)0x78,(byte)0x52,(byte)0xB8,(byte)0x55};
	
	final static byte[] tls_ccs = {(byte)0x14,(byte)3,(byte)3,(byte)0,(byte)1,(byte)1};
	
	final static byte[] tls_resp= {(byte)'I',(byte)' ',(byte)'h',(byte)'e',(byte)'a',(byte)'r',(byte)' ',(byte)'y',(byte)'o',(byte)'u',(byte)' ',(byte)'f',(byte)'a',(byte)' ',(byte)'s',(byte)'h',(byte)'i',(byte)'z',(byte)'z',(byte)'l',(byte)'e',(byte)'!'};
	final static byte[] tls_req = {(byte)'G',(byte)'E',(byte)'T',(byte)' ',(byte)'/',(byte)0xD,(byte)0xA};
	
	final static short NVRSIZE=  (short)((short)1024+2*N_KEYS) ;
    byte[] NVR = new byte[NVRSIZE] ;
	
	private static OwnerPIN UserPin=null;
	private static final  byte[]   MyPin = {(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30,
											(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
    
	private static OwnerPIN AdminPin=null;
	private static final  byte[]   OpPin = {(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30,
											(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30};
  
	private final static short  SW_VERIFICATION_FAILED        = (short)0x6300;
	private final static  short SW_PIN_VERIFICATION_REQUIRED  = (short)0x6380;
	
	final static  short SW_KPUB_DEFINED    = (short)0x6401;
	final static  short SW_KPRIV_DEFINED   = (short)0x6402;
	final static  short SW_KPRIV_UNDEFINED = (short)0x6403;
	final static  short SW_GENKEY_ERROR    = (short)0x6D10;
	final static  short SW_SIGN_ERROR      = (short)0x6D20;
	final static  short SW_DUMP_KEYS_PAIR  = (short)0x6D30;
	final static  short SW_SET_KEY_PARAM   = (short)0x6D40;
	final static  short SW_DH_ERROR        = (short)0x6D50;
	final static  short SW_ERROR_WRITE     = (short)0x6D02;	
	final static  short SW_ERROR_READ      = (short)0x6D01;
	final static  short SW_DECRYPT_ERROR   = (short)0x6D14;
	final static  short SW_ENCRYPT_ERROR   = (short)0x6D15;
	final static  short SW_TLS_ERROR       = (short)0x6D16;
	final static  short SW_TLS_OPEN        = (short)0x9001;
	final static  short SW_TLS_END         = (short)0x9002; 

	
	private final static byte [] ParamA1    = {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xfc};
	private final static byte [] ParamB1    = {(byte)0x5a,(byte)0xc6,(byte)0x35,(byte)0xd8,(byte)0xaa,(byte)0x3a,(byte)0x93,(byte)0xe7,(byte)0xb3,(byte)0xeb,(byte)0xbd,(byte)0x55,(byte)0x76,(byte)0x98,(byte)0x86,(byte)0xbc,(byte)0x65,(byte)0x1d,(byte)0x06,(byte)0xb0,(byte)0xcc,(byte)0x53,(byte)0xb0,(byte)0xf6,(byte)0x3b,(byte)0xce,(byte)0x3c,(byte)0x3e,(byte)0x27,(byte)0xd2,(byte)0x60,(byte)0x4b};
    private final static byte [] ParamField1= {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
    private final static byte [] ParamG1=     {(byte)0x04,(byte)0x6b,(byte)0x17,(byte)0xd1,(byte)0xf2,(byte)0xe1,(byte)0x2c,(byte)0x42,(byte)0x47,(byte)0xf8,(byte)0xbc,(byte)0xe6,(byte)0xe5,(byte)0x63,(byte)0xa4,(byte)0x40,(byte)0xf2,(byte)0x77,(byte)0x03,(byte)0x7d,(byte)0x81,(byte)0x2d,(byte)0xeb,(byte)0x33,(byte)0xa0,(byte)0xf4,(byte)0xa1,(byte)0x39,(byte)0x45,(byte)0xd8,(byte)0x98,(byte)0xc2,(byte)0x96,
                                                        (byte)0x4f,(byte)0xe3,(byte)0x42,(byte)0xe2,(byte)0xfe,(byte)0x1a,(byte)0x7f,(byte)0x9b,(byte)0x8e,(byte)0xe7,(byte)0xeb,(byte)0x4a,(byte)0x7c,(byte)0x0f,(byte)0x9e,(byte)0x16,(byte)0x2b,(byte)0xce,(byte)0x33,(byte)0x57,(byte)0x6b,(byte)0x31,(byte)0x5e,(byte)0xce,(byte)0xcb,(byte)0xb6,(byte)0x40,(byte)0x68,(byte)0x37,(byte)0xbf,(byte)0x51,(byte)0xf5};
    private final static short   ParamK1 =    (short) 0x0001;
    private final static byte [] ParamR1=     {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xbc,(byte)0xe6,(byte)0xfa,(byte)0xad,(byte)0xa7,(byte)0x17,(byte)0x9e,(byte)0x84,(byte)0xf3,(byte)0xb9,(byte)0xca,(byte)0xc2,(byte)0xfc,(byte)0x63,(byte)0x25,(byte)0x51};
    
    private byte []  ESK = new byte[32]; // Early Secret Key
    private byte []  HSK = new byte[32]; // Handshake Secret Key
    private byte [] eBSK = new byte[32]; // Binder Secret Key
    private byte [] rBSK = new byte[32]; // Binder Secret Key
    private byte [] feBSK = new byte[32]; // Finished Binder Secret Key
    private byte [] frBSK = new byte[32]; // Finished Binder Secret Key
    
    
    private final static byte  EXTRACT_EARLY  =  (byte)0x0A;
    private final static byte  EXPAND_EARLY   =  (byte)0x0B;
    private final static byte  HMAC_EBSK      =  (byte)0x0C;
    private final static byte  HMAC_RBSK      =  (byte)0x0D;
    private final static byte  EXTRACT_HANDSHAKE =  (byte)0x0E;
    
    private final static byte  AESCCM_ENCRYPT  =  (byte)0x05;
    private final static byte  AESCCM_DECRYPT  =  (byte)0x06;
    
    private  final static  byte  [] derived     = {(byte)0x00,(byte)32,(byte)13,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'d',(byte)'e',(byte)'r',(byte)'i',(byte)'v',(byte)'e',(byte)'d',(byte)0x20,(byte)0xE3,(byte)0xB0,(byte)0xC4,(byte)0x42,(byte)0x98,(byte)0xFC,(byte)0x1C,(byte)0x14,(byte)0x9A,(byte)0xFB,(byte)0xF4,(byte)0xC8,(byte)0x99 ,(byte)0x6F ,(byte)0xB9,(byte)0x24,(byte)0x27 ,(byte)0xAE,(byte)0x41,(byte)0xE4,(byte)0x64,(byte)0x9B,(byte)0x93,(byte)0x4C,(byte)0xA4,(byte)0x95,(byte)0x99,(byte)0x1B,(byte)0x78,(byte)0x52,(byte)0xB8,(byte)0x55,(byte)0x01};
    private  final static  byte [] ext_binder   = {(byte)0x00,(byte)32,(byte)16,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'e',(byte)'x',(byte)'t',(byte)' ',(byte)'b',(byte)'i',(byte)'n',(byte)'d',(byte)'e',(byte)'r',(byte)0x20,(byte)0xE3,(byte)0xB0,(byte)0xC4,(byte)0x42,(byte)0x98,(byte)0xFC,(byte)0x1C,(byte)0x14,(byte)0x9A,(byte)0xFB,(byte)0xF4,(byte)0xC8,(byte)0x99 ,(byte)0x6F ,(byte)0xB9,(byte)0x24,(byte)0x27 ,(byte)0xAE,(byte)0x41,(byte)0xE4,(byte)0x64,(byte)0x9B,(byte)0x93,(byte)0x4C,(byte)0xA4,(byte)0x95,(byte)0x99,(byte)0x1B,(byte)0x78,(byte)0x52,(byte)0xB8,(byte)0x55,(byte)0x01};
    private  final static  byte [] res_binder   = {(byte)0x00,(byte)32,(byte)16,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'r',(byte)'e',(byte)'s',(byte)' ',(byte)'b',(byte)'i',(byte)'n',(byte)'d',(byte)'e',(byte)'r',(byte)0x00,(byte)0x01};
    private  final static  byte [] c_e_traffic  = {(byte)17,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'c',(byte)' ',(byte)'e',(byte)' ',(byte)'t',(byte)'r',(byte)'a',(byte)'f',(byte)'f',(byte)'i',(byte)'c'};
    private  final static  byte [] c_exp_master = {(byte)18,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'e',(byte)' ',(byte)'e',(byte)'x',(byte)'p',(byte)' ',(byte)'m',(byte)'a',(byte)'s',(byte)'t',(byte)'e',(byte)'r'};
    private  final static  byte [] finished     = {(byte)0x00,(byte)32,(byte)14,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'f',(byte)'i',(byte)'n',(byte)'i',(byte)'s',(byte)'h',(byte)'e',(byte)'d',(byte)0x00,(byte)0x01};
 
    private  static  byte[] dh_test={(byte)0x64,(byte)0x00 ,(byte)0xFF ,(byte)0xBE ,(byte)0xDD ,(byte)0xCC ,(byte)0x89 ,(byte)0x27 ,
                             (byte)0x26 ,(byte)0xFE ,(byte)0x23 ,(byte)0x9E ,(byte)0xA1 ,(byte)0xA1 ,(byte)0x14 ,(byte)0xBA ,(byte)0x4F ,(byte)0x35 ,(byte)0xE7 ,(byte)0x13 ,(byte)0x19 ,(byte)0x7F ,(byte)0xDA ,(byte)0x37 ,(byte)0x08 ,(byte)0x51 ,(byte)0x8E ,(byte)0xEC ,(byte)0xA4 ,(byte)0x26 ,(byte)0x79 ,(byte)0xF8};
    private  final static  byte[] rnd_test={(byte)0x3e ,(byte)0x09 ,(byte)0x8d ,(byte)0xc9 ,(byte)0x04 ,(byte)0x02 ,(byte)0x01 ,(byte)0x11 ,(byte)0xcf,
                             (byte)0xe1 ,(byte)0x80 ,(byte)0xcd ,(byte)0xf3 ,(byte)0xa9 ,(byte)0xd6 ,(byte)0x99 ,(byte)0xe7 ,(byte)0xe3 ,(byte)0xb2 ,(byte)0x25 ,(byte)0x99 ,(byte)0xf4 ,(byte)0xf9 ,(byte)0x79 ,(byte)0x3a,
                             (byte)0x06 ,(byte)0xba ,(byte)0x12 ,(byte)0x48 ,(byte)0x27 ,(byte)0xc4 ,(byte)0x75};
    private static byte[] pk_test={(byte)0x04,(byte)0x0B,(byte)0x5A,(byte)0x6E,(byte)0xC3,(byte)0x13,(byte)0x66,
                                   (byte)0xD6,(byte)0xFC,(byte)0x7A,(byte)0xCB,(byte)0x5C,(byte)0x0E,(byte)0x6E,
                                   (byte)0xF1,(byte)0x53,(byte)0x35,(byte)0xD4,(byte)0xDE,(byte)0x88,(byte)0xB0,
                                   (byte)0x4A,(byte)0x5E,(byte)0x4C,(byte)0xE4,(byte)0x93,(byte)0xE6,(byte)0xB8,
                                   (byte)0xFF,(byte)0xB4,(byte)0x6B,(byte)0x24,(byte)0x3F,(byte)0x32,(byte)0x61,
                                   (byte)0xFA,(byte)0xB9,(byte)0x0A,(byte)0xA1,(byte)0x41,(byte)0xA5,(byte)0xFE,
                                   (byte)0x64,(byte)0x64,(byte)0x10,(byte)0x20,(byte)0x4F,(byte)0xEA,(byte)0x2D,
                                   (byte)0xC4,(byte)0x58,(byte)0x23,(byte)0x71,(byte)0x0A,(byte)0xE7,(byte)0x16,
                                   (byte)0x06,(byte)0xA3,(byte)0x8D,(byte)0x2E,(byte)0x42,(byte)0xA7,(byte)0xD5,
                                   (byte)0x74,(byte)0xFF};

   
    private   final static byte[] zero32 = {(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,
                                            (byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,
                                            (byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,
                                            (byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0};
   
    AESKey      key1=null;
	Cipher      cipher1=null;
	AESKey      key2=null;
	Cipher      cipher2=null;
	
    public static byte[] HistByteArray = { (byte)'e',(byte)'t',(byte)'h',(byte)'e',(byte)'r',
                                           (byte)'t',(byte)'r',(byte)'u',(byte)'s',(byte)'t'};// assign to Historical Bytes

	public static  byte[] mypsk  = {(byte)1,(byte)2,(byte)3,(byte)4,(byte)5,(byte)6,(byte)7,(byte)8,
                                    (byte)9,(byte)10,(byte)11,(byte)12,(byte)13,(byte)14,(byte)15,(byte)16,
                                    (byte)17,(byte)18,(byte)19,(byte)20,(byte)21,(byte)22,(byte)23,(byte)24,
                                    (byte)25,(byte)26,(byte)27,(byte)28,(byte)29,(byte)30,(byte)31,(byte)32};
  
	public static byte[] quit= {(byte)'q',(byte)'u',(byte)'i',(byte)'t',(byte)0xd,(byte)0xa};

void reset_tls()
{  short i;
	 Util.arrayFillNonAtomic(DB,(short)0,(short)DB.length,(byte)0);
	for (i=0;i<VSSIZE;i++)
	VS[i]= (short)0;
}

void tls(APDU apdu,byte[]buffer)
{ boolean stat;
  short err   ;
  boolean toquit=false;
    
  while(true)
  {
	switch (VS[STATE])
	{
	case S_READY:
		sha0.reset();
		sha1.reset();
		sha2.reset();
		stat= CheckClient();
		if (!stat) 
		{reset_tls();
		 send(apdu,buffer,SW_TLS_ERROR);
		}
		sha0.update(RX,(short)5,(short)(VS[RXPTR]-5));
		sha1.update(RX,(short)5,(short)(VS[RXPTR]-5));
		sha2.update(RX,(short)5,(short)(VS[RXPTR]-5));
		err = MakeServerHello();
		if (err <0)
		{reset_tls();
		 send(apdu,buffer,SW_TLS_ERROR);
		}	
		VS[STATE] = S_EXTENSION;
		VS[RXPTR] = (short)(err+5);
		send(apdu,buffer,Util.makeShort(SW1M,(byte)0x1C));
		break;
		
	case S_EXTENSION:
		err = MakeEncryptedExtensions();
		if (err <0)
		{reset_tls();
		 send(apdu,buffer,SW_TLS_ERROR);
		}	
		VS[STATE] = S_SFINISHED;
		VS[RXPTR] = (short)(err+5);
		send(apdu,buffer,Util.makeShort(SW1M,(byte)0x3A));
		break;	
		
	case S_SFINISHED:
		err= MakeEncryptedFinished();
		if (err <0)
		{reset_tls();
		 send(apdu,buffer,SW_TLS_ERROR);
		}	
		VS[STATE] = S_CCS;
		VS[RXPTR] = (short)(err+5);
		send(apdu,buffer,(short)0x9000);
		break;
		
	case S_CCS:
		if (RX[(short)0] == (byte) 0x17)
		{ VS[STATE] = S_CFINISHED;
		  continue;
		}
		if (!CheckClientChangeCipherSpec())
		{reset_tls();
		 send(apdu,buffer,SW_TLS_ERROR);
		}
		VS[STATE] = S_CFINISHED;
		VS[RXPTR] = (short)0;
		send(apdu,buffer,(short)0x9000);	
		break;
		
	case S_CFINISHED:
		if (!CheckClientFinished())
		{reset_tls();
		 send(apdu,buffer,SW_TLS_ERROR);
		}
		VS[STATE] = S_OPEN;
		VS[RXPTR] = (short)0;
		send(apdu,buffer,SW_TLS_OPEN);	
		break;
		
	case S_OPEN:
		
		if (VS[MODE]== (short)1)  // read
		err = tls_read(); 
			
		else if (VS[MODE]== (short)2)  // write	
		err = tls_write();
		    
		else
		{ err = test_rx();
		  if (err < (short)-1) {toquit=true; err= (short)-err;}
		}
					
		if (err <0)
		{reset_tls();
		 send(apdu,buffer,SW_TLS_ERROR);
		}
		
		if  (VS[MODE]== (short)1) VS[RXPTR] = err ;
		else                      VS[RXPTR] = (short)(err+5);
		
		if ((VS[MODE]== (short)2) || (VS[MODE]== (short)1))	
		{
		send(apdu,buffer,(short)0x9000);	
		}
		else
		{ 
		if (!toquit) send(apdu,buffer,(short)0x9000);
		else 
		{VS[STATE] = S_READY;
		 send(apdu,buffer,SW_TLS_END);
		}
		}
 
 		break;
	default:
		break;
	}
  }
}

void seq_inc(boolean chtx)
{ byte msb, lsb;
   
if (chtx)	
{
msb =(byte)((short)0xFF & VS[SEQ1]>>8 );
lsb =(byte)((short)0xFF & VS[SEQ1]);
DB[(short)(DB_IV1+10)] ^= msb;
DB[(short)(DB_IV1+11)] ^= lsb;
VS[SEQ1]++;
msb =(byte)((short)0xFF & VS[SEQ1]>>8 );
lsb =(byte)((short)0xFF & VS[SEQ1]);
DB[(short)(DB_IV1+10)] ^= msb;
DB[(short)(DB_IV1+11)] ^= lsb;
}
else
{
msb =(byte)((short)0xFF & VS[SEQ2]>>8 );
lsb =(byte)((short)0xFF & VS[SEQ2]);
DB[(short)(DB_IV2+10)] ^= msb;
DB[(short)(DB_IV2+11)] ^= lsb;	
VS[SEQ2]++;
msb =(byte)((short)0xFF & VS[SEQ2]>>8 );
lsb =(byte)((short)0xFF & VS[SEQ2]);
DB[(short)(DB_IV2+10)] ^= msb;
DB[(short)(DB_IV2+11)] ^= lsb;
}	
}

boolean CheckClientFinished()
{ short err,ptr;
 
  ptr = (short)(RXSIZE-(short)64);
  
  if ( (RX[0] == (byte)0x17) && (RX[1] == (byte)3)  && (RX[2] == (byte)3) && (RX[3] == (byte)0) && (RX[4] == (byte)0x35) );
  else 
  	return false;
  	
  err= aesccm_decrypt(cipher2,
					  RX,(short)5,(short)0x25,
					  DB,DB_IV2,
					  RX,(short)0,(short)5,
					  RX,(short)5,
					  RX,(short)(5+0x25));
					  
  if (err < 0)
  	return false;
  	
  if ( (RX[5] == (byte)0x14) && (RX[6] == (byte)0) && 
	   (RX[7] == (byte)0) && (RX[8] == (byte)32) && (RX[41] == (byte)0x16));
  else 
  	return false;
  	
   	
  sha2.doFinal(RX,(short)0,(short)0,RX,(short)(ptr+32));	
  
  DeriveSecret(DB,DB_S2,(short)32,
			   (short)32,
			   tls13_finished,(short)0,(short)tls13_finished.length,
			   null,(short)0,(short)0,
			   RX,ptr);
			   
  hmac(RX,ptr,(short)32,
	   RX,(short)(ptr+32),(short)32,
	   sha256,
	   RX,ptr,true);
	   
  if (Util.arrayCompare(RX,(short)9,RX,ptr,(short)32) != (byte)0)
  return false;
    
  	// s_ap_traffic -> DB_S1
	DeriveSecret(DB,DB_S0,(short)32,
				(short)32,
				 s_ap_traffic,(short)0,(short)s_ap_traffic.length,
				 RX,(short)(ptr+(short)32),(short)32,
				 DB,DB_S1);
	
	// c_ap_traffic	->DB_S2		 
	DeriveSecret(DB,DB_S0,(short)32,
				(short)32,
				 c_ap_traffic,(short)0,(short)c_ap_traffic.length,
				 RX,(short)(ptr+(short)32),(short)32,
				 DB,DB_S2);			 
  	 
 
	// Key1 -> ptr     
	DeriveSecret(DB,DB_S1,(short)32,
				(short)16,
				 tls13_key,(short)0,(short)tls13_key.length,
				 null,(short)0,(short)0,
				 RX,ptr); // KEY	
 
	 try 
	 { key1.setKey(RX,ptr);
	   cipher1.init(key1,Cipher.MODE_ENCRYPT);
     }
     catch (CryptoException e){return false ;}			 
	
	// IV1-> DB_IV1
	DeriveSecret(DB,DB_S1,(short)32,
				(short)12,
				 tls13_iv,(short)0,(short)tls13_iv.length,
				 null,(short)0,(short)0,
				 DB,DB_IV1); 
	
	VS[SEQ1]=VS[SEQ2]=(short)0;			 		 
	
	// Key2 -> 	ptr	 
	DeriveSecret(DB,DB_S2,(short)32,
				(short)16,
				 tls13_key,(short)0,(short)tls13_key.length,
				 null,(short)0,(short)0,
				 RX,ptr); // KEY	
	
	try 
	{ key2.setKey(RX,ptr);
	  cipher2.init(key2,Cipher.MODE_ENCRYPT);
    }
    catch (CryptoException e){return false;}
    		
    // IV2 -> DB_IV2		
	DeriveSecret(DB,DB_S2,(short)32,
				(short)12,
				 tls13_iv,(short)0,(short)tls13_iv.length,
				 null,(short)0,(short)0,
				 DB,DB_IV2); 
return true ;
}


short MakeEncryptedFinished()
{ short err;
  short ptr;
  
  ptr = (short)(RXSIZE-64);
  
  RX[0]=(byte)0x17;
  RX[1]=RX[2]=(byte)3;
  RX[3]=(byte)0;
  RX[4]=(byte)0x35;
    
  RX[5]=(byte)0x14;
  RX[6]=RX[7]=(byte)0;
  RX[8]=(byte)0x20;
  RX[9+32]=(byte)0x16;

  sha1.doFinal(RX,(short)0,(short)0,RX,ptr);
    
  DeriveSecret(DB,DB_S1,(short)32,
			   (short)32,
			   tls13_finished,(short)0,(short)tls13_finished.length,
			   null,(short)0,(short)0,
			   RX,(short)(ptr+32));
  
  
  hmac(RX,(short)(ptr+32),(short)32,
	   RX,ptr,(short)32,
	   sha256,
	   RX,(short)9,true);
	   
  sha2.update(RX,(short)5,(short)36);

  err= aesccm_encrypt(cipher1,
					  RX,(short)5,(short)37,
					  DB,DB_IV1,
					  RX,(short)0,(short)5,
				      RX,(short)5,RX,(short)(5+37));
  seq_inc(true);				
				  
  return err;
}



short MakeEncryptedExtensions()
{ short err;
  
  RX[0] =(byte)0x17;
  RX[1]=RX[2] =(byte)3;
  RX[3]= (byte)0;
  RX[4]=(byte)0x17;
  RX[5]=(byte)8;
  RX[6]=(byte)0;
  RX[7]=(byte)0;
  RX[8]=(byte)2;
  RX[9]=RX[10] =(byte)0;
  RX[11]= (byte)0x16;
  
  sha1.update(RX,(short)5,(short)6);
  sha2.update(RX,(short)5,(short)6);
  
  err= aesccm_encrypt(cipher1,RX,(short)5,(short)7,
					       DB,DB_IV1,
					       RX,(short)0,(short)5,
				           RX,(short)5,RX,(short)12);
  seq_inc(true);			           

return err ;
}
short MakeServerHello()
{   short ptr ;
    short len=0,err  ;
	byte mode,test;
	
	test = (byte)(VS[MODE]    & (short)0xFF);
	mode = (byte)(VS[MODE]>>8 & (short)0xFF);
	
	ptr = (short)5;
    RX[ptr++]=(short)2;
	RX[ptr++]= (short)0;
	RX[ptr++]= (short)0;
	RX[ptr++]=  (short)0;
	
	RX[ptr++] =(short)3;// version= TLS1.2
	RX[ptr++] =(short)3; 
	
	if (test == (byte)0)
    rng.generateData(RX,ptr,(short)32);	
	else
	Util.arrayCopyNonAtomic(rnd_test,(short)0,RX,ptr,(short)32);
	
	ptr += (short)32;

	RX[ptr++]= (byte)((short)0xFF & VS[SIDLEN]);
	
	if (VS[SIDLEN] != (short)0)
	{ Util.arrayCopyNonAtomic(DB,DB_SID,RX,ptr,VS[SIDLEN]);
	  ptr+=  VS[SIDLEN];
	}

    RX[ptr++] = (byte)((short)0xFF & MY_CIPHER>>8);
	RX[ptr++] = (byte)((short)0xFF & MY_CIPHER);
	RX[ptr++] = (byte)0; // MY_COMPRESS);
   

	RX[ptr++] = 0;  // extensions length
	if (mode == (byte)0) RX[ptr++] = (short)85; // psk
	else                 RX[ptr++] = (short)79; // 85-6    
    
	if (mode == (byte)0)
	{
    RX[ptr++] = (short)0  ;
    RX[ptr++] = (short)41; // pre_share_key
    RX[ptr++] = (short)0;
    RX[ptr++] = (short)2; // pre_share_key length
    RX[ptr++] = (short)0; 
    RX[ptr++] = (short)0;
	}
    
	RX[ptr++] = (short)0;
    RX[ptr++] = (short)51; // key_share
    RX[ptr++] = (short)0;
    RX[ptr++] = (short)69; //  key_share length
    RX[ptr++] = (short)((short)0xFF & MY_CURVE >> 8);
    RX[ptr++] = (short)(MY_CURVE & (short)0xFF);
    RX[ptr++] = (short)0 ;
    RX[ptr++] = (short)65;
	
	Util.arrayCopyNonAtomic(DB,DB_PK,RX,ptr,(short)65);
	ptr+= (short)65;
    
	RX[ptr++] = (short)0;
    RX[ptr++] = (short)43; // supported_versions
    RX[ptr++] = (short)0;
    RX[ptr++] = (short)2; //  supported_versions length
    RX[ptr++] = (short)((short)0xFF & MY_VERSION >> 8);
    RX[ptr++] = (short)((short)0xFF & MY_VERSION);
    	
    len= (short)(ptr-(short)5);	
	RX[(short)7] = (byte)((short)0xFF & ((short)(len-4) >> 8)) ;
	RX[(short)8] = (byte)((short)0xFF & (len-4))        ;
	
	RX[(short)0]=  (byte)0x16;
	RX[(short)1] = (byte)0x03;
	RX[(short)2] = (byte)0x03;
	RX[(short)3] = (byte)((short)0xFF & (len >>8));
    RX[(short)4] = (byte)((short)0xFF & len);
	
	ptr = (short)(RXSIZE - (short)64);
	// Compute Handshake secret DH
	hmac(HSK,(short)0,(short)HSK.length,
		 DB,DB_DH,(short)32,
		 sha256,
		 RX,ptr,true);	

		 
    // compute hash(ClientHello+ServerHello)
	sha1.update(RX,(short)5,len);	
	sha2.update(RX,(short)5,len);		
	sha0.doFinal(RX,(short)5,len,RX,(short)(ptr+32)) ;
	
	// s_hs_traffic -> DB_S1
	DeriveSecret(RX,ptr,(short)32,
				(short)32,
				 s_hs_traffic,(short)0,(short)s_hs_traffic.length,
				 RX,(short)(ptr+(short)32),(short)32,
				 DB,DB_S1);
	
	// c_hs_traffic	->DB_S2		 
	DeriveSecret(RX,ptr,(short)32,
				(short)32,
				 c_hs_traffic,(short)0,(short)c_hs_traffic.length,
				 RX,(short)(ptr+(short)32),(short)32,
				 DB,DB_S2);			 
  	 
    // MasterSecret -> DB_S0
    DeriveSecret(RX,ptr,(short)32,
				(short)32,
				 tls13_derived,(short)0,(short)tls13_derived.length,
				 sha256_zero,(short)0,(short)sha256_zero.length,
				 RX,ptr); // derived key	
     // ComputePRK		
    hmac(RX,ptr,(short)32,
	     zero32,(short)0,(short)zero32.length,
	     sha256,
	     DB,DB_S0,true);
	     
	// Key1 -> ptr     
	DeriveSecret(DB,DB_S1,(short)32,
				(short)16,
				 tls13_key,(short)0,(short)tls13_key.length,
				 null,(short)0,(short)0,
				 RX,ptr); // KEY	
 
	 try 
	 { key1.setKey(RX,ptr);
	   cipher1.init(key1,Cipher.MODE_ENCRYPT);
     }
     catch (CryptoException e){return -1;}			 
	
	// IV1-> DB_IV1
	DeriveSecret(DB,DB_S1,(short)32,
				(short)12,
				 tls13_iv,(short)0,(short)tls13_iv.length,
				 null,(short)0,(short)0,
				 DB,DB_IV1); 
	
	VS[SEQ1]=VS[SEQ2]=(short)0;			 		 
	
	// Key2 -> 	ptr	 
	DeriveSecret(DB,DB_S2,(short)32,
				(short)16,
				 tls13_key,(short)0,(short)tls13_key.length,
				 null,(short)0,(short)0,
				 RX,ptr); // KEY	
	
	try 
	{ key2.setKey(RX,ptr);
	  cipher2.init(key2,Cipher.MODE_ENCRYPT);
    }
    catch (CryptoException e){return -1;}
    		
    // IV2 -> DB_IV2		
	DeriveSecret(DB,DB_S2,(short)32,
				(short)12,
				 tls13_iv,(short)0,(short)tls13_iv.length,
				 null,(short)0,(short)0,
				 DB,DB_IV2); 
	
    return len;
}

boolean check_supported_groups(short len, short ptr)
{ short leng,i,v;
	
 if (len < (short)2)  return false ;

  leng  =  (short)((RX[ptr]<<8) & LMASK) ;
  leng |=  (short)(RX[(short)(ptr+1)] & (short)0xFF) ;
 
 if (len != (short)(2+leng))
	 return false;

 for (i=0;i<leng;i+=2)
 { v  =  (short)(RX[(short)(ptr+i+2)]<<8  & (short)0xFF00) ;
   v |=  (short)(RX[(short)(ptr+i+3)]     & (short)0xFF);
   if (v == MY_CURVE)
	   return true;
 }

 return false;
}

boolean check_ec_point_formats(short len, short ptr)
{ short i,lenp;

  lenp  =  (short)((short)0xFF & RX[ptr]) ;
  if (lenp != (short)(len-1))  return false;
 
  for(i=0;i<lenp;i++)
  {
  if (RX[(short)(ptr+i+1)] == MY_EC_FORMAT)
	  return true;
  }
  return false;
}


boolean check_supported_versions(short len, short ptr)
{ short lens,i,v;
	
 if (len < (short)1) 
		return false ;

 lens = (short)((short)0xFF & RX[ptr]);
 
 if (len != (short)(1+lens))
	 return false;

 for (i=0;i<lens;i+=(short)2)
 { v  =   (short)(RX[(short)(ptr+i+1)]<<8 & (short)0xFF00) ;
   v |=   (short)(RX[(short)(ptr+i+2)]     & (short)0xFF);
   if (v == MY_VERSION)
	   return true;
 }

 return false;
}

boolean check_signature_algorithms(short len, short ptr)
{ short i,s,lenh;
  
  if (len < (short)4)
	  return false;

  lenh  =  (short)(RX[ptr]<<8 & LMASK) ;
  lenh |=  (short)(RX[(short)(ptr+1)] & (short)0xFF) ;
  
  if (lenh != (short)(len-2))
  return false;

 if (lenh == (short)0) return false;
 if ( (short)(lenh & (short)0x1) != (short)0) return false;

  for(i=0;i<lenh;i+=(short)2)
  {
  s  = (short) (RX[(short)(ptr+i+2)]<<8 & (short)0xFF00);
  s |= (short) (RX[(short)(ptr+i+3)]    & (short)0xFF);
  if (s == MY_SIGNATURE)
	  return true;
  
  }

  return false;
}

short check_key_share_extension(short len, short ptr)
{ short lene,curve;
  short lenc,pti=0;
  short b=0,pt,mylenc=-1;
  short remain;
  boolean found=false;

  remain = len ;
  
  remain-=(short)2;
  if (remain < (short)0)
	  return (short)-1 ;
  lene  = (short) (RX[(short)ptr]<<8  & LMASK) ;
  lene |= (short) (RX[(short)(ptr+1)] & (short)0xFF);
  
  if (lene != (short)(len-2))
  	return -1;

  while (remain > (short)0)
  {
  
  remain-=(short)2;
  if (remain < 0)
	  return -1 ;

  curve  =  (short)(RX[(short)(ptr+b+2)]<<8 & (short)0xFF00);
  curve |=  (short)(RX[(short)(ptr+b+3)]    & (short)0xFF);

  remain-=(short)2;
  if (remain < (short)0)
	  return (short)-1 ;

  lenc  =  (short)(RX[(short)(ptr+b+4)]<<8 & LMASK);
  lenc |=  (short)(RX[(short)(ptr+b+5)]    & (short)0xFF);

  remain -= lenc;
  if (remain < (short)0) 
	  return -1;

  if (curve == MY_CURVE)
  {	  pti = (short)(b+4);
	  found=true;
	  mylenc= lenc;
  }
  
 
  b += (short)(4+lenc);

  }

  if (found)
  {	if (mylenc != (short)65)  return -1; 
  	return pti;
  }
  
  return -1;

}

short check_pre_share_key(short len, short ptr)
{ short leni,lenb;
  short lenid,lenbd;
  short pt, pti;
  short b=0;
  short remain,ni=0,nb=0;
  boolean found;

  if (len < (short)(2+2+1+2+33))
	  return -1;
  
  leni  =  (short)(RX[(short)(b+ptr)]<<8 & LMASK);
  leni |=  (short)(RX[(short)(ptr+b+1)] & (short)0xFF);

  lenb  =  (short)(RX[(short)(ptr+b+2+leni)]<<8 & LMASK);
  lenb |=  (short)(RX[(short)(ptr+b+3+leni)] & (short)0xFF);

   pt= (short)(4+leni+lenb);
   if (pt != len)
	   return -1;

  remain = leni;
  found=false;
  b=(short)2;
  while(remain>0)
  { 
   if (!found) 
   ni++;
       
   remain -=(short)2;
   if (remain <= 0) return -1;
   lenid  =  (short)(RX[(short)(ptr+b)]<<8 & LMASK);
   lenid |=  (short)(RX[(short)(ptr+b+1)]  & (short)0xFF);
   
   remain -= (short)(lenid+4); 
   
   if (remain < 0) 
	   return -1;

   if (lenid == (short)MY_IDENTITY.length)
   { if (Util.arrayCompare(RX,(short)(ptr+b+2),MY_IDENTITY,(short)0,lenid)==(byte)0) found=true;}

   b+= (short)(2+lenid+4); // => next identity

  }

  if (!found) 
	  return -1;


  pti= b;
  remain = lenb;
  b+=(short)2;
  nb=(short)0;

  while(remain>0)
  { 
   nb++;
   remain -=1;
   if (remain <= 0) return -1;

   lenbd=    (short)(RX[(short)(b+ptr)]  & (short)0xFF);
   remain -= lenbd ;
   
   if (remain < 0) 
	   return -1;

   if (ni == nb) pt= b;
  
   b+= (short)(1+lenbd);

  }
  
  VS[SIDLEN]=pti;
  return pt;
}

boolean check_key_exchange(short len, short ptr)
{ short i,lenp;

  lenp  = (short) ((short)0xFF & RX[ptr]) ;

  if (lenp != (short)(len-1))  return false;
 
  for(i=0;i<lenp;i++)
  {
  if (RX[(short)(ptr+i+1)] == (byte)1) //MY_DHE)
	  return true;
  }

	
	return false;
}

boolean ComputePRK(byte[] salt, short salt_off, short salt_len, byte[] ikm, short ikm_off,short ikm_len,byte[] prk, short prk_off)
{ 
  hmac(salt,salt_off,salt_len,
	   ikm,ikm_off,ikm_len,
	   sha256,
	   ikm,ikm_off,true);

  return true ;
}

boolean DeriveSecret(byte[] prk,short prk_off, short prk_len,
					 short len,
					 byte[] label, short label_off, short label_len,
					 byte[] data,  short data_off, short data_len,
					 byte[] secret, short secret_off)
{ short lent;      ;
  short ii= DB_BUFX;
  
  lent = (short)(5+label_len+data_len) ;
  
  if (lent > DBX_SIZE)
  	return false;

  DB[ii++]  = (byte)((byte)0xFF & (len >> 8));
  DB[ii++]  = (byte)((byte)0xFF & len);
  DB[ii++] =  (byte)((byte)0xFF & label_len);
  Util.arrayCopyNonAtomic(label,label_off,DB,ii,label_len);
  ii += label_len;
  DB[ii++]= (byte)(data_len & (byte)0xFF) ;
  if (data_len != (short)0)
  { Util.arrayCopyNonAtomic(data,data_off,DB,ii,data_len);
    ii+= data_len;
  }
  DB[ii++]= (byte)0x01;
   
  hmac(prk,prk_off,prk_len,
	   DB,DB_BUFX,lent,
	   sha256,
	   DB,(short)0,true);
	   
  Util.arrayCopyNonAtomic(DB,(short)0,secret,secret_off,len);

  return true;
}

boolean CheckClientChangeCipherSpec()
{ 
  if (Util.arrayCompare(RX,(short)0,tls_ccs,(short)0,(short)tls_ccs.length)== (byte)0)
  return true;
	
	return false;
}


short test_rx()
{ short len,err;
  boolean squit=false;

  len = Util.getShort(RX,(short)3);
  if (len < (short)16)
  	return (short)-1;
  
  err = aesccm_decrypt(cipher2,RX,(short)5,(short)(len-16),
					   DB,DB_IV2,
					   RX,(short)0,(short)5,
					   RX,(short)5,
					   RX,(short)(5+len-16));
 seq_inc(false);
 
 if (err < (short)0)
 	return (short)-1;
 	
 if (RX[(short)(5+err-1)] != (byte)0x17)
 	return -1;
 	
 if (((short)tls_req.length == (short)(err-1))	&&
    (Util.arrayCompare(RX,(short)5,tls_req,(short)0,(short)(err-1)) == (byte)0))
 {
   Util.arrayCopyNonAtomic(tls_resp,(short)0,RX,(short)5,(short)tls_resp.length);
   len= (short)(tls_resp.length + 1);
   RX[(short)(5+len-1)] = (byte)0x17;
   squit=true; 
 }	
 
  else if (((short)quit.length == (short)(err-1))	&&
 (Util.arrayCompare(RX,(short)5,quit,(short)0,(short)(err-1)) == (byte)0))
 {
   Util.arrayCopyNonAtomic(quit,(short)0,RX,(short)5,(short)quit.length);
   len= (short)(quit.length + 1)    ;
   RX[(short)(5+len-1)] = (byte)0x17; 
   squit=true;
 }
 
 else 
 len= err;	
 
 RX[0]=(byte)0x17;
 RX[1]=(byte)3;
 RX[2]=(byte)3;
 Util.setShort(RX,(short)3,(short)(len+16));
 
 err = aesccm_encrypt(cipher1,
					  RX,(short)5,len,
					  DB,DB_IV1,
					  RX,(short)0,(short)5,
					  RX,(short)5,
					  RX,(short)(5+len));
seq_inc(true);					  
if (squit) 
	return (short)-err;
return err;	
}

short tls_write()
{ short len,err;
 
 len=VS[RXPTR];
 Util.arrayCopyNonAtomic(RX,(short)0,RX,(short)5,len);
 
 //RX[(short)(5+len)]= (byte)0x17;
 //len++;

 RX[0]=(byte)0x17;
 RX[1]=(byte)3;
 RX[2]=(byte)3;
 Util.setShort(RX,(short)3,(short)(len+16));
 
 err = aesccm_encrypt(cipher1,
					  RX,(short)5,len,
					  DB,DB_IV1,
					  RX,(short)0,(short)5,
					  RX,(short)5,
					  RX,(short)(5+len));
seq_inc(true);					  

return err;	
}

short tls_read()
{ short len,err;

  len = Util.getShort(RX,(short)3);
  if (len < (short)16)
  	return -1;
  
  err = aesccm_decrypt(cipher2,RX,(short)5,(short)(len-16),
					   DB,DB_IV2,
					   RX,(short)0,(short)5,
					   RX,(short)5,
					   RX,(short)(5+len-16));
  
 if (err < 0) return -1;
 
 seq_inc(false);
 
// if (RX[(short)(5+err-1)] != (byte)0x17)
// 	return -1;
 
 Util.arrayCopyNonAtomic(RX,(short)5,RX,(short)0,err);
  
 return (short)err;	
}


boolean CheckClient()
{ boolean fpsk=false,fdhe=false,fpki=false,ftls13=false,fbinder=false;
  short lenr,len,remain,err;
  short pt_binder_hash=(short)0, pt_binder_value=(short)0,pt_pk=(short)0;
      
      lenr  =   (short)((RX[3]<<8) & LMASK);
      lenr |=   (short)(RX[4] & 0xFF);

      byte ptcol = RX[5];
      if (ptcol != (byte)0x01) return false; // Client hello
      
      if (RX[6] != (byte)0) return false;
      len =   (short)((RX[7]<<8) & LMASK);
      len |=  (short)(RX[8] & 0xFF);
      
      if (len != (short)(lenr-4)) 
    	  return false;
      
      remain=len;
      
      byte vhigh= RX[9] ;
      byte vlow=  RX[10];

      if ( (vhigh != (byte)3) || (vlow != (byte)3) )
    	  return false;
      
      // 11 -> client random 32 bytes

      remain -= (short)34;
      
      short sidlen= (short) (0xFF & RX[43]);
      if (sidlen >(short)32) return false;
      // 44-> sid
      short next =44;
          
      remain -= (1+sidlen);
      if (remain <=0) return false ;
         
      next += sidlen ;
      short ii=   (short)((short)44+ sidlen);
      
      remain-=(short)2 ;
      short cipherlen  =  (short)((RX[next]<<8) & LMASK);
      cipherlen |=  (short)(RX[(short)(next+1)] & 0xFF);
      next+=2;
      ii+=2;
      
      remain -= cipherlen;
      if (remain <=0) return false ;

     if ( (short)(cipherlen & (short)0x1) == (short)0x1) return false ; // !!!
    	  
      boolean fcipher=false;
      short cipher,i ;
       for (i=0;i<cipherlen;i+=(short)2)
      {  cipher  =  (short)((RX[(short)(next+i)]<<8) & (short)0xFF00);
         cipher  =  (short)(cipher | ((short)( RX[(short)(next+i+1)] & (short)0xFF)));
    	 if (cipher == MY_CIPHER)
    	 fcipher=true;
      }
      
       if (!fcipher) return false ;

      next += cipherlen;
      ii+= cipherlen;
      
      remain -=1;  
      if (remain <=0) return false;
    	  
      len = (short)(0xFF & RX[next]);
      
      remain -= len  ;
      if (remain <=0) return false ;
    	  
      boolean  found=false;
      for (i=0;i<len;i++)
      { if (RX[(short)(next+i+1)] == (byte)0) // COMPRESS
    	  found=true ; 
      }
      if (!found) return false;
      
      next+=(short)(1+len);
      ii+=  (short)(1+len);

      remain -= (short)2;
      if (remain <=0)  return false;

      short extlen,extype;
      extlen  =  (short) ((RX[next]<<8) & LMASK);
      extlen |=  (short) (RX[(short)(next+1)] & (short)0xFF);
      
      next+=(short)2;
      ii+=(short)2;

      if (remain != extlen) return false ;
      
      while (remain != (short)0)
      {
      remain-= (short)4;
      if (remain <0) return false ;

      extype  = (short)((RX[next]<<8) & (short)0xFF00);
      extype |= (short) (RX[(short)(next+1)]   & (short)0xFF);
      extlen  = (short)((RX[(short)(next+2)]<<8) & LMASK);
      extlen |= (short)(RX[(short)(next+3)] & (short)0xFF);
      remain-=extlen ;
      next+= (short)4;
      ii+=(short)4;
      
      if (remain < 0) return false ;

      switch (extype) 
      {   case (short)45: // psk_key_exchange_modes
          if (!check_key_exchange(extlen,next))
          return false;
          break;

      	case (short)13: // signature_algorithms
        if(check_signature_algorithms(extlen,next))
  	    fpki= true;
        break;
        
        case (short)41:
        err= check_pre_share_key(extlen,next);
        if (err < 0) return false ;
        fpsk=true;
        pt_binder_hash = (short)(ii+VS[SIDLEN]-5);
        pt_binder_value= (short)(next+err+1);
        
        break;
        
       case (short)11:
       if (!check_ec_point_formats(extlen,next))
       return false;
       break;

       case (short)51:
       err= check_key_share_extension(extlen,next);
       if (err < 0) return false ;
       pt_pk = (short)(next+err+2) ; // -> public key, 65 bytes
	   fdhe=true ;
       break;

       case (short)43:
       if (!check_supported_versions(extlen,next))
       return false;
       ftls13=true;
       break; 
       
       case (short)10:
       if (!check_supported_groups(extlen,next))
       return false;
       break;


       default: 
      	break;
      }
      
      next += extlen;
      ii+= extlen;
      }
       
      byte test =(byte)((short)0xFF & VS[MODE]) ;
       
      if (fpsk && ftls13)
      { sha256.reset();
        sha256.doFinal(RX,(short)5,pt_binder_hash,DB,DB_BUFX);
        
        hmac(feBSK,(short)0,(short)eBSK.length,
				 DB,DB_BUFX,(short)32,
				 sha256,
				 DB,DB_BUFX,true);
        if (Util.arrayCompare(DB,DB_BUFX,RX,pt_binder_value,(short)32)== (byte)0)
        	fbinder = true;
        else  
        	return false;
        
        if (test == (byte)0)	
        { if (genkey(N_KEYS) != (short)0) 
        	return false;
        }
        
        ECPrivateKey privk=null;
        short index= N_KEYS;
        
        if (test != (byte)0)  
        {Util.arrayCopyNonAtomic(pk_test,(short)0,DB,DB_PK,(short)pk_test.length);	  
		 Util.arrayCopyNonAtomic(dh_test,(short)0,DB,DB_DH,(short)dh_test.length);	  
        }
        else
        {	
		privk = (ECPrivateKey)ECCkp[index].getPrivate();
		
		if (ECCkeyAgreement != null) // issue with debugger
		{ ECCkeyAgreement.init(privk);
	      try  
	      { len= ECCkeyAgreement.generateSecret(RX,pt_pk,(short)65,DB,DB_DH);}
	      catch (CryptoException e)
	      { return false;}
	    }
	    
	  	try { len= ((ECPublicKey) ECCkp[index].getPublic()).getW(DB,DB_PK);}
	    catch (CryptoException e)
	    { return false;}
	    }
	
	   VS[SIDLEN] = sidlen;
        // 44 -> sid
        if (sidlen != (short)0)
        Util.arrayCopyNonAtomic(RX,(short)44,DB,DB_SID,sidlen);
	    			       
	  return true;
      }    
      
    return false ;

}
  
 void send(APDU apdu, byte[] buffer, short sw)
 { boolean fsyn=false;
   short len;
   
   if (VS[RXPTR] <= MAXRXSIZE) len = VS[RXPTR] ;
   else                        len = MAXRXSIZE ;
   
   if ( (VS[STATE_RECV] == S_RECV_WAITING) && (len != VS[RECV_REQUEST_LEN]) )
   fsyn=true;
  
   if ( (byte)(sw>>8 &(short)0xFF) == SW1M )
   {  VS[STATE_RECV]       = S_RECV_WAITING           ;
	  VS[RECV_WAITING_LEN] = (short)(sw &(short)0xFF) ;
   }	 
   else
   {  VS[STATE_RECV]       = S_READY;
	  VS[RECV_WAITING_LEN] = (short)0;
   }
   	
   if (fsyn)
   {
   VS[TXLEN]= VS[RXPTR] ;
   VS[RXPTR]=0 ;
   VS[TXSW]=sw ;
   ISOException.throwIt(Util.makeShort((byte)0x6C,(byte)(0xFF & len))) ;  
   }
   
   if (VS[RXPTR] <= MAXRXSIZE)
   { if (VS[RXPTR] != (short)0)
   	 { Util.arrayCopyNonAtomic(RX,(short)0,buffer,(short)0,VS[RXPTR]);
  	   apdu.setOutgoingAndSend((short)0,VS[RXPTR]);
  	 }
  	 VS[TXSW]=sw;
  	 VS[TXLEN]=VS[RXPTR]= (short)0;
  	 ISOException.throwIt(sw);
   }
   VS[TXLEN]= VS[RXPTR] ;
   VS[RXPTR]=0 ;
   VS[TXSW]=sw;
   ISOException.throwIt(Util.makeShort(SW1M,(byte)(short)(0xFF & MAXRXSIZE))) ;
 }
 
 void recv(APDU apdu, byte [] buffer, short len)
 {     
    if (VS[TXLEN] == (short)0)
    {  if (VS[STATE_RECV] == S_RECV_WAITING) 
	   {VS[RECV_REQUEST_LEN] = (short)((short)0xFF & buffer[4]);
	   	tls(apdu,buffer); 
	   } 
       else	
       ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
							
    if (len == (short)0) len=(short)256;
    
    
    if (VS[TXLEN] <= MAXRXSIZE)
    { if (len != VS[TXLEN])  
  	  ISOException.throwIt(Util.makeShort(((byte)0x6C),(byte)(0xFF & VS[TXLEN]))) ;	
    }
    else
    { if (len != MAXRXSIZE)  
	  ISOException.throwIt(Util.makeShort((byte)0x6C,(byte)(short)(0xFF & MAXRXSIZE))) ;
    }
    
    Util.arrayCopyNonAtomic(RX,VS[RXPTR],buffer,(short)0,len);
	VS[RXPTR] = (short)(VS[RXPTR] + len)	;
	VS[TXLEN] = (short)(VS[TXLEN] - len)	;
  	apdu.setOutgoingAndSend((short)0,len)   ;   
  	
  	if (VS[TXLEN] == (short)0) 
  	ISOException.throwIt(VS[TXSW]);
  	else if (VS[TXLEN] <= MAXRXSIZE)
  	ISOException.throwIt(Util.makeShort(SW1M,(byte)(0xFF & VS[TXLEN]))) ;	
  	else 
  	ISOException.throwIt(Util.makeShort(SW1M,(byte)(short)(0xFF & MAXRXSIZE))) ;
}	 
 
 
public void process(APDU apdu) throws ISOException
  { short adr=0,len=0,index=0,readCount=0,err=0;
	
  byte[] buffer = apdu.getBuffer() ; 
  
  byte cla = buffer[ISO7816.OFFSET_CLA];
  byte ins = buffer[ISO7816.OFFSET_INS];
  byte P1  = buffer[ISO7816.OFFSET_P1] ;
  byte P2  = buffer[ISO7816.OFFSET_P2] ;
  byte P3  = buffer[ISO7816.OFFSET_LC] ;
  
  adr = Util.makeShort(P1,P2)       ;
  len = Util.makeShort((byte)0,P3)  ;
  
  switch (ins)
		{
	  
        case INS_SELECT: 
	    readCount = apdu.setIncomingAndReceive()  ;
	    return;
			
		case INS_GET_STATUS:	
			Util.arrayCopyNonAtomic(VERSION,(short)0,buffer,(short)0,(short)VERSION.length);
			Util.setShort(buffer,(short)VERSION.length,status);
			apdu.setOutgoingAndSend((short)0,(short)(2+VERSION.length));
			break;
		
		case INS_BINARY_READ:
			
		if (len == (short)0) 
			len=(short)256;
		
	    if (!AdminPin.isValidated() && !UserPin.isValidated())
		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			
		if (adr < (short)0)
		ISOException.throwIt(SW_ERROR_READ) ;
   	    if ((short)(adr + len -1) >= (short)NVR.length)
		ISOException.throwIt(SW_ERROR_READ) ;
			
		Util.arrayCopy(NVR,adr,buffer,(short)0,len);
		apdu.setOutgoingAndSend((short)0,len);
				  
		break;
		
		case INS_BINARY_WRITE:	

     	readCount = apdu.setIncomingAndReceive();   
     	
     	if (len == (short)0)
     	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
                
		if (readCount <= 0)
			ISOException.throwIt(SW_ERROR_WRITE) ;
			
		if (!AdminPin.isValidated())
		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
	
		if (adr < (short)0)                
		ISOException.throwIt(SW_ERROR_WRITE) ;
				
		if ((short)(adr + len -1) >= (short)NVR.length )  
		ISOException.throwIt(SW_ERROR_WRITE) ;
				  
		Util.arrayCopy(buffer,(short)5,NVR,adr,len);
							
		break;
		
		case INS_TEST:	

     	readCount = apdu.setIncomingAndReceive();   
     	
     	if (len == (short)0)
     	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
                
		if (readCount <= 0)
			ISOException.throwIt(SW_ERROR_WRITE) ;
			
		if (len != readCount)
     	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
        	
		if (!AdminPin.isValidated())
		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
	   
        if (P2==(byte)1)		  
		Util.arrayCopy(buffer,(short)5,dh_test,(short)0,(short)dh_test.length);
		else if (P2==(byte)2)		  
		Util.arrayCopy(buffer,(short)5,pk_test,(short)0,(short)pk_test.length);
		else if (P2==(byte)3)		  
		Util.arrayCopy(buffer,(short)5,rnd_test,(short)0,(short)rnd_test.length);
		else
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
								
		break;
		
		
		case (byte)0xC0:
			recv(apdu,buffer,len);
			break;
		
		case INS_SEND:	

     	if (len != (short)0)
     	readCount = apdu.setIncomingAndReceive();  
     	else
     	readCount =(short)0;
     	
     	if (len != readCount)
     	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
     	
      	// if ( (!AdminPin.isValidated()) && (!UserPin.isValidated()) )
		// ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		
		if (len == (short)0)
		{
		 reset_tls();
		 ISOException.throwIt((short)0x9000); 
		}
  	    
  	    if ( (byte)(P2 & (byte)0x1) == (byte)0x1) VS[RXPTR] = 0;
  	    
		if ((short)(VS[RXPTR] + len) > RXSIZE )  
		ISOException.throwIt(SW_ERROR_WRITE) ;
				  
		Util.arrayCopy(buffer,(short)5,RX,VS[RXPTR],len);
		VS[RXPTR] = (short)(VS[RXPTR]+len);
		
		if ( (byte)(P2 & (byte)0x2) == (byte)0x2) 
		{ 	  
		  if (P1 == (byte)0xFF) //echo test
		  send(apdu,buffer,(short)0x9000);
		  
		  else
		  { VS[MODE] = (short)((short)0xFF & P1);
		  	
		  	if ((VS[MODE] == (short)2) && (VS[STATE] == S_OPEN)) ; // WRITE
		  	else
		  	{	
		  	if (VS[RXPTR] < (short)5)
		    ISOException.throwIt(SW_ERROR_WRITE);	
		  	len = Util.makeShort(RX[(short)3],RX[(short)4]);
		    if ((short)(len+(short)5) != VS[RXPTR])
		    ISOException.throwIt(SW_ERROR_WRITE);
		    }
		    
			if (VS[STATE] != S_OFF) 
			tls(apdu,buffer);
			ISOException.throwIt(SW_TLS_ERROR);
		  }
		  
		}
							
		break;

		
		
		case INS_VERIFY:   
		readCount = apdu.setIncomingAndReceive();
						   
		if (P2 == (byte)1)
		{  if (readCount != (short)8)
	       ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);  
		   verify(AdminPin,buffer) ;
		   if(AdminPin.isValidated()) 
		   { UserPin.resetAndUnblock();
		   }
	    }
					   
		else if (P2 == (byte)0xFF)
		{ if (readCount != (short)8)
		  ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		  verify(AdminPin,buffer) ;
		  if(AdminPin.isValidated()) 
		 { UserPin.resetAndUnblock();
		   UserPin.update(MyPin,(short)0,(byte)8) ;
	     }
	    }
						   
		else if (P2 == (byte)0)
		{  if (readCount > (short)8)
		   ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			verify(UserPin,buffer);
		}
		
        else
	    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
						   	
	    break;			
		
		case INS_CHANGE_PIN:   // retrieve the PIN data for validation.
			             
		readCount = apdu.setIncomingAndReceive() ;
					   
	    if (readCount != (short)16)
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
	    
	    buffer[4]=(byte)8;
					   
	    if (P2 == (byte)1)
	    {  verify(AdminPin,buffer) ;
		   AdminPin.update(buffer,(short)13,(byte)8);
		}
		
	    else if  (P2 == (byte)0)
		{ verify(UserPin,buffer)  ;
		  UserPin.update(buffer,(short)13,(byte)8);
	    }
	    
	    else
	    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
	    break;	
	    
	    
	    case INS_HMAC:
	    	
	    	// Key_Length KEY_Value Data_Length Data_Value
	    	
	    	readCount = apdu.setIncomingAndReceive();
	    	len = Util.makeShort((byte)0,buffer[(short)4]); 
	    	
	    	if (len != readCount)
	    	ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
	    	
		    
		    else if ( (!AdminPin.isValidated()) && (!UserPin.isValidated()) )
		    ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED); 
		    
		    if (P2 == AESCCM_ENCRYPT)
		    {
		      try 
		      { key1.setKey(buffer, (short)5);
	            cipher1.init(key1,Cipher.MODE_ENCRYPT);
	          }
	          catch (CryptoException e){ISOException.throwIt(SW_ENCRYPT_ERROR); }
	          len = (short)(len - (16+12+5));
	          err = aesccm_encrypt(cipher1,buffer,(short)(5+16+12+5),len,
								   buffer,(short)(5+16),
								   buffer,(short)(5+16+12),(short)5,
								   DB,(short)32,
								   DB,(short)(32+len));
			  if (err <0)   ISOException.throwIt(SW_ENCRYPT_ERROR);
			  Util.arrayCopyNonAtomic(DB,(short)(32),buffer,(short)0,err); 
			  apdu.setOutgoingAndSend((short)0,err);
			}
		
			else if (P2 == AESCCM_DECRYPT)
		    {
		      try 
		      { key1.setKey(buffer, (short)5);
	            cipher1.init(key1,Cipher.MODE_ENCRYPT);
	          }
	          catch (CryptoException e){ISOException.throwIt(SW_DECRYPT_ERROR); }
	          len = (short)(len - (16+12+5+16));
	          err = aesccm_decrypt(cipher1,buffer,(short)(5+16+12+5+16),len,
								   buffer,(short)(5+16),
								   buffer,(short)(5+16+12),(short)5,
								   DB,(short)32,
								   buffer,(short)(5+16+12+5));
			  if (err <0)   ISOException.throwIt(SW_DECRYPT_ERROR);
			  Util.arrayCopyNonAtomic(DB,(short)(32),buffer,(short)0,err); 
			  apdu.setOutgoingAndSend((short)0,err);
			}

			
 	      	else if (P2 == (byte)2) // Compute HMAC
	    	{
	    	len = Util.makeShort((byte)0,buffer[(short)5])      ;  // Longueur clé
	    		    	
	    	hmac(buffer,(short)6,len,
				 buffer,(short)(7+len),Util.makeShort((byte)0,buffer[(short)(6+len)]),
				 sha256,
				 buffer,(short)0,true);
            
	    	apdu.setOutgoingAndSend((short)0,(short)sha256.getLength());
	    	}
	    	
	    	else if (P2 == EXTRACT_EARLY)
	    	{
	    	len = Util.makeShort((byte)0,buffer[(short)5]);  // hmac key-length
	    		    	
	    	hmac(buffer,(short)6,len,
				 buffer,(short)(7+len),Util.makeShort((byte)0,buffer[(short)(6+len)]),
				 sha256,
				 buffer,(short)0,true);
				 Util.arrayCopyNonAtomic(buffer,(short)0,ESK,(short)0,(short)ESK.length); 
				 				 
			Util.arrayCopyNonAtomic(buffer,(short)0,buffer,(short)32,(short)32);
			
			hmac(ESK,(short)0,(short)ESK.length,
				 derived,(short)0,(short)derived.length,
				 sha256,
				 buffer,(short)0,true);
			
			Util.arrayCopyNonAtomic(buffer,(short)0,HSK,(short)0,(short)HSK.length);  

			Util.arrayCopyNonAtomic(buffer,(short)0,buffer,(short)64,(short)32);

		        
	        hmac(ESK,(short)0,(short)ESK.length,
				 ext_binder,(short)0,(short)ext_binder.length,
				 sha256,
				 buffer,(short)0,true);
				 Util.arrayCopyNonAtomic(buffer,(short)0,eBSK,(short)0,(short)eBSK.length);  
		
			
			Util.arrayCopyNonAtomic(buffer,(short)0,buffer,(short)96,(short)32);

		
	        hmac(ESK,(short)0,(short)ESK.length,
				 res_binder,(short)0,(short)res_binder.length,
				 sha256,
				 buffer,(short)0,true);
			Util.arrayCopyNonAtomic(buffer,(short)0,rBSK,(short)0,(short)rBSK.length);  
			
			
			Util.arrayCopyNonAtomic(buffer,(short)0,buffer,(short)128,(short)32);

			
		    hmac(eBSK,(short)0,(short)eBSK.length,
				 finished,(short)0,(short)finished.length,
				 sha256,
				 buffer,(short)0,true);
			Util.arrayCopyNonAtomic(buffer,(short)0,feBSK,(short)0,(short)feBSK.length);  
			
			
			Util.arrayCopyNonAtomic(buffer,(short)0,buffer,(short)160,(short)32);

		
		    
			hmac(rBSK,(short)0,(short)rBSK.length,
				 finished,(short)0,(short)finished.length,
				 sha256,
				 buffer,(short)0,true);
			
			Util.arrayCopyNonAtomic(buffer,(short)0,frBSK,(short)0,(short)frBSK.length);  
			
			
			Util.arrayCopyNonAtomic(buffer,(short)0,buffer,(short)192,(short)32);

				
		    if(P1==(byte)0xFF)					
			apdu.setOutgoingAndSend((short)32,(short)192); 
			
	   
	    	return ;
	    	
	    	}
	    	
	    	// length (2 bytes) message (length data)
	    	else if (P2 == EXPAND_EARLY)
	    	{ len = Util.makeShort((byte)0,buffer[(short)7]);  // data len
	    		
		    if (P1 == (byte)0)	
		    {
		    Util.arrayCopyNonAtomic(buffer,(short)5,buffer,(short)0,(short)2);
		    Util.arrayCopyNonAtomic(buffer,(short)7,buffer,(short)(2+ c_e_traffic.length),(short)(readCount-2));
			Util.arrayCopyNonAtomic(c_e_traffic,(short)0,buffer,(short)2,(short)c_e_traffic.length);
			buffer[(short)(readCount + c_e_traffic.length)] = (byte)0x01;
			
			hmac(ESK,(short)0,(short)ESK.length,
				 buffer,(short)0,(short)(readCount+c_e_traffic.length+1),
				 sha256,
				 buffer,(short)0,true);
			
			apdu.setOutgoingAndSend((short)0,(short)sha256.getLength()); 
		    return;	
			}
			else if (P1 == (byte)1)
			{
			Util.arrayCopyNonAtomic(buffer,(short)5,buffer,(short)0,(short)2);
		    Util.arrayCopyNonAtomic(buffer,(short)7,buffer,(short)(2+ c_exp_master.length),(short)(readCount-2));
			Util.arrayCopyNonAtomic(c_exp_master,(short)0,buffer,(short)2,(short)c_exp_master.length);
			buffer[(short)(readCount + c_exp_master.length)] = (byte)0x01;
			hmac(ESK,(short)0,(short)ESK.length,
				 buffer,(short)0,(short)(readCount+c_exp_master.length+1),
				 sha256,
				 buffer,(short)0,true);
			
			apdu.setOutgoingAndSend((short)0,(short)sha256.getLength()); 
		
		   return;	
	        }
	         else
	    	 ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	    	}
	    	
	    	else if ( P2 == HMAC_RBSK)
	    	{
		    hmac(frBSK,(short)0,(short)rBSK.length,
				 buffer,(short)5,readCount,
				 sha256,
				 buffer,(short)0,true);
            
	    	apdu.setOutgoingAndSend((short)0,(short)sha256.getLength());
		
	    	}
	    	else if (P2 == HMAC_EBSK)
	    	{
		    hmac(feBSK,(short)0,(short)eBSK.length,
				 buffer,(short)5,readCount,
				 sha256,
				 buffer,(short)0,true);
            
	    	apdu.setOutgoingAndSend((short)0,(short)sha256.getLength());
		   	}
	    	
	    	else if (P2 == EXTRACT_HANDSHAKE )
	    	{
		     hmac(HSK,(short)0,(short)HSK.length,
				  buffer,(short)5,readCount,
				  sha256,
				  buffer,(short)0,true);	
			      apdu.setOutgoingAndSend((short)0,(short)sha256.getLength());   
	    	}
	    	
	    	else
	    	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);		
	    	
	    	break;
	
		case INS_SIGN: // Sign
			
			readCount = apdu.setIncomingAndReceive();  
			
			if ( (!AdminPin.isValidated()) && (!UserPin.isValidated())  )
		    ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			 
			index= Util.makeShort((byte)0,P2);
			
			if ( (index <0) || (index >= N_KEYS))
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			if (!ECCkp[index].getPublic().isInitialized())
				ISOException.throwIt(SW_KPUB_DEFINED);
			
			if (!ECCkp[index].getPrivate().isInitialized())
			    ISOException.throwIt(SW_KPRIV_DEFINED);

            // ALG_ECDSA_SHA_256	33
            // ALG_ECDSA_SHA_384	34
         	// ALG_ECDSA_SHA_512	38
  
            switch (P1)
            {
            case (byte)0: // RAW
            case (byte)33:
     		len= EccSign(ECCkp[index],buffer,P1) ;		
		 	apdu.setOutgoingAndSend((short)0,len);
			break;
						
			default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
            }
            
			break;	
	
			
		case INS_CLEAR_KEYPAIR: 
			
			if ( !AdminPin.isValidated()) 
		    ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			
			index= Util.makeShort((byte)0,P2);
			
			if ( (index <0) || (index >= N_KEYS))
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);	
			 	
			if (ECCkp[index].getPublic().isInitialized())
			 	ECCkp[index].getPublic().clearKey();
			 	
			if (ECCkp[index].getPrivate().isInitialized())
			 	ECCkp[index].getPrivate().clearKey(); 
			 	
			break;
		 		  
				
		case INS_GEN_KEYPAIR: // Generate KeyPair
				
		 if ( !AdminPin.isValidated()) 
		 ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			
			index= Util.makeShort((byte)0,P2);
			
			if ( (index <0) || (index >= N_KEYS))
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			if (ECCkp[index].getPublic().isInitialized())
				ISOException.throwIt(SW_KPUB_DEFINED);
			
			if (ECCkp[index].getPrivate().isInitialized())
			    ISOException.throwIt(SW_KPRIV_DEFINED);
			    
			len=this.GenECCkp(ECCkp[index]);
			
		  break;
		
   		    case INS_GET_KEY_PARAM: // Get Key Parameters
				
			if ( (!AdminPin.isValidated()) && (!UserPin.isValidated())  )
		    ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);	
			
			if (P2 == (byte)0xFF)
				index= N_KEYS ;
			else
			{
			index= Util.makeShort((byte)0,P2);
			if ( (index <0) || (index >= N_KEYS))
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			
			if ( (P1 == (byte)7) && !AdminPin.isValidated()) 
		    ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			
			if ( (P1 == (byte)6) && !ECCkp[index].getPublic().isInitialized())
				ISOException.throwIt(SW_KPUB_DEFINED);
			
			if ( (P1 == (byte)7) && !ECCkp[index].getPrivate().isInitialized())
			    ISOException.throwIt(SW_KPRIV_DEFINED);
			    
	 
			try
			{
			 switch (P1)
			 { 
			 case 0:
			 len= ((ECPublicKey) ECCkp[index].getPublic()).getA(buffer,(short)(2));	
			 Util.setShort(buffer,(short)0,len);
			 apdu.setOutgoingAndSend((short)0,(short)(len+2));		
			 break;
			 
			 case 1:
			 len= ((ECPublicKey) ECCkp[index].getPublic()).getB(buffer,(short)(2));	
			 Util.setShort(buffer,(short)0,len);
			 apdu.setOutgoingAndSend((short)0,(short)(len+2));		
			 break;			 
			 
			 case 2:
			 len= ((ECPublicKey) ECCkp[index].getPublic()).getField(buffer,(short)(2));	
			 Util.setShort(buffer,(short)0,len);
			 apdu.setOutgoingAndSend((short)0,(short)(len+2));		
			 break;			 
			 
			 case 3:
			 len= ((ECPublicKey) ECCkp[index].getPublic()).getG(buffer,(short)(2));	
			 Util.setShort(buffer,(short)0,len);
			 apdu.setOutgoingAndSend((short)0,(short)(len+2));		
			 break;		
	
			 case 4:
			 len= ((ECPublicKey) ECCkp[index].getPublic()).getK();
			 Util.setShort(buffer,(short)2,len);
	   		 Util.setShort(buffer,(short)0,(short)2);
			 apdu.setOutgoingAndSend((short)0,(short)4);		
			 break;		
	
	         case 5:
			 len= ((ECPublicKey) ECCkp[index].getPublic()).getR(buffer,(short)(2));	
			 Util.setShort(buffer,(short)0,len);
			 apdu.setOutgoingAndSend((short)0,(short)(len+2));		
			 break;		
	
			 case (byte)6:
			 len= ((ECPublicKey) ECCkp[index].getPublic()).getW(buffer,(short)(2));					       
			 Util.setShort(buffer,(short)0,len);
			 apdu.setOutgoingAndSend((short)0,(short)(len+2));		
			 break;	
			 
			 case (byte)7:
			 len= ((ECPrivateKey)ECCkp[index].getPrivate()).getS(buffer,(short)(2));					       
			 Util.setShort(buffer,(short)0,len);
			 apdu.setOutgoingAndSend((short)0,(short)(len+2));	
			 break;
			 
			 default:
			 ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			 break;	
			 }
	     	}
		   	
		   	catch (CryptoException e)
	        {ISOException.throwIt(SW_DUMP_KEYS_PAIR);
	         break;
	        }
		   	
			break;			
	 
		case INS_SET_KEY_PARAM: // Set Keys
            	
		readCount = apdu.setIncomingAndReceive(); 
		
		if ( !AdminPin.isValidated()) 
		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
				
		index= Util.makeShort((byte)0,P2);
			
		if ( (index <0) || (index >= N_KEYS))
		ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		if ( (P1 == (byte)6) && ECCkp[index].getPublic().isInitialized())
		ISOException.throwIt(SW_KPUB_DEFINED);
		
		if ( (P1 == (byte)7) && ECCkp[index].getPrivate().isInitialized())
		ISOException.throwIt(SW_KPRIV_DEFINED);
		
		try
		{
			
        switch (P1)
				   { case (byte)0:
					   ((ECPublicKey)ECCkp[index].getPublic()).setA(buffer,(short)5,len) ;
				       ((ECPrivateKey)ECCkp[index].getPrivate()).setA(buffer,(short)5,len);
					   break;
				     case (byte)1:
					   ((ECPublicKey)ECCkp[index].getPublic()).setB(buffer,(short)5,len) ;
				       ((ECPrivateKey)ECCkp[index].getPrivate()).setB(buffer,(short)5,len);
					   break;  
				     case (byte)2:
					   ((ECPublicKey)ECCkp[index].getPublic()).setFieldFP(buffer,(short)5,len) ;
				       ((ECPrivateKey)ECCkp[index].getPrivate()).setFieldFP(buffer,(short)5,len);
					   break;
				     case (byte)3:
					   ((ECPublicKey)ECCkp[index].getPublic()).setG(buffer,(short)5,len) ;
				       ((ECPrivateKey)ECCkp[index].getPrivate()).setG(buffer,(short)5,len);
			 		   break;
				     case (byte)4:
					   ((ECPublicKey)ECCkp[index].getPublic()).setK(Util.makeShort(buffer[5],buffer[6])) ;
				       ((ECPrivateKey)ECCkp[index].getPrivate()).setK(Util.makeShort(buffer[5],buffer[6]));
					   break;  
				     case (byte)5:
					   ((ECPublicKey)ECCkp[index].getPublic()).setR(buffer,(short)5,len) ;
				       ((ECPrivateKey)ECCkp[index].getPrivate()).setR(buffer,(short)5,len);
					   break;
				     case (byte)6:
				       ((ECPublicKey)ECCkp[index].getPublic()).setW(buffer,(short)5,len) ;
					   break;  
				     case (byte)7:
			           ((ECPrivateKey)ECCkp[index].getPrivate()).setS(buffer,(short)5,len);
					   break; 

			   					   						     
					 default:
					   ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
					   break;
						 
				   }
				  }
		 
		 catch (CryptoException e)
	     {ISOException.throwIt(SW_SET_KEY_PARAM);
	       break;
	     }		  

	     break;		
		
    	case INS_ECDHE:
			
		readCount = apdu.setIncomingAndReceive();  
			
		if ( (!AdminPin.isValidated()) && (!UserPin.isValidated())  )
		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			 
		index= Util.makeShort((byte)0,P2);
			
		if (P2 == (byte)0xFF)
		{ index = (short)N_KEYS ;
		  if (genkey(index) != (short)0)
		  ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
			
		else
		{
		if ( (index <0) || (index >= N_KEYS))
		ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
		if (!ECCkp[index].getPublic().isInitialized())
 	    ISOException.throwIt(SW_KPUB_DEFINED);
			
		if (!ECCkp[index].getPrivate().isInitialized())
	    ISOException.throwIt(SW_KPRIV_DEFINED);
		}

        ECPrivateKey privk = (ECPrivateKey)ECCkp[index].getPrivate();
        short len2 = privk.getG(buffer,(short)(5+len));
             
        if (Util.arrayCompare(buffer,(short)5,buffer,(short)(5+len),len2) == (byte)0)
        ISOException.throwIt(SW_DH_ERROR);  	
	         
	    ECCkeyAgreement.init(privk);
	         
	    try  
	    { 
	    len2= ECCkeyAgreement.generateSecret(buffer,(short)5,len,buffer,(short)(len+5)); 
	    }
	    catch (CryptoException e)
	    { ISOException.throwIt(SW_DH_ERROR);}
	    	
	    apdu.setOutgoingAndSend((short)(5+len),len2);
	    break;
	         
	    case INS_INIT_CURVE:  // Init Curve
        	
        if ( !AdminPin.isValidated()) 
		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);	
            	
     	index= Util.makeShort((byte)0,P2);
			
		if ( (index <0) || (index >= N_KEYS))
		ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
		if ( (P1 == (byte)6) && ECCkp[index].getPublic().isInitialized() )
   	    ISOException.throwIt(SW_KPUB_DEFINED);
			
	    if ((P1 == (byte)7) && ECCkp[index].getPrivate().isInitialized())
	    ISOException.throwIt(SW_KPRIV_DEFINED);
	    
	    ((ECPublicKey)ECCkp[index].getPublic()).setA(ParamA1,(short)0,(short)ParamA1.length) ;
		((ECPrivateKey)ECCkp[index].getPrivate()).setA(ParamA1,(short)0,(short)ParamA1.length);
		
		((ECPublicKey)ECCkp[index].getPublic()).setB(ParamB1,(short)0,(short)ParamB1.length) ;
	    ((ECPrivateKey)ECCkp[index].getPrivate()).setB(ParamB1,(short)0,(short)ParamB1.length);
					  
	    ((ECPublicKey)ECCkp[index].getPublic()).setFieldFP(ParamField1,(short)0,(short)ParamField1.length) ;
	    ((ECPrivateKey)ECCkp[index].getPrivate()).setFieldFP(ParamField1,(short)0,(short)ParamField1.length);
					   
		((ECPublicKey)ECCkp[index].getPublic()).setG(ParamG1,(short)0,(short)ParamG1.length) ;
		((ECPrivateKey)ECCkp[index].getPrivate()).setG(ParamG1,(short)0,(short)ParamG1.length);
			 		   
		((ECPublicKey)ECCkp[index].getPublic()).setK(ParamK1) ;
	    ((ECPrivateKey)ECCkp[index].getPrivate()).setK(ParamK1);
					  
		((ECPublicKey)ECCkp[index].getPublic()).setR(ParamR1,(short)0,(short)ParamR1.length) ;
	    ((ECPrivateKey)ECCkp[index].getPrivate()).setR(ParamR1,(short)0,(short)ParamR1.length);
	      
        break;
	    
	    
	    case INS_RND:
	         if (rng == null)
		   	 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		   	 		   	 
		   	 rng.generateData(buffer,(short)0,len);
	    	 apdu.setOutgoingAndSend((short)0,len);
	    	 break;
	    	 
	    	 
  
	     default:  
		 ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);			
  }
  
  }
  
  
   	public short EccSign(KeyPair ECCkeyPair, byte [] buf, byte mode) 
	{ short len,sLen=(short)0;
		
	len= Util.makeShort((byte)0,buf[4]);
	Util.arrayCopy(buf,(short)5,buf,(short)2,len);
	 
	 // Sign
    try
	{// (byte)33 = Signature.ALG_ECDSA_SHA_256
	if (mode == (byte)0)// default
	{ ECCsig.init(ECCkeyPair.getPrivate(),Signature.MODE_SIGN);
      sLen = ECCsig.signPreComputedHash(buf, (short)2, len, buf, (short)(2+len));
	} 
	else
	{ ECCsig.init(ECCkeyPair.getPrivate(),Signature.MODE_SIGN);
      sLen = ECCsig.sign(buf, (short)2, len, buf, (short)(2+len));
	}	
	
	}
	catch (CryptoException e)
	{ISOException.throwIt(SW_SIGN_ERROR);
	 return (short)0;
	}
	
	Util.arrayCopy(buf,(short)(2+len),buf,(short)2,sLen);
	Util.setShort(buf,(short)0,sLen);
	
	return(short)(sLen+2);
	}
  
  
  	public short GenECCkp(KeyPair ECCkeyPair)
	{ short len;
	
	try
	{
	ECCkeyPair.genKeyPair();
	} 
	catch (CryptoException e)
	{ISOException.throwIt(SW_GENKEY_ERROR);
	 return (short)0;
	}
	
	return 0;
	
	}
	
  
  public void verify(OwnerPIN pin,byte [] buffer) throws ISOException
  {short i,x;
   
   x = Util.makeShort((byte)0,buffer[4]);
   
   for(i=x;i<(short)8;i=(short)(i+1))
	   buffer[(short)(5+i)]=(byte)0xFF;
	  
   if ( pin.check(buffer, (short)5,(byte)8) == false )
   ISOException.throwIt((short)((short)SW_VERIFICATION_FAILED | (short)pin.getTriesRemaining()));
  }
  
  
 public short aesccm_decrypt(Cipher aes, byte in[], short in_off, short in_len,
						        byte nonce[], short nonce_off,
						        byte auth[], short auth_off, short auth_len,
						        byte out[], short out_off,
						        byte tag[],short tag_off)
 {  short i,r,n,k;
    if (auth_len> (short)14) return (short)-1;
    
    DB[16]= 2;
	DB[29]=DB[30]=0;
	DB[31]=1;
    for(i=0;i<12;i++) DB[(short)(17+i)] = nonce[(short)(nonce_off+i)];
    
   	n = (short)(in_len>>4);
	r = (short)(in_len & 0xF);
	
	// Decrypt
	
	for(k=0;k<n;k++)
	{ 
	  try{aes.doFinal(DB,(short)16,(short)16,DB,(short)0);}
	  catch (CryptoException e){return -1;}
	  DB[31] = (byte)(DB[31]+1);
	  for (i=0;i<(short)16;i++) out[(short)(out_off+(k<<4)+i)]=(byte)(in[(short)(in_off+(k<<4)+i)] ^ DB[i]);
	}	
	
	try{aes.doFinal(DB,(short)16,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	// for (i=0;i<r;i++) out[(short)(out_off+(k<<4)+i)]= (byte)(in[(short)(in_off+(n<<4)+i)] ^ DB[i] )   ;
	for (i=0;i<r;i++) out[(short)(out_off+(n<<4)+i)]= (byte)(in[(short)(in_off+(n<<4)+i)] ^ DB[i] )   ;

    // compute tag
    DB[16]= (byte)0x7A;
	DB[29]=0 ; // 29=13+16, 30=14+16
	DB[30] = (byte)((in_len>>8) & 0xFF);
	DB[31] = (byte)(in_len & 0xFF);
	
	try{aes.doFinal(DB,(short)16,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	
	// !up to 14 authentication bytes
	DB[1] ^= (byte) (auth_len & 0xFF) ;

	for(i=0;i<auth_len;i++) DB[(short)(i+2)] ^= auth[(short)(i+auth_off)] ;
	try{aes.doFinal(DB,(short)0,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	
	for(k=0;k<n;k++)
	{
	for(i=0;i<(short)16;i++) DB[(short)(i)] ^= out[(short)(out_off+i+(k<<4))] ;
	try{aes.doFinal(DB,(short)0,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	}
	
	for(i=0;i<r;i++)
	DB[(short)(i)] ^= out[(short)(out_off+i+(n<<4))] ;
	try{aes.doFinal(DB,(short)0,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	
	// TAG= DB[0...15]
    DB[16]= 2;
	DB[29]=DB[30]=DB[31]=0;
	
	try{aes.doFinal(DB,(short)16,(short)16,DB,(short)16);}
	catch (CryptoException e){return -1;}
	for(i=0;i<(short)16;i++) DB[i] ^= DB[(short)(i+16)];
    
    if (Util.arrayCompare(DB,(short)0,tag,tag_off,(short)16) != (byte)0)
    	return -1;
 
 return in_len;
 }
  
  
  
  public short aesccm_encrypt(Cipher aes, byte in[], short in_off, short in_len,
						        byte nonce[], short nonce_off,
						        byte auth[], short auth_off, short auth_len,
						        byte out[], short out_off,
						        byte tag[],short tag_off)
 {  short i,r,n,k;
    
    if (auth_len> (short)14) return (short)-1;
   
    DB[16]= (byte)0x7A;
	for(i=0;i<12;i++) DB[(short)(17+i)] = nonce[(short)(nonce_off+i)];
	DB[29]=0 ; // 29=13+16, 30=14+16
	DB[30] = (byte)((in_len>>8) & 0xFF);
	DB[31] = (byte) (in_len & 0xFF) ;
	
	try{aes.doFinal(DB,(short)16,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	
	// !up to 14 authentication bytes

  	DB[1] ^= (byte) (auth_len & 0xFF) ;

	for(i=0;i<auth_len;i++) DB[(short)(i+2)] ^= auth[(short)(i+auth_off)] ;
	try{aes.doFinal(DB,(short)0,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	
	n = (short)(in_len>>4);
	r = (short)(in_len & 0xF);
	
	for(k=0;k<n;k++)
	{
	for(i=0;i<(short)16;i++) DB[(short)(i)] ^= in[(short)(in_off+i+(k<<4))] ;
	try{aes.doFinal(DB,(short)0,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	}
	
	for(i=0;i<r;i++)
	DB[(short)(i)] ^= in[(short)(in_off+i+(n<<4))] ;
	try{aes.doFinal(DB,(short)0,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	
	for(i=0;i<(short)16;i++) tag[(short)(tag_off+i)] = DB[i] ;
	
	//////////////////////////////////////////////////////////
		
	DB[16]= 2;
	DB[29]=DB[30]=DB[31]=0;
	
	try{aes.doFinal(DB,(short)16,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}
	for(i=0;i<(short)16;i++) tag[(short)(tag_off+i)] ^= DB[i];
	
	DB[31]= 1;
	for(k=0;k<n;k++)
	{ 
	  try{aes.doFinal(DB,(short)16,(short)16,DB,(short)0);}
	  catch (CryptoException e){return -1;}
	  DB[31] = (byte)(DB[31]+1);
	  for (i=0;i<(short)16;i++) out[(short)(out_off+(k<<4)+i)]=(byte)(in[(short)(in_off+(k<<4)+i)] ^ DB[i])   ;
	}	
	
	try{aes.doFinal(DB,(short)16,(short)16,DB,(short)0);}
	catch (CryptoException e){return -1;}

	for (i=0;i<r;i++) out[(short)(out_off+(n<<4)+i)]= (byte)(in[(short)(in_off+(n<<4)+i)] ^ DB[i] )   ;
	
	return (short)(in_len+16); 
 }						        

  
  /**
 * HMAC Procedure
 *<br>Secret key        : k, k_off, lk
 *<br>Data              : d, d_off, ld
 *<br>Message Digest    : md
 *<br>Output            : out, out_off
 *<br>returns: nothing
 */
 
public static final short  DB_off = (short)0    ;

 public void  hmac
   ( byte []  k,short k_off, short lk,    /* Secret key */
     byte []  d,short d_off,short ld,     /* data       */
     MessageDigest md,
	 byte out[], short out_off, boolean init)
   {  	     
           short i,DIGESTSIZE=(short)32,BLOCKSIZE=(short)64 ; 
		   	   
		   if (init)
		   {
		   if (lk > (short)BLOCKSIZE ) 
		   {  md.reset();
              md.doFinal(k,k_off,lk,k,k_off);
              lk = DIGESTSIZE ;
           }
		   
		   //=====================================================
		   // BLOCKSIZE DIGESTSIZE BLOCKSIZE = 64 + 32 + 64 = 160 
		   //=====================================================
		   
           for (i = 0 ; i < lk ; i=(short)(i+1)) 
           DB[(short)(i+DB_off+BLOCKSIZE+DIGESTSIZE)] = (byte)(k[(short)(i+k_off)] ^ (byte)0x36) ;
	   	   Util.arrayFillNonAtomic(DB,(short)(BLOCKSIZE+DIGESTSIZE+lk+DB_off),(short)(BLOCKSIZE-lk),(byte)0x36);
			   		            
           for (i = 0 ; i < lk ; i=(short)(i+1)) DB[(short)(i+DB_off)] = (byte)(k[(short)(i+k_off)] ^ (byte)0x5C);
           Util.arrayFillNonAtomic(DB,(short)(lk+DB_off),(short)(BLOCKSIZE-lk),(byte)0x5C);
		  
		   }
					   
	       md.reset();
		   md.update(DB,(short)(DB_off+BLOCKSIZE+DIGESTSIZE),BLOCKSIZE);
		   md.doFinal(d, d_off,ld,DB,(short)(DB_off+BLOCKSIZE));
		   
   		   md.reset();
		   md.doFinal(DB,DB_off,(short)(DIGESTSIZE+BLOCKSIZE),out,out_off);
		   
	    }
   
public short genkey(short index)
{
if (ECCkp[index].getPublic().isInitialized())
ECCkp[index].getPublic().clearKey();
			 	
if (ECCkp[index].getPrivate().isInitialized())
ECCkp[index].getPrivate().clearKey(); 
// Public
((ECPublicKey)ECCkp[index].getPublic()).setA(ParamA1,(short)0,(short)ParamA1.length) ;
((ECPublicKey)ECCkp[index].getPublic()).setB(ParamB1,(short)0,(short)ParamB1.length) ;
((ECPublicKey)ECCkp[index].getPublic()).setFieldFP(ParamField1,(short)0,(short)ParamField1.length) ;
((ECPublicKey)ECCkp[index].getPublic()).setG(ParamG1,(short)0,(short)ParamG1.length) ;
((ECPublicKey)ECCkp[index].getPublic()).setK(ParamK1) ;
((ECPublicKey)ECCkp[index].getPublic()).setR(ParamR1,(short)0,(short)ParamR1.length);
//Private
((ECPrivateKey)ECCkp[index].getPrivate()).setA(ParamA1,(short)0,(short)ParamA1.length);
((ECPrivateKey)ECCkp[index].getPrivate()).setB(ParamB1,(short)0,(short)ParamB1.length);
((ECPrivateKey)ECCkp[index].getPrivate()).setFieldFP(ParamField1,(short)0,(short)ParamField1.length);
((ECPrivateKey)ECCkp[index].getPrivate()).setG(ParamG1,(short)0,(short)ParamG1.length);
((ECPrivateKey)ECCkp[index].getPrivate()).setK(ParamK1);
((ECPrivateKey)ECCkp[index].getPrivate()).setR(ParamR1,(short)0,(short)ParamR1.length);

try
{ ECCkp[index].genKeyPair();} 
catch (CryptoException e)
{ISOException.throwIt(SW_GENKEY_ERROR);
 return (short)-1;
}
return 0;
}

    /**
     * Only this class's install method should create the applet object.
     * @see APDU
     * @param apdu the incoming APDU containing the INSTALL command.
     */
    protected tls_se(byte[] bArray,short bOffset,byte bLength)
    {
		init();
        register();
	}
	

void compute_psk(byte psk[],short off,short len, byte[] buffer)
{	    
	
hmac(zero32,(short)0,(short)1,
     psk,off,len,
     sha256,
     buffer,(short)0,true);
 
 Util.arrayCopyNonAtomic(buffer,(short)0,ESK,(short)0,(short)ESK.length); 
				 				 
 hmac(ESK,(short)0,(short)ESK.length,
	  derived,(short)0,(short)derived.length,
	  sha256,
   	  buffer,(short)0,true);
			
 Util.arrayCopyNonAtomic(buffer,(short)0,HSK,(short)0,(short)HSK.length);  

 hmac(ESK,(short)0,(short)ESK.length,
	  ext_binder,(short)0,(short)ext_binder.length,
	  sha256,
	  buffer,(short)0,true);

 Util.arrayCopyNonAtomic(buffer,(short)0,eBSK,(short)0,(short)eBSK.length);  
		
 hmac(ESK,(short)0,(short)ESK.length,
	  res_binder,(short)0,(short)res_binder.length,
	  sha256,
	  buffer,(short)0,true);

 Util.arrayCopyNonAtomic(buffer,(short)0,rBSK,(short)0,(short)rBSK.length);  
			
 hmac(eBSK,(short)0,(short)eBSK.length,
	  finished,(short)0,(short)finished.length,
	  sha256,
	  buffer,(short)0,true);

 Util.arrayCopyNonAtomic(buffer,(short)0,feBSK,(short)0,(short)feBSK.length);  
			
  hmac(rBSK,(short)0,(short)rBSK.length,
	   finished,(short)0,(short)finished.length,
	   sha256,
	   buffer,(short)0,true);
			
 Util.arrayCopyNonAtomic(buffer,(short)0,frBSK,(short)0,(short)frBSK.length);  
			

 
}



	
	public void init()
	{   short i=0;
	    
	    status = (short)0;	         

		ECCkp = new KeyPair[N_KEYS+1] ;
	
		UserPin   = new OwnerPIN((byte)3,(byte)8) ;  // 3  tries 4=Max Size
		AdminPin  = new OwnerPIN((byte)10,(byte)8);  // 10 tries 8=Max Size
      
 	    UserPin.update(MyPin,(short)0,(byte)8) ;
		AdminPin.update(OpPin,(short)0,(byte)8);
		
		for(i=0;i<(N_KEYS+1);i++)
		{
		  try 
		  { 
           ECCkp[i] = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_256);
	   	   status =(short)(status + (short)1);	         
	      }
	       catch (CryptoException e){}
	  	}
           
        try 
        {
	    ECCsig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
	    status =(short)(status | (short)0x1000);
	    }
        catch (CryptoException e){}
        
 	   try 
       {
	   ECCkeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
	   status =(short)(status | (short)0x2000);
	   }
	   catch (CryptoException e){}
        
       try 
	   {
	   sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
	   sha0 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
	   sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
	   sha2 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
	   status =(short)(status | (short)0x4000);
	   }
	   catch (CryptoException e){}
	   
	   try 
	   {
	   rng    = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	   status =(short)(status | (short)0x8000);
	   }
	   catch (CryptoException e){}
	   
	   try {
	   cipher1     = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
	   cipher2     = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false); 
	   status =(short)(status | (short)0x0100);}
	   catch (CryptoException e){}
	  

	  try {
	  key1 = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES,KeyBuilder.LENGTH_AES_128,false);
	  key2 = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES,KeyBuilder.LENGTH_AES_128,false);
	  status =(short)(status | (short)0x0200);}
	  catch (CryptoException e){}
	
   
     DB = JCSystem.makeTransientByteArray(DBSIZE,JCSystem.CLEAR_ON_DESELECT);
     RX = JCSystem.makeTransientByteArray(RXSIZE,JCSystem.CLEAR_ON_DESELECT);
     VS = JCSystem.makeTransientShortArray(VSSIZE,JCSystem.CLEAR_ON_DESELECT);
     
     compute_psk(mypsk,(short)0,(short)mypsk.length,DB);

	}
  
  public static void install( byte[] bArray, short bOffset, byte bLength )
  {  
     new tls_se(bArray,bOffset,bLength);
  }

  public boolean select()
  { if (UserPin.isValidated())
    UserPin.reset();
    if (AdminPin.isValidated())
    AdminPin.reset();
    reset_tls();
    // This method shall not be invoked from the Applet.install() method
    org.globalplatform.GPSystem.setATRHistBytes(HistByteArray,(short)0,(byte)HistByteArray.length);
    return true;
  }
  
  public tls_se()
  { init();
	register();
  }

  public void deselect()
  {
  }
	



}




