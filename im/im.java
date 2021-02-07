/* im.java */

/* Copyright (C) 2020 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 *
 * This software is an implementation of TLS13 Identity Module in Javacard 3.0.4
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
 *    "This product includes TLS-IM software written by
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
// TLS-IM Version 1.0  //
/////////////////////////

package im;

import javacard.framework.*;
import javacard.security.* ;
import javacardx.crypto.*  ;

/**
 */

public class im extends Applet
{  
	
	final static byte  INS_SIGN          = (byte)  0x80        ;
	final static byte  INS_CLEAR_KEYPAIR = (byte)  0x81        ;
	final static byte  INS_GEN_KEYPAIR   = (byte)  0x82        ;
	final static byte  INS_GET_KEY_PARAM = (byte)  0x84        ;
	final static byte  INS_HMAC          = (byte)  0x85        ;
	final static byte  INS_GET_STATUS    = (byte)  0x87        ;
	final static byte  INS_SET_KEY_PARAM = (byte)  0x88        ;
	final static byte  INS_INIT_CURVE    = (byte)  0x89        ;
	
	final static byte        INS_SELECT     = (byte) 0xA4 ;
	public final static byte INS_VERIFY     = (byte) 0x20 ;
	public final static byte INS_CHANGE_PIN = (byte) 0x24 ;
	
	public final static short N_KEYS     = (short) 16;
	public final static byte[] VERSION= {(byte)1,(byte)0};
	
	KeyPair[] ECCkp       = null  ;
	Signature ECCsig      = null  ;
	MessageDigest sha256  = null  ;

    short status=0                                ;
	byte [] DB = null                             ;
	public final static short DBSIZE = (short)320 ;
	
	
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

	private final static byte [] ParamA1    = {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xfc};
	private final static byte [] ParamB1    = {(byte)0x5a,(byte)0xc6,(byte)0x35,(byte)0xd8,(byte)0xaa,(byte)0x3a,(byte)0x93,(byte)0xe7,(byte)0xb3,(byte)0xeb,(byte)0xbd,(byte)0x55,(byte)0x76,(byte)0x98,(byte)0x86,(byte)0xbc,(byte)0x65,(byte)0x1d,(byte)0x06,(byte)0xb0,(byte)0xcc,(byte)0x53,(byte)0xb0,(byte)0xf6,(byte)0x3b,(byte)0xce,(byte)0x3c,(byte)0x3e,(byte)0x27,(byte)0xd2,(byte)0x60,(byte)0x4b};
    private final static byte [] ParamField1= {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
     
    private final static byte [] ParamG1=     {(byte)0x04,(byte)0x6b,(byte)0x17,(byte)0xd1,(byte)0xf2,(byte)0xe1,(byte)0x2c,(byte)0x42,(byte)0x47,(byte)0xf8,(byte)0xbc,(byte)0xe6,(byte)0xe5,(byte)0x63,(byte)0xa4,(byte)0x40,(byte)0xf2,(byte)0x77,(byte)0x03,(byte)0x7d,(byte)0x81,(byte)0x2d,(byte)0xeb,(byte)0x33,(byte)0xa0,(byte)0xf4,(byte)0xa1,(byte)0x39,(byte)0x45,(byte)0xd8,(byte)0x98,(byte)0xc2,(byte)0x96,
                                                          (byte)0x4f,(byte)0xe3,(byte)0x42,(byte)0xe2,(byte)0xfe,(byte)0x1a,(byte)0x7f,(byte)0x9b,(byte)0x8e,(byte)0xe7,(byte)0xeb,(byte)0x4a,(byte)0x7c,(byte)0x0f,(byte)0x9e,(byte)0x16,(byte)0x2b,(byte)0xce,(byte)0x33,(byte)0x57,(byte)0x6b,(byte)0x31,(byte)0x5e,(byte)0xce,(byte)0xcb,(byte)0xb6,(byte)0x40,(byte)0x68,(byte)0x37,(byte)0xbf,(byte)0x51,(byte)0xf5};
    private final static short   ParamK1 =    (short) 0x0001;
    private final static byte [] ParamR1=     {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xbc,(byte)0xe6,(byte)0xfa,(byte)0xad,(byte)0xa7,(byte)0x17,(byte)0x9e,(byte)0x84,(byte)0xf3,(byte)0xb9,(byte)0xca,(byte)0xc2,(byte)0xfc,(byte)0x63,(byte)0x25,(byte)0x51};
    
    //private final static byte [] zero= {(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0};
    
    
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
    
    private byte [] derived =      {(byte)0x00,(byte)32,(byte)13,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'d',(byte)'e',(byte)'r',(byte)'i',(byte)'v',(byte)'e',(byte)'d',(byte)0x20,(byte)0xE3,(byte)0xB0,(byte)0xC4,(byte)0x42,(byte)0x98,(byte)0xFC,(byte)0x1C,(byte)0x14,(byte)0x9A,(byte)0xFB,(byte)0xF4,(byte)0xC8,(byte)0x99 ,(byte)0x6F ,(byte)0xB9,(byte)0x24,(byte)0x27 ,(byte)0xAE,(byte)0x41,(byte)0xE4,(byte)0x64,(byte)0x9B,(byte)0x93,(byte)0x4C,(byte)0xA4,(byte)0x95,(byte)0x99,(byte)0x1B,(byte)0x78,(byte)0x52,(byte)0xB8,(byte)0x55,(byte)0x01};
    private byte [] ext_binder   = {(byte)0x00,(byte)32,(byte)16,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'e',(byte)'x',(byte)'t',(byte)' ',(byte)'b',(byte)'i',(byte)'n',(byte)'d',(byte)'e',(byte)'r',(byte)0x20,(byte)0xE3,(byte)0xB0,(byte)0xC4,(byte)0x42,(byte)0x98,(byte)0xFC,(byte)0x1C,(byte)0x14,(byte)0x9A,(byte)0xFB,(byte)0xF4,(byte)0xC8,(byte)0x99 ,(byte)0x6F ,(byte)0xB9,(byte)0x24,(byte)0x27 ,(byte)0xAE,(byte)0x41,(byte)0xE4,(byte)0x64,(byte)0x9B,(byte)0x93,(byte)0x4C,(byte)0xA4,(byte)0x95,(byte)0x99,(byte)0x1B,(byte)0x78,(byte)0x52,(byte)0xB8,(byte)0x55,(byte)0x01};
    private byte [] res_binder   = {(byte)0x00,(byte)32,(byte)16,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'r',(byte)'e',(byte)'s',(byte)' ',(byte)'b',(byte)'i',(byte)'n',(byte)'d',(byte)'e',(byte)'r',(byte)0x00,(byte)0x01};
    private byte [] c_e_traffic  = {(byte)17,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'c',(byte)' ',(byte)'e',(byte)' ',(byte)'t',(byte)'r',(byte)'a',(byte)'f',(byte)'f',(byte)'i',(byte)'c'};
    private byte [] c_exp_master = {(byte)18,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'e',(byte)' ',(byte)'e',(byte)'x',(byte)'p',(byte)' ',(byte)'m',(byte)'a',(byte)'s',(byte)'t',(byte)'e',(byte)'r'};
    private byte [] finished     = {(byte)0x00,(byte)32,(byte)14,(byte)'t',(byte)'l',(byte)'s',(byte)'1',(byte)'3',(byte)' ',(byte)'f',(byte)'i',(byte)'n',(byte)'i',(byte)'s',(byte)'h',(byte)'e',(byte)'d',(byte)0x00,(byte)0x01};
 
 
public void process(APDU apdu) throws ISOException
  { short adr=0,len=0,index=0,readCount=0;
	
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
		
		case INS_VERIFY:   
						   
		readCount = apdu.setIncomingAndReceive()        ;
						   
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
		    
	      	if (P2 == (byte)2) // Compute HMAC
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

            // ALG_ECDSA_SHA	    17
       	    // ALG_ECDSA_SHA_224	37
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
			
			index= Util.makeShort((byte)0,P2);
			
			if ( (index <0) || (index >= N_KEYS))
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
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
	    
	    switch((byte)P1)
		{	
			
		 case (byte)0:			
	     case (byte)1:		 
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
	     
	     
	     default:
	     ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		 break;
	     }
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
  
  /**
 * HMAC Procedure
 *<br>Secret key        : k, k_off, lk
 *<br>Data              : d, d_off, ld
 *<br>Message Digest    : md
 *<br>Output            : out, out_off
 *<br>returns: nothing
 */
 
//public static final short  BLOCKSIZE  = (short)128  ; // 1024 bits
//public static final short  DIGESTSIZE2= (short)64   ; // 512 bits

public static final short      DB_off = (short)0    ;

 public void  hmac
   ( byte []  k,short k_off, short lk,    /* Secret key */
     byte []  d,short d_off,short ld,     /* data       */
     MessageDigest md,
	 byte out[], short out_off, boolean init)
   {  	     
           short i,DIGESTSIZE, DIGESTSIZE2=(short)64,BLOCKSIZE=(short)128; 
		   
		   DIGESTSIZE=(short)md.getLength();
		   
		   if (md.getAlgorithm() == md.ALG_SHA_512)
		   { DIGESTSIZE2= (short)64;BLOCKSIZE  = (short)128; }
		   else if (md.getAlgorithm() == md.ALG_SHA_256)
		   { DIGESTSIZE2= (short)32; BLOCKSIZE = (short)64; }
		   
		   if (init)
		   {
		   if (lk > (short)BLOCKSIZE ) 
		   {  md.reset();
              md.doFinal(k,k_off,lk,k,k_off);
              lk = DIGESTSIZE ;
           }
		   
		   //=======================================================
		   // BLOCKSIZE DIGESTSIZE2 BLOCKSIZE = 128 + 64 + 128 = 320 
		   //=======================================================
           for (i = 0 ; i < lk ; i=(short)(i+1)) 
           DB[(short)(i+DB_off+BLOCKSIZE+DIGESTSIZE2)] = (byte)(k[(short)(i+k_off)] ^ (byte)0x36) ;
	   	   Util.arrayFillNonAtomic(DB,(short)(BLOCKSIZE+DIGESTSIZE2+lk+DB_off),(short)(BLOCKSIZE-lk),(byte)0x36);
			   		            
           for (i = 0 ; i < lk ; i=(short)(i+1)) DB[(short)(i+DB_off)] = (byte)(k[(short)(i+k_off)] ^ (byte)0x5C);
           Util.arrayFillNonAtomic(DB,(short)(lk+DB_off),(short)(BLOCKSIZE-lk),(byte)0x5C);
		  
		   }
					   
	       md.reset();
		   md.update(DB,(short)(DB_off+BLOCKSIZE+DIGESTSIZE2),BLOCKSIZE);
		   md.doFinal(d, d_off,ld,DB,(short)(DB_off+BLOCKSIZE));
		   
   		   md.reset();
		   md.doFinal(DB,DB_off,(short)(DIGESTSIZE+BLOCKSIZE),out,out_off);
   }
   
  
	
    /**
     * Only this class's install method should create the applet object.
     * @see APDU
     * @param apdu the incoming APDU containing the INSTALL command.
     */
    protected im(byte[] bArray,short bOffset,byte bLength)
    {
		init();
        register();
	}

	
	public void init()
	{   short i=0;
	    
	    status = (short)0;	         

		ECCkp = new KeyPair[N_KEYS] ;
	
		UserPin   = new OwnerPIN((byte)3,(byte)8) ;  // 3  tries 4=Max Size
		AdminPin  = new OwnerPIN((byte)10,(byte)8);  // 10 tries 8=Max Size
      
 	    UserPin.update(MyPin,(short)0,(byte)8) ;
		AdminPin.update(OpPin,(short)0,(byte)8);
		
		for(i=0;i<N_KEYS;i++)
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
	    status =(short)(status | (short)0x0100);
	    }
        catch (CryptoException e){}
        
        
       try 
	   {
	   sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
	   status =(short)(status | (short)0x2000);
	   }
	   catch (CryptoException e){}
	   
       
       DB = JCSystem.makeTransientByteArray(DBSIZE,JCSystem.CLEAR_ON_DESELECT);
	}
    /**
     * Installs this applet.
     * @see APDU
     * @param apdu the incoming APDU containing the INSTALL command.
     * @exception ISOException with the response bytes per ISO 7816-4
     */
    public static void install( byte[] bArray, short bOffset, byte bLength )
    {
        new im(bArray,bOffset,bLength);
    }

  public boolean select()
  { if (UserPin.isValidated())
    UserPin.reset();
    if (AdminPin.isValidated())
    AdminPin.reset();
    return true;
  }
  
  public im()
  { init();
	register();
  }

  public void deselect()
  {
  }
	



}


