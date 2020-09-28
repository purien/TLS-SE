
/* server.java */

/* Copyright (C) 2020 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 *
 * This software is an implementation of TCP/IP server 
 * for TLS13 Secure Element (TLS-SE)
 * https://datatracker.ietf.org/doc/draft-urien-tls-se/
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
 *    "This product TCP/IP server for TLS-SE software written by
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


package servertlsse;

import java.io.* ;
import java.net.*;
import java.util.List;

import javax.smartcardio.*;

public   class server 
{
	static Socket client=null        ;
	static DataInputStream  in=null  ;
	static DataOutputStream out=null ;
	static ServerSocket soq=null   ;
	static String myip="127.0.0.1" ;
	static short port = 444;
	static int queue_size=0;
	static final int RXSIZE= 2048 ;
	static byte[] rx= new byte[RXSIZE];
	static int ptrx=0;
	static int stimeout=30000;
	
	static String ReaderName = "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"; 
	static Card card =null;
	static TerminalFactory factory = null;
	static CardTerminal terminal = null;
	static ResponseAPDU r=null;
	static ATR atr=null;
	static CardTerminals cardterminals=null;
	static CardChannel channel =null;
	static String Select = "00A4040006010203040500";
	static String User =  "002000000430303030";
	static String Admin=  "00200001083030303030303030";
	static String ResetTLS=  "00D8000000";
	static String SetPSK= "0085000A230100200102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20";
	
	static byte[] More = {0,(byte)0xC0,0,0,0};
	
	public static void main(String[] args) 
	{ int err;
	  byte flag=0;
	  boolean fopen=false,fclose=false;
		
	    if (!SE_init())
	    { System.out.println("SE_init Error");return ;}
	    
	    // Set the PSK secret
	    if (!SE_open())	
	    { System.out.println("SE_open error");return ;}	
	    SendAPDU(Admin);
	    SendAPDU(SetPSK);
	    SE_close();
				
		if (!server_open(port))
	    { System.out.println("Server error");return ;}
		
		
		while(true)
		{ 
		  if (!server_wait()) continue ;
		  if (!SE_open()) {client_close();continue;}
		  fopen=fclose=false;
		  flag=0;
		  SendAPDU(ResetTLS);
		
		 while(true)
		{ err = NetRecv();
		  if (err <=0) {client_close();break;}
		  
		  if (fopen) flag=(byte)1;
		  else       flag=(byte)0;
		  
		  err = SE_RECV(flag);
		  if (err<0) {client_close();break;}
		  
		  if (fopen)
		  { err = SE_RECV((byte)2);
			if (err<0) {client_close();break;}
		  }
		  
		  if      (err== 1) fopen=true;
		  else if (err== 2) fclose=true;
		  
		  if (ptrx !=0)
		  { err = NetSend();
		    if (err <=0) {client_close();break;}
		  }
		  
		  if (fclose){client_close();break;}
			  
		}
		 SE_close();
		}
		
		
	}
	
	 public static  boolean server_wait()
	  { 	
		System.out.println("Server Ready");
		try {client= soq.accept();
		     client.setSoTimeout(stimeout);
		     in  = new DataInputStream(client.getInputStream());
		     out = new DataOutputStream(client.getOutputStream());
		    }
	    catch(IOException e){client=null;return false;}

		return true;
	}
	
	
    public  static  boolean server_open(short port)
	{
	try
	{ soq = new ServerSocket(port,queue_size,InetAddress.getByName(myip)); 	}
	catch(IOException e){ soq=null;return false;}
    return true;
	
	}
	
	public static boolean server_close()
	 {  if (soq != null)
		 {
		 try { soq.close() ; }
		 catch(IOException e){return false;}
	     }

		 return true ;
     }
	
	 public static boolean client_close()
	 { if (client != null)
		 { try { client.close(); 
		         client = null;
		       }
		   catch(IOException e) {return false;}
		 }
		      
	     return true;
	   }
	 
	 public static int  NetRecv()
	  {   int nb=0,nr=0,offset=0,len=5 ;
	      ptrx=0;
	      
	
		 while(nr < len)
		 {  
			 try	{ nb = in.read(rx,offset,len-nr) ;
			  	      if (nb <= 0)  return(0) ; 
					  offset += nb ; nr +=  nb;
				    }
			   
					catch(IOException e) {return -1;}
		 }
		  
		 
	    len  = 0xFF00 & (rx[3] << 8);
	    len |= 0xFF & rx[4];
	    nr=0;
	    
	    if (len > RXSIZE)
	    	return -1;
		
		 while(nr < len)
		 {  
			 try	{ nb = in.read(rx,offset,len-nr) ;
			  	      if (nb <= 0)  return(0) ; 
					  offset += nb ; nr +=  nb;
				    }
			   
					catch(IOException e) { return -1;}
		 }
	    
		 ptrx=5+len;
		 System.out.println("RxNet: " + b2s(rx,0,ptrx));
		 return(ptrx);
	  }
	 

	 public static int NetSend() 
	 { System.out.println("TxNet: " + b2s(rx,0,ptrx));
	   try {out.write(rx,0,ptrx); }
	   catch(IOException e){return -1 ;}
	   return(ptrx);
	 }
	       
	 
     public static  CommandAPDU t2a(byte[] t)
	 { CommandAPDU a =null ;
	 if (t.length == 4)
	 { a = new CommandAPDU(0xFF & t[0],0xFF & t[1],0xFF & t[2],0xFF & t[3]);
	 }
	 else if (t.length == 5)
	 {   if (t[4] != 0)
		 a = new CommandAPDU(0xFF & t[0],0xFF & t[1],0xFF & t[2], 0xFF & t[3],0xFF & t[4]);
	     else
	     a = new CommandAPDU(0xFF & t[0],0xFF & t[1],0xFF & t[2], 0xFF & t[3], 256);
	 } 
	 else if (t.length > 5)
	 { byte b[] = new byte[t.length-5];
	   System.arraycopy(t,5,b,0,b.length);
	   a = new CommandAPDU(0xFF & t[0],0xFF & t[1],0xFF & t[2], 0xFF & t[3],b,256);
	 } 	 
		 return a;
	 } 
	 
final static char[] cnv  = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
public static  String b2s(byte[] value)
 {  String cline="" ;
    int i;
    char[] c= new char [2*value.length];

   for(i=0;i<value.length;i++)
   { c[2*i]    = cnv[(((int)value[i]) >> 4)&0xF]  ;
     c[2*i+1]  = cnv[((int)value[i]) & 0xF]       ;  
   }
  cline= String.copyValueOf(c,0,2*value.length) ;
  return(cline);
}

public static  String b2s(byte[] value, int off, int len)
{  String cline="" ;
   int i;
   char[] c= new char [2*len];

  for(i=0;i<len;i++)
  { c[2*i]    = cnv[(((int)value[off+i]) >> 4) & 0xF] ;
    c[2*i+1]  = cnv[((int)value[off+i]) & 0xF]      ;  
  }
 cline= String.copyValueOf(c,0,2*len) ;
 return(cline);
}



public static boolean SE_open()
{
	try {card = terminal.connect("*");}
	catch (CardException e) {return false;}
	
	atr = card.getATR() ;
	byte[] rep = atr.getBytes() ;
	System.out.println("ATR: " + b2s(rep));
			 
	channel = card.getBasicChannel();
	
	rep= SendAPDU(Select);
	if ( (rep != null) && (rep.length == 2) && (rep[0]==(byte)0x90) &&  (rep[1]==(byte)0x00) );
	else return false;
	
	rep= SendAPDU(User);
	if ( (rep != null) && (rep.length == 2) && (rep[0]==(byte)0x90) &&  (rep[1]==(byte)0x00) );
	else return false;
	
	
	return true;

}

public static boolean  SE_close()
{
	try { card.disconnect(false);}
	 catch (CardException e) {return false; }
	 return true;
}

     
public static boolean SE_init()
{
	factory = TerminalFactory.getDefault();
	cardterminals = factory.terminals()   ;
    
    List<CardTerminal> terminals;
	try { terminals = factory.terminals().list();} 
	catch (CardException e1) {return false;}
	// System.out.println("Terminals: " + terminals);
	// terminal = (CardTerminal)factory.terminals().getTerminal(ReaderName);
	
	int nb= terminals.size();
    for(int i=0;i<nb;i++)
	{ terminal = (CardTerminal) terminals.get(i);
	  String name = terminal.getName();
	  
    try {
	terminal.waitForCardPresent(100);
    if(terminal.isCardPresent()) 
      { System.out.println("SE inserted in "+ name);
        return true;
      }
    } catch (CardException e) {return false ;}
 
	}
    return false ;
	
}

public static byte[] SendAPDU(String req)
{
	return SendAPDU(a2b(req));
}


public static byte[] SendAPDU(byte[] req)
{
	 System.out.println("TxSE: " + b2s(req));
	 try {  r = channel.transmit(t2a(req)); }
	 catch (CardException e) {return null;}
	 byte[] rep = r.getBytes();
	 if (rep == null) return null;
	 System.out.println("RxSE: " + b2s(rep));
	 
	 if ( (rep.length==5) && (rep[0] == (byte)0x61) )
	 { More[4]= rep[1]; 
	   return SendAPDU(More);
	 }
	 
	 if ( (rep.length==5) && (rep[0] == (byte)0x6C) )
	 {req[4] = rep[1]; 
	  return SendAPDU(req);
	 }
	 
	return rep;
	
}

public static int SE_RECV(byte flag)
{ byte[] bufrx = null;
	 int remain= ptrx,len,pt=0;
	 boolean cfirst=true;

	
	  while(remain >0)
	 { if (remain >= 240) { len=240   ;bufrx=new byte[5+len];bufrx[3]=0;bufrx[2]=0;}
	   else               { len=remain;bufrx=new byte[5+len];bufrx[3]=2;bufrx[2]=flag;}
	   
	   if (cfirst){bufrx[3] |= 1; cfirst=false;}
	   bufrx[0]= 0;
	   bufrx[1]= (byte)0xD8;
	   bufrx[4]= (byte)(0xFF & len) ;
		 	   
	   System.arraycopy(rx,pt,bufrx,5,len);
	   remain -= len;
	   pt+=len;
	   
	   bufrx = SendAPDU(bufrx);
	   
	   if (bufrx == null)    return -1;
	   if (bufrx.length < 2) return -1;
	   
	   if ((bufrx.length != 2) && (remain !=0))
	   return -1;

	   if (bufrx.length > 2)  break ;
	   else 
	   { 
	   if(remain == 0) 
	   {ptrx=0;
	    if      ((bufrx[0]==(byte)0x90) && (bufrx[1]==(byte)0x00)) return 0;
	    else if ((bufrx[0]==(byte)0x90) && (bufrx[1]==(byte)0x01)) return 1;
	    else if ((bufrx[0]==(byte)0x90) && (bufrx[1]==(byte)0x02)) return 2;
	    else return -1;
	   }
	   else
	   { if ((bufrx[0]==(byte)0x90) && (bufrx[1]==(byte)0x00)) ;
	     else return -1;
	   }
	   }
	 }

	 pt=0;
	 while (true)
	 { 
	   if (bufrx.length != 2)
	   {  if ((pt+bufrx.length-2) > RXSIZE) return -1;
	      System.arraycopy(bufrx,0,rx,pt,bufrx.length-2);
	   }
	   pt += (bufrx.length-2);
	   ptrx=pt;
		   
	   if      ((bufrx[bufrx.length-2]==(byte)0x90) && (bufrx[bufrx.length-1]==(byte)0x00)) return 0;
	   else if ((bufrx[bufrx.length-2]==(byte)0x90) && (bufrx[bufrx.length-1]==(byte)0x01)) return 1;
	   else if ((bufrx[bufrx.length-2]==(byte)0x90) && (bufrx[bufrx.length-1]==(byte)0x02)) return 2;
	   else if ((bufrx[bufrx.length-2]==(byte)0x61) || (bufrx[bufrx.length-2]==(byte)0x9F))
	   len = 0xFF & bufrx[bufrx.length-1];
	   else return -1;
	   
 	   More[4]= (byte) (0xFF & len);
	   
	   bufrx= SendAPDU(More);
	   if (bufrx == null)    return -1;
	   if (bufrx.length < 2) return -1;
	   }
		 
	}

public static byte[] a2b(String sdata_in)
{  	int deb=-1,fin=-1,i,j=0,iCt=0,len;
    int  v ;
	char[] data_in ;
    byte [] data_out = new byte[1+sdata_in.length()/2] ;
	
						 
	data_in = sdata_in.toCharArray() ;
	len     = data_in.length         ;

	for(i=0;i<len;i++)
	{ if      ( (deb == -1) && (toDigit(data_in[i])!= -1) )            {iCt=1;deb=i;}
      else if ( (deb != -1) && (iCt==1) && (toDigit(data_in[i])!=-1) ) {iCt=2;fin=i;}

      if (iCt == 2)
	  { v  = toDigit(data_in[deb]) << 4;
		v |= toDigit(data_in[fin])     ;
		
	    data_out[j++]= (byte) v ;
		deb=fin=-1;iCt=0;
	   }
    }
	
    byte []out = new byte [j];
    for(i=0;i<j;i++) out[i]=data_out[i] ;
	
return(out);
}


public static int toDigit(char c)
{ if (((int)c >= (int)'0') && ((int)c<= (int)'9')) return((int)c-(int)'0') ;
  if (((int)c >= (int)'A') && ((int)c<= (int)'F')) return(10+(int)c-(int)'A') ;
  if (((int)c >= (int)'a') && ((int)c<= (int)'f')) return (10+(int)c-(int)'a');
  return(-1);
}


}

