<?php
/**
*  Copyright I-2019 denobisipsis

# AES SIV, CMAC & PMAC

Non Misuse Resistant cipher

aes_cmac  https://tools.ietf.org/html/rfc4493
aes_pmac  http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-bak.htm
AES-SIV   https://tools.ietf.org/html/rfc5297

# USAGE 

$x = new NMR;

$x->aes_cmac($data, $key);

$x->aes_pmac($data, $key);


$x->aes_siv_encrypt($Key,$Sn,$plaintext) 
$x->aes_siv_decrypt($Key,$Sn,$cipher) 

[$Sn is an array of additional data (for example AAD or nonce)]

# TEST VECTORS

$x->test_cmac();
$x->test_pmac();
$x->test_aes_siv();
	
# License

This code is placed in the public domain.
*/
	
class NMR
{
/** aes_cmac  https://tools.ietf.org/html/rfc4493 */

    private function genKeyscmac($key) 
    	{ 
        $keys      = array();		
	$sX	   = strlen($key)/16;		
        $text      = str_repeat("\0", 16);	
        $lVal      = openssl_encrypt($text, 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);					
	/**
	dbl(S)
	      is the multiplication of S and 0...010 in the finite field
	      represented using the primitive polynomial
	      x^128 + x^7 + x^2 + x + 1. 
	*/					
	$Uints     = unpack('J*',$lVal);
	$s	   = sizeof($Uints);
	$lH 	   = $lL = 0;						
	$lH 	  ^= $Uints[$s-1];
	$lL 	  ^= $Uints[$s];		

	$xLSB 	   = $lH;	 				
	$lH   	   = ($lL >> 63)& PHP_INT_MAX|$lH << 1;
	$lL      <<= 1;
	if ($xLSB & 0x8000000000000000)
		$lL 	^= 0x0000000000000087;			
	$keys[0]   = pack('J',$lH).pack('J',$lL);
	
	$xLSB 	   = $lH;	 				
	$lH   	   = ($lL >> 63)& PHP_INT_MAX|$lH << 1;
	$lL      <<= 1;
	if ($xLSB & 0x8000000000000000)
		$lL 	^= 0x0000000000000087;
	
	$keys[1]   = pack('J',$lH).pack('J',$lL);
        return $keys;
    	}
    private function padBlocks($data, $key) 
    	{
	$keys      = $this->genKeyscmac($key);
        $data      = str_split($data, 16);	
        $last      = end($data);	
        if (strlen($last) != 16) 
		{
            	$last .= chr(0x80) . str_repeat(chr(0), 15-strlen($last));
            	$last  = $last ^ $keys[1];
        	} 
	else 	$last  = $last ^ $keys[0] ;
        
        $data[count($data) - 1] = $last;
        return $data;
    	}
    public function aes_cmac($data, $key) 
   	{  	 	
        $M	   = $this->padBlocks($data, $key);	
        $MAC       = str_repeat("\0", 16);	
	$sX	   = strlen($key)/16;
        foreach ($M as $Block) 
		$MAC  =   openssl_encrypt($Block ^ $MAC , 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);	
        return bin2hex($MAC);
    	}

/** aes_pmac http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-bak.htm */

   private function dbl_pmac($L0,$n)
   	{
	/**
	dbl(S)
	      is the multiplication of S and 0...010 in the finite field
	      represented using the primitive polynomial
	      x^128 + x^7 + x^2 + x + 1. 
	*/

	$ks  	   = array();	
	$X	   = array_values(unpack('L*',strrev($L0)));
			
	for ($k=0;$k<$n;$k++)
		{		
		$lsb=$X[3];
	        $X[3]<<=1;							
	        for($j=1;$j<4;$j++)
	            {			
	            if ($X[3-$j] & 0x80000000)					    	 
			    $X[4-$j] |= 1;
	            $X[3-$j]<<=1;          
	            }
		if ($lsb & 0x80000000)
			$X[0]^=0x00000087;

		$Z="";foreach ($X as $z) $Z.=pack("L",$z);			
		$ks[$k] =  strrev($Z);
		}
		
	return $ks;	
	}
	
    public function aes_pmac($data, $key) 
   	{ 
	/**
	Break the message M into m=1 blocks M[1]M[2]...M[m] where each block except the last one has 128 bits. 
	The last one may have fewer than 128 bits. Now we MAC as follows.
		    
	    function pmac (K, M)
	    begin
	        Offset = ZERO
	        S = ZERO
	        for i = 1 to m-1 do begin
	            Offset = Offset xor L(ntz(i))
	            S = S xor AES(K, Offset xor M[i])
	        end
	        S = S xor pad(M[m])
	        if |M[m]|=n then S = S xor L(-1)
	        FullTag = AES(K, S)
	        return a prefix of FullTag (of the desired length)
	    end	
	*/
	 
        $M       = str_split($data, 16);
        $Sigma   = $Offset  = str_repeat(chr(0), 16);	
	$sX	 = strlen($key)/16;

	$L	 = array();			
	$L[0]    = openssl_encrypt($Sigma , 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);
        $L 	 = array_merge($L, $this->dbl_pmac($L[0],sizeof($M)-1));
							
        for ($m=0;$m<sizeof($M)-1;$m++)
		{
		/**
		For a nonzero number i, let ntz(i) be the number of trailing 0-bits in the binary representation of i 
		(so, for example, ntz(52)=2, because 52 is 110100 in binary, which ends in two zeros). 
		*/
		$ntz	 = strpos(strrev(decbin($m+1)),"1");
		$Offset ^= $L[$ntz];		
		$Sigma  ^= openssl_encrypt($Offset ^ $M[$m], 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);
		}

	$s=strlen($M[$m]);		
	if ($s==16)
		{ 	
		$Sigma  ^= $M[$m]; 

		/** Let L(-1) be L>>1 if the last bit of L is 0, 
		    and 
		    let L(-1) be L>>1 xor 0x80000000000000000000000000000043 otherwise */
		
		$Uints   = unpack('J*',$L[0]);														
		$s2	 = sizeof($Uints);
		$lH 	 = $lL = 0;						
		$lH 	^= $Uints[$s2-1];
		$lL 	^= $Uints[$s2];		
	
		$xLSB 	 = $lL;	 				
		$lL   	 = ($lH << 63)|($lL >> 1)& PHP_INT_MAX;
		$lH      = ($lH >> 1)& PHP_INT_MAX;
		if ($xLSB & 1)
			{
			$lH	^= 0x8000000000000000;
			$lL 	^= 0x0000000000000043;
			}

		/** if |M[m]|=n then S = S xor L(-1) */
		$Sigma^=pack('J',$lH).pack('J',$lL);
		}
	else
		{
		/** S = S xor pad(M[m]) */
		$mod=$s%16;			
		$M[$m] .= chr(0x80) . str_repeat(chr(0), 15-$mod);
		$Sigma ^= $M[$m];
		}

	$FullTag = openssl_encrypt($Sigma, 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);
        return bin2hex($FullTag);		
    	}

/** AES-SIV, as described in RFC 5297.
 To meet the security requirements of DeterministicAead, this cipher can only be used with 256-bit keys. */
	 
   private function dbl_siv($k)
   	{
	/**
	dbl(S)
	      is the multiplication of S and 0...010 in the finite field
	      represented using the primitive polynomial
	      x^128 + x^7 + x^2 + x + 1. 
	*/	
	$X   	= array_values(unpack('L*',strrev(substr($k,0,16))));					
	$lsb	=$X[3];
        $X[3] <<=1;							
        for($j=3;$j>0;$j--)
            {			
            if ($X[$j-1] & 0x80000000)					    	 
		    $X[$j] |= 1;
            $X[$j-1] <<=1;          
            }
	if ($lsb & 0x80000000)
		$X[0] ^=0x00000087;
	
	$Z="";foreach ($X as $z) $Z.=pack("L",$z);		
	return  strrev($Z);	
	}
    private function generateKeys_siv($key) 
    	{ 
        $keys      = array();		
	$sX	   = strlen($key)/16;
	$key	   = substr($key,0,$sX*8);
        $text      = str_repeat("\0", 16);
	
        $lVal      = openssl_encrypt($text, 'aes-'.($sX*64).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);					
	$keys[0]   = $this->dbl_siv($lVal);		
	$keys[1]   = $this->dbl_siv($keys[0]);

        return $keys;
    	}
    		    
    private function Blocks($data, $keys) 
    	{
        $data      = str_split($data, 16);	
        $last      = end($data);
	
        if (strlen($last) != 16) 		
            	$last   = $this->pad($last) ^ $keys[1];      	
	else 	$last   = $last             ^ $keys[0] ;
        
        $data[count($data) - 1] = $last;
        return $data;
    	}
   private function cmac_siv($data, $key) 
   	{  	 	
        $keys    = $this->generateKeys_siv($key);
        $Blocks  = $this->Blocks($data, $keys);	
        $cBlock  = str_repeat("\0", 16);	
	$sX	 = strlen($key)/16;			
	$key	 = substr($key,0,$sX*8);	
        foreach ($Blocks as $block) 
		$cBlock = openssl_encrypt($block ^ $cBlock, 'aes-'.($sX*64).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);	
        return $cBlock;
    	}
    private function xorend($a,$b)
    	{
	$gap	= strlen($a)-strlen($b);
	$i	= substr($a,0,$gap);  
	$j	= substr($a,$gap)^$b;
	return $i.$j;  
	}  
    private function pad($a)
    	{
	$s = strlen($a);
	$mod=$s%16;				
	if ($mod or $s==0) 
		$a.=chr(0x80) . str_repeat("\0",15-$s);				
	return $a;
	}
    private function S2V($K,$S="",$P="")
    	{
	/** S2V with key k on a vector of n inputs S1, S2, ..., Sn-1, Sn, and
	   len(Sn) >= 128: Sn is msg*/
	   
        $D = $this->cmac_siv(str_repeat("\0", 16),$K);
		   
	foreach ($S as $s)
		$D  = $this->dbl_siv($D) ^ $this->cmac_siv(pack("H*",$s),$K);
			
	if (strlen($P)>=16)
		$T  = $this->xorend($P,$D);
	else    $T  = $this->dbl_siv($D) ^ $this->pad($P);
	
	$T = $this->cmac_siv($T,$K);
	
	return $T;	    
	}
	
    public function aes_siv_decrypt($K,$Z="",$S="") 
        {
	$Z	= pack("H*",$Z);
	$V 	= substr($Z,0,16);
	$C 	= substr($Z,16);
	$sX     = strlen($K)/16;
	$K2     = substr($K,$sX*8);
	
	$Q	= $V & pack("H*","ffffffffffffffff7fffffff7fffffff");	

	$addition  = '32b';
	
	if      ($addition=='32b')
		{$n=4;$pack="N";}
	else if ($addition=='64b')
		{$n=8;$pack="L";}
	
	$Sn     = str_split($C,16);	
	$P	= "";
	foreach ($Sn as $m)
		{
		$P   .= openssl_encrypt($Q, 'aes-'.($sX*64).'-ecb', $K2, 1|OPENSSL_ZERO_PADDING) ^ $m ;
		$SALT = substr($Q,0,16-$n);
		extract(unpack($pack."count",substr($Q,-$n)));	
		$Q    = $SALT.pack($pack, $count+1);
		}
	
	$T 	= $this->S2V($K,$S,$P);
	
	if ($T==$V) return bin2hex($P);
	else	    die("Fail");
      }
      
    public function aes_siv_encrypt($K,$Sn="",$S="") 
        {
	if (strlen($K)<32) die("To meet the security requirements of DeterministicAead, this cipher can only be used with 256-bit keys");
	
	/** cmac final = SIV or initial counter */
	
	$cmac_final = $V = $this->S2V($K,$S,$Sn);
	
	/**
	The 31st and 63rd bit (where the rightmost bit is the 0th) of the
	   counter are zeroed out just prior to being used in CTR mode for
	   optimization purposes
	*/	

	$Q = $V & pack("H*","ffffffffffffffff7fffffff7fffffff");
		
	/** 
	More formally, 
	
	   For 32 bit addition the counter is incremented as:
	
              SALT=leftmost(X,96)

              n=rightmost(X,32)

              X+i = SALT || (n + i mod 2^32).
	
	   For 64 bit addition the counter is incremented as:
	
              SALT=leftmost(X,64)

              n=rightmost(X,64)

              X+i = SALT || (n + i mod 2^64).
	*/
	
	$addition  = '32b';
	
	if      ($addition=='32b')
		{$n=4;$pack="N";}
	else if ($addition=='64b')
		{$n=8;$pack="L";}
	
	$sX	   = strlen($K)/16;
	$key	   = substr($K,$sX*8);	
	$Sn	   = str_split($Sn,16);	
	$ctr="";
	foreach ($Sn as $m)
		{
		$ctr .= openssl_encrypt($Q, 'aes-'.($sX*64).'-ecb', $key, 1|OPENSSL_ZERO_PADDING) ^ $m ;
		$SALT = substr($Q,0,16-$n);
		extract(unpack($pack."count",substr($Q,-$n)));	
		$Q    = $SALT.pack($pack, $count+1);
		}
	return bin2hex($cmac_final.$ctr);
      }
      
    public function test_cmac()
    	{
	echo "CMAC TEST VECTORS https://raw.githubusercontent.com/miscreant/miscreant.js/master/vectors/aes_cmac.tjson\n\n";
	$testvectors=json_Decode(file_get_contents("https://raw.githubusercontent.com/miscreant/miscreant.js/master/vectors/aes_cmac.tjson"));
	foreach ($testvectors->{"examples:A<O>"} as $test)
		{
		echo "Valid 		".$test->{"tag:d16"}."\n"; 
		echo "Computed 	".$this->aes_cmac(pack("H*",$test->{"message:d16"}),pack("H*",$test->{"key:d16"}))."\n\n";
		}	    
	}
    public function test_pmac()
    	{
	echo "PMAC TEST VECTORS https://raw.githubusercontent.com/miscreant/miscreant.js/master/vectors/aes_pmac.tjson\n\n";
	$testvectors=json_Decode(file_get_contents("https://raw.githubusercontent.com/miscreant/miscreant.js/master/vectors/aes_pmac.tjson"));
	foreach ($testvectors->{"examples:A<O>"} as $test)
		{
		$name=$test->{"name:s"};
		$key=pack("H*",$test->{"key:d16"});
		$msg=pack("H*",$test->{"message:d16"});
		echo "Valid 		".$test->{"tag:d16"}."\n"; 
		echo "Computed 	".$this->aes_pmac($msg,$key)."\n\n";			
		}	    
	}
    public function test_aes_siv()
    	{
	echo "AES SIV TEST VECTORS https://raw.githubusercontent.com/miscreant/miscreant.js/master/vectors/aes_siv.tjson\n\n";
	$testvectors=json_Decode(file_get_contents("https://raw.githubusercontent.com/miscreant/miscreant.js/master/vectors/aes_siv.tjson"));
	foreach ($testvectors->{"examples:A<O>"} as $test)
		{
		$key=pack("H*",$test->{"key:d16"});
		$aad=pack("H*",@($test->{"ad:A<d16>"}[0]));
		$ad2=pack("H*",@($test->{"ad:A<d16>"}[1]));
		$nonce=pack("H*",@($test->{"ad:A<d16>"}[2]));
		$msg=pack("H*",$test->{"plaintext:d16"});
		
		echo "Valid 		".$test->{"ciphertext:d16"}."\n";
		echo "Computed 	".($cipher=$this->aes_siv_encrypt($key,$msg,$test->{"ad:A<d16>"}))."\n";
		echo "Decrypted	".$this->aes_siv_decrypt($key,$cipher,$test->{"ad:A<d16>"})."\n\n";
		}	    
	}
}

$x = new NMR;
$x->test_cmac();
$x->test_pmac();
$x->test_aes_siv();