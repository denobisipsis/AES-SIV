<?php
/**
*  Copyright I-2019 denobisipsis

# AES SIV, CMAC & PMAC, AES EAX, OMAC-2

Non Misuse Resistant cipher

AES_CMAC  https://tools.ietf.org/html/rfc4493
AES_PMAC  http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-bak.htm
AES-SIV   https://tools.ietf.org/html/rfc5297
AES_EAX   http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
OMAC-2    http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html

# USAGE 

$x = new NMR;

$x->aes_cmac($data, $key);

$x->aes_pmac($data, $key);

$x->OMAC2($data, $key);

$x->aes_siv_encrypt($Key,$Sn,$plaintext) 
$x->aes_siv_decrypt($Key,$Sn,$cipher) 

[$Sn is an array of additional data (for example AAD or nonce)]

$x->aes_eax_encrypt($Message,$Key,$Nonce,$Header) 
$x->aes_eax_decrypt($Cipher,$Key,$Nonce,$Header) 

# TEST VECTORS

$x->test_cmac();
$x->test_pmac();
$x->test_OMAC2();
$x->test_aes_siv();
$x->test_aes_eax();
	
# License

This code is placed in the public domain.
*/
	
class NMR
{
/** aes_cmac  https://tools.ietf.org/html/rfc4493 */

   private function double($X)
   	{
	/**
	dbl(S)
	      is the multiplication of S and 0...010 in the finite field
	      represented using the primitive polynomial
	      x^128 + x^7 + x^2 + x + 1. 
	*/
	
	$s	 = sizeof($X)-1;
	
	if ($s==3) $R=0x00000087;
	else	   $R=0x001b;

	$lsb     =$X[$s];
        $X[$s] <<=1;							
        for($j=$s;$j>0;$j--)
            {			
            if ($X[$j-1] & 0x80000000)					    	 
		    $X[$j] |= 1;
            $X[$j-1] <<=1;          
            }
	if ($lsb & 0x80000000)
		$X[0] ^=$R;
	return $X;	   
	}
	
   private function dbl_siv($k)
   	{	
	$X   	= array_values(unpack('L*',strrev($k)));						
	$X 	= $this->double($X);	
	$Z="";foreach ($X as $z) $Z.=pack("L",$z);		
	return  strrev($Z);	
	} 

    private function generateKeys($sX,$key, $omac2)
    	{
        $text      = str_repeat("\0", 16);	
        $lVal      = openssl_encrypt($text, 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);					
	$Uints     = array_values(unpack('L*',strrev($lVal)));	
	$temp	   = $this->double($Uints);	
	$k0="";foreach ($temp as $z) $k0.=pack("L",$z);	
	
	if ($omac2)
		return array(strrev($k0),$this->L_1($lVal)); // L.u and L.u 2  
		
	$k1="";foreach ($this->double($temp) as $z) $k1.=pack("L",$z);	
        return array(strrev($k0),strrev($k1));	        
	}

    private function MAC($data,$key,$sX, $omac2=0)
    	{
        $Blocks  = $this->Blocks($data, $this->generateKeys($sX,$key,$omac2));	
        $MAC  	 = str_repeat("\0", 16);	
						
        foreach ($Blocks as $block) 
		$MAC = openssl_encrypt($block ^ $MAC, 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);	
		
	return $MAC;    
	}
		
    public function aes_cmac($data, $key) 
   	{  
	$sX	   = strlen($key)/16;	 		
        return bin2hex($this->MAC($data,$key,$sX));
    	}
	    
   private function siv_cmac($data, $key)
   	{  
	$sX	 = strlen($key)/16;
	$key	 = substr($key,0,$sX*8);	 		
        return $this->MAC($data,$key,$sX/2);
    	}

    private function pad($a)
    	{
	$s = strlen($a);
	$mod=$s%16;				
	if ($mod or $s==0) 
		$a.=chr(0x80) . str_repeat("\0",15-$mod);				
	return $a;
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
	
   private function genL($key,$n)
   	{
	/**
	Compute all $n-1 pmac L 
	*/
	
	$ks  	   = array();
	$sX	   = strlen($key)/16;
	$ks[]      = openssl_encrypt(str_repeat(chr(0), 16) , 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);		
	$X	   = array_values(unpack('L*',strrev($ks[0])));			
	for ($k=1;$k<$n;$k++)
		{		
		$X    = $this->double($X);
		$Z="";foreach ($X as $z) $Z.=pack("L",$z);			
		$ks[] =  strrev($Z);
		}	
        return $ks;
	}
    
    private function L_1($k)
    	{
	/** 
	    Let L(-1) be L>>1 if the last bit of L is 0, 
	    and 
	    let L(-1) be L>>1 xor 0x80000000000000000000000000000043 otherwise 
	*/
		
	$Uints   = unpack('J*',$k);													
	$s2	 = sizeof($Uints);
	$lH 	 = $lL = 0;						
	$lH 	^= $Uints[$s2-1];
	$lL 	^= $Uints[$s2];		

	$xLSB 	 = $lL;	 				
	$lL   	 = ($lH << 63)|($lL >> 1)& PHP_INT_MAX;
	$lH      = ($lH >> 1)		 & PHP_INT_MAX;
	if ($xLSB & 1)
		{
		$lH	^= 0x8000000000000000;
		$lL 	^= 0x0000000000000043;
		}
	
	return pack('J',$lH).pack('J',$lL);	    
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
		
	$L       = $this->genL($key,sizeof($M));
							
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
	
	$Sigma  ^= $this->pad($M[$m]); 
		
	if (strlen($M[$m])==16)		
		/** 
		    if |M[m]|=n then S = S xor L(-1)
		*/		
		$Sigma  ^= $this->L_1($L[0]);
		
	$FullTag = openssl_encrypt($Sigma, 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING);
        return bin2hex($FullTag);		
    	} 	    

 
    public function OMAC2($data,$key)
    	{
	$sX	 = strlen($key)/16;	
	return bin2hex($this->MAC($data,$key,$sX,1));   	    
	}
	
   private function OMAC($data,$key,$n)
    	{
	// EAX CMAC data tunning  	    
	return pack("H*",$this->aes_cmac(str_repeat("\0", 15).chr($n).$data,$key)); 
	}

    private function counter_inc($addition,$COUNTER)
    	{
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
	if      ($addition=='32b')
		{$n=4;$pack="N";}
	else if ($addition=='64b')
		{$n=8;$pack="J";}

	$SALT = substr($COUNTER,0,16-$n);			
	extract(unpack($pack."count",substr($COUNTER,-$n)));	
	return $SALT.pack($pack, $count+1);	    
	}

    public function ctr($M,$COUNTER,$sX,$key)
    	{
	$M     	   = str_split($M,16);
	$cipher    = "";
	for ($k=0;$k<sizeof($M);$k++)
		{
		$cipher  .= openssl_encrypt($COUNTER, 'aes-'.($sX*128).'-ecb', $key, 1|OPENSSL_ZERO_PADDING) ^ $M[$k];			
		$COUNTER  = $this->counter_inc('32b',$COUNTER);
		}
	return $cipher;	    
	}
		
    public function aes_eax_decrypt($cipher,$key,$nonce,$header)
    	{
	/** http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf */
	
	// Tau = 16. This can be changed
	
	if (strlen($cipher)<16) die('Invalid');
	
	$ETag	   = substr($cipher,-16);
	$cipher	   = substr($cipher,0,strlen($cipher)-16);
		
	$sX    	   = strlen($key)/16;
	
	$MAC_NONCE = $this->OMAC($nonce,$key,0);
	$MAC_H     = $this->OMAC($header,$key,1);	
	$MAC_C 	   = $this->OMAC($cipher,$key,2);
	
	$Tag 	   = substr($MAC_NONCE ^ $MAC_H ^ $MAC_C,0,16);
	
	if ($Tag!=$ETag) die('Invalid');		
	
	return bin2hex($this->ctr($cipher,$MAC_NONCE,$sX,$key));	
	}
		
    public function aes_eax_encrypt($data,$key,$nonce,$header)
    	{
	/** http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf */
	$sX    	   = strlen($key)/16;
	
	$MAC_NONCE = $this->OMAC($nonce,$key,0);
	$MAC_H     = $this->OMAC($header,$key,1);	

	$cipher    = $this->ctr($data,$MAC_NONCE,$sX,$key);		
	
	$MAC_C 	   = $this->OMAC($cipher ,$key , 2);				
	$Tag 	   = $MAC_NONCE ^ $MAC_H ^ $MAC_C;	
	
	return bin2hex($cipher.$Tag);	
	}
	
    private function xorend($a,$b)
    	{
	$gap	= strlen($a)-strlen($b);
	$i	= substr($a,0,$gap);  
	$j	= substr($a,$gap)^$b;
	return $i.$j;  
	}  

    private function S2V($K,$S="",$P="")
    	{
	/** S2V with key k on a vector of n inputs S1, S2, ..., Sn-1, Sn, and
	   len(Sn) >= 128: Sn is msg*/
	   
        $D = $this->siv_cmac(str_repeat("\0", 16),$K);
		   
	foreach ($S as $s)
		$D  = $this->dbl_siv($D) ^ $this->siv_cmac(pack("H*",$s),$K);
			
	if (strlen($P)>=16)
		$T  = $this->xorend($P,$D);
	else    $T  = $this->dbl_siv($D) ^ $this->pad($P);
	
	$T = $this->siv_cmac($T,$K);
	
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
	$P	= $this->ctr($C,$Q,$sX/2,$K);	
	$T 	= $this->S2V($K,$S,$P);
	
	if ($T==$V) return bin2hex($P);
	else	    die("Fail");
      }
      
    public function aes_siv_encrypt($K,$Sn="",$S="") 
        {
	if (strlen($K)<32) 
		die("To meet the security requirements of DeterministicAead, this cipher can only be used with 256-bit keys");
	
	/** cmac final = SIV or initial counter */
	
	$cmac_final = $this->S2V($K,$S,$Sn);
	
	/**
	The 31st and 63rd bit (where the rightmost bit is the 0th) of the
	   counter are zeroed out just prior to being used in CTR mode for
	   optimization purposes
	*/	

	$Q = $cmac_final & pack("H*","ffffffffffffffff7fffffff7fffffff");
	
	$sX	   = strlen($K)/16;
	$key	   = substr($K,$sX*8);		
	$ctr	   = $this->ctr($Sn,$Q,$sX/2,$K);

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
    public function test_omac2()
    	{
	echo "OMAC2 TEST VECTORS http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/tv/omac2-tv.txt\n\n";
	$testvectors=json_Decode(file_get_contents("https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/omac2_test_vectors.json"));
	foreach ($testvectors->OMAC2_VECTORS as $test)
		{
		echo "Valid 		".$test->tag."\n"; 
		echo "Computed 	".$this->OMAC2(pack("H*",$test->msg),pack("H*",$test->key))."\n\n";
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
    public function test_aes_eax()
    	{
	echo "AES EAX TEST VECTORS http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf\n\n";
	$testvectors=json_Decode(file_get_contents("https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/aes_eax_test_vectors.json"));
	foreach ($testvectors->EAX_VECTORS as $test)
		{
		$key=pack("H*",$test->key);
		$header=pack("H*",$test->header);
		$nonce=pack("H*",$test->nonce);
		$msg=pack("H*",$test->msg);
		
		echo "Valid 		".strtolower($test->ct)."\n";
		echo "Computed 	".($cipher=$this->aes_eax_encrypt($msg,$key,$nonce,$header))."\n";
		echo "Decrypted	".$this->aes_eax_decrypt(pack("H*",$cipher),$key,$nonce,$header)."\n\n";
		}	    
	}
}

$x = new NMR;

$x->test_cmac();
$x->test_pmac();
$x->test_OMAC2();
$x->test_aes_siv();
$x->test_aes_eax();

