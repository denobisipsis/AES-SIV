<?php
/**
*  Copyright I-2019 denobisipsis

# AES SIV, CMAC & PMAC, AES EAX, OMAC-2, VMAC

Non Misuse Resistant cipher

AES_CMAC  https://tools.ietf.org/html/rfc4493
AES_PMAC  http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-bak.htm
AES-SIV   https://tools.ietf.org/html/rfc5297
AES_EAX   http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
OMAC-2    http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
VMAC	  https://tools.ietf.org/html/draft-krovetz-vmac-01

# USAGE 

$x = new NMR;

$x->aes_cmac($data, $key);

$x->aes_pmac($data, $key);

$x->OMAC2($data, $key);

$x->vmac($key, $m, $nonce, $taglen);

$x->aes_siv_encrypt($Key,$Sn,$plaintext) 
$x->aes_siv_decrypt($Key,$Sn,$cipher) 

[$Sn is an array of additional data (for example AAD or nonce)]

$x->aes_eax_encrypt($Message,$Key,$Nonce,$Header) 
$x->aes_eax_decrypt($Cipher,$Key,$Nonce,$Header) 

# TEST VECTORS

$x->test_cmac();
$x->test_pmac();
$x->test_OMAC2();
$x->test_vmac();
$x->test_aes_siv();
$x->test_aes_eax();
	
# License

This code is placed in the public domain.
*/
	
class NMR
{
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
	$P	= $this->ctr($C,$Q,$sX/2,$K2);	
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
	$ctr	   = $this->ctr($Sn,$Q,$sX/2,$key);

	return bin2hex($cmac_final.$ctr);
      }


	/* 
	VMAC
	based on 
	http://www.fastcrypto.org/vmac/vmac.txt  
	https://tools.ietf.org/html/draft-krovetz-vmac-01 */  

	var $BLOCKLEN,$KEYLEN,$L1KEYLEN,$M64,$M126,$MP,$P64,$PP,$P127,$hbin,$h2bin,$pow2_64, $taglen;

	function __construct()
		{
		$this->pow2_64  = bcpow(2,64);
					
		$this->BLOCKLEN = 128;    # block-length 
		$this->KEYLEN   = 128;    # key-length
		$this->L1KEYLEN = 1024;   # bits used for l1_hash (compression)
		
		$this->M64  = $this->big("FFFFFFFFFFFFFFFF"); 
		$this->M126 = $this->big("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
		$this->MP   = $this->big("1FFFFFFF1FFFFFFF1FFFFFFF1FFFFFFF");    # Mask for creating poly key
		$this->P64  = $this->big("FFFFFFFFFFFFFEFF");                    # 2^64 - 257
		$this->PP   = $this->big("FFFFFFFF00000000");                 	 # 2^64 - 2^32
		$this->P127 = $this->big("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");    # 2^127 - 1
		}	
	
	private function big($hex)
	 	{
	     	$dec = 0;
	     	$len = strlen($hex);
	     	for ($i = 1; $i <= $len; $i++)
	         	$dec = bcadd($dec, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));	
	     	return $dec;
	 	}
		 
	private function kdf($key, $index, $numbits) 
		{
		/** The key-derivation function generates pseudorandom bits used by the
		   hash function. */
	              
		$n 	= ceil(($numbits+$this->BLOCKLEN-1)/$this->BLOCKLEN); 
		$prefix = chr($index).str_repeat(chr(0),14);
		
		$Y = ""; 
		for ($i=0;$i<$n;$i++)
			$Y .=openssl_encrypt($prefix.chr($i), 'aes-128-ecb', $key, 1|OPENSSL_ZERO_PADDING);
				
		return substr($Y,0,$numbits/8);
		}
	
	private function pdf($key, $nonce, $taglen)
		{
		/** This function takes a key and a nonce and returns a pseudorandom pad
		   for use in tag generation.  The length of the pad can be any positive
		   multiple of 64 bits, up to BLOCKLEN bits.*/	
		$tagsperblock 	= $this->BLOCKLEN/$taglen;
		$mask 		= $tagsperblock-1;  
		$index 		= ord(substr($nonce,-1)) & $mask;
	
		$tmpnonce = str_repeat(chr(0),$this->BLOCKLEN/8-strlen($nonce)).substr($nonce,0,-1).chr(ord(substr($nonce,-1))-$index);	
		$tmpblock = openssl_encrypt($tmpnonce, 'aes-128-ecb', $key, 1|OPENSSL_ZERO_PADDING);
		
		return substr($tmpblock,$index*($taglen/8),$taglen/8);
		}

	private function nh($key, $m)
		{
		$m = array_values(unpack("Q*",$m));
	
		$y = 0;
		for ($i=0;$i<sizeof($m);$i+=2)
			{				
			$k3 = gmp_add($key[$i],$m[$i]);
			$k4 = gmp_add($key[$i+1],$m[$i+1]);			
			$k5 = gmp_mul(gmp_and($k3,$this->M64) , gmp_and($k4,$this->M64));
			$y  = gmp_add($y , $k5);
			}
			
		return gmp_and($y , $this->M126);  
		}
	
	private function l1_hash($key, $m, $iter)
		{
		/** The first-layer hash breaks the message into blocks, each of length
		   up to L1KEYLEN (normally defined as 1024 bits), and hashes each with
		   a function called NH.  Concatenating the results forms a string which
		   is shorter than the original (unless the original length was no
		   greater than 128 bits).*/
		# Max number of bytes per NH hash
		$bytesblock     = $this->L1KEYLEN/8; 
	
		$tmpk 	        = substr($this->kdf($key, 128, $this->L1KEYLEN+128*$iter),-$bytesblock); 
		$tmpk 	        = array_values(unpack("J*",$tmpk));
	 	
		$m = str_split($m,$bytesblock);
	
		$y = array();                              
		for  ($i=0;$i<sizeof($m)-1;$i++)                   			
			{$y[] 	= $this->nh($tmpk,$m[$i]);}	
		
		$s 	= strlen($m[$i])*8;
		$mod	= $s % $bytesblock;				
		if ($mod) 
			$m[$i] .= str_repeat("\0",($bytesblock-$mod)/8);    
	
		$y[] 	= $this->nh($tmpk,$m[$i]);
				 					
		return $y;                             
		}

	private function l2_hash($key, $m, $bitlen, $iter)
		{
		/**
		The second-layer rehashes the L1-HASH output using a polynomial hash
		*/
		
		$t = str_split(substr($this->kdf($key, 192, 128 * ($iter+1)),-16),8);		

		$q0 = $this->big(bin2hex($t[0]));
		$q1 = $this->big(bin2hex($t[1]));
		
		$t1 = gmp_mul(gmp_and($q0,$this->MP),$this->pow2_64);
		$t2 = gmp_and($q1,$this->MP);
				
		$k = $y = $t1 | $t2;
	
		if (sizeof($m))
			{
			# Compute polynomial using Horner's rule	
			$y = 1;                         		
			for ($x=0;$x<sizeof($m);$x++)                   
				$y = gmp_mod(gmp_add(gmp_mul($y , $k) , $m[$x]) , $this->P127);
			}
	
		return gmp_mod(gmp_add($y , gmp_mul($bitlen % $this->L1KEYLEN , $this->pow2_64)) , $this->P127);
		}

	private function l3_hash($key, $m, $iter)
		{
		/** The output from L2-HASH is 128 bits long.  This final hash function
		   hashes the 128-bit string to a fixed length of 64 bits.*/
		# Generate key. 1/2^55 chance that it fails the first time (and so loop)
	
		$i 	= 1;
		$need 	= $iter + 1;
	
		while ($need > 0)
			{	
			$t  = str_split(substr($this->kdf($key, 224, 128 * $i),-16),8);
			
			$q0 = $this->big(bin2hex($t[0]));
			$q1 = $this->big(bin2hex($t[1]));

			$i++;
			
			if (gmp_cmp($this->P64, $q0) and gmp_cmp($this->P64 , $q1))
				$need--;									
			}
		
		$m0 	= gmp_add(gmp_div($m , $this->PP),$q0);
		$m1 	= gmp_add(gmp_mod($m , $this->PP),$q1);
	
		return gmp_mod(gmp_mul($m0 , $m1) , $this->P64);
		}		

	private function vhash($key, $m, $taglen)
		{
		/** VHASH is a keyed hash function, which takes as input a string and
		   produces a string output with length that is a multiple of 64 bits.*/
		$y = array();
	
		for ($i=0;$i<$taglen/64;$i++)
			{
			$a  = $this->l1_hash($key,$m,$i);	
			$b  = $this->l2_hash($key,$a,strlen($m)*8,$i);			
			$y[]= $this->l3_hash($key,$b,$i);			
			}
	
		return $y;
		}

	function vmac($key, $m, $nonce, $taglen)
		{	 
		/** The length of the
		   pad and hash can be any positive multiple of 64 bits, up to BLOCKLEN
		   bits*/  
		                              
		$hash = $this->vhash($key,$m,$taglen); 	
		$pad  = str_split(bin2hex($this->pdf($key,$nonce,$taglen)),16);
	
		$tag  = "";
		for ($i=0;$i<$taglen/64;$i++)	
			$tag .= gmp_Export(gmp_and(gmp_add($hash[$i] , $this->big($pad[$i])),$this->M64));
			
		return bin2hex($tag);	    
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
    public function test_vmac()
    	{
	echo "VMAC TEST VECTORS http://www.fastcrypto.org/vmac/draft-krovetz-vmac-01.txt\n\n";
	foreach (array(0,1,16,100,1000000) as $c)
		{
		echo $this->vmac("abcdefghijklmnop",str_repeat("abc",$c),"bcdefghi",64)." ";
		echo $this->vmac("abcdefghijklmnop",str_repeat("abc",$c),"bcdefghi",128)."\n";
		}
	echo "\n";	    
	}
}

$x = new NMR;

$x->test_cmac();
$x->test_pmac();
$x->test_OMAC2();
$x->test_vmac();
$x->test_aes_siv();
$x->test_aes_eax();

