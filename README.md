# AES-SIV
Included AES-CMAC &amp; AES_PMAC

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
