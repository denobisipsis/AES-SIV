# AES-SIV

Included AES-CMAC &amp; AES_PMAC, OMAC2 & EAX

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

$x->aes_siv_encrypt($Key,$Sn,$plaintext);

$x->aes_siv_decrypt($Key,$Sn,$cipher);

[$Sn is an array of additional data (for example AAD or nonce)]

$x->aes_eax_encrypt($Message,$Key,$Nonce,$Header);

$x->aes_eax_decrypt($Cipher,$Key,$Nonce,$Header);

# TEST VECTORS

$x->test_cmac();
$x->test_pmac();
$x->test_OMAC2();
$x->test_vmac();
$x->test_aes_siv();
$x->test_aes_eax();
	
# License
This code is placed in the public domain.
