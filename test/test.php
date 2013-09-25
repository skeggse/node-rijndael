<?php
//error_reporting(E_ERROR | E_PARSE);

$key = "90897ae9d0efa1e0c30bf9cb86af34d8";
$plaintext = "hello how are you this is supposed to be long to surpass the 256 block limit so yeah let's go it's gonna take a while how are you today";
$plaintext = "$plaintext--$plaintext";

echo "  plaintext: $plaintext\n\n";

$ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $plaintext, MCRYPT_MODE_CBC);
$finaltext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $ciphertext, MCRYPT_MODE_CBC);

echo "CBC\n";
echo "  ciphertext: " . base64_encode($ciphertext) . "\n";
echo "  original:   $finaltext\n";
echo "  match: " . (trim($finaltext) === $plaintext ? "YES" : "NO") . "\n\n";

$ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $plaintext, MCRYPT_MODE_ECB);
$finaltext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $ciphertext, MCRYPT_MODE_ECB);

echo "ECB\n";
echo "  ciphertext: " . base64_encode($ciphertext) . "\n";
echo "  original:   $finaltext\n";
echo "  match: " . (trim($finaltext) === $plaintext ? "YES" : "NO") . "\n\n";

echo "All done\n";
