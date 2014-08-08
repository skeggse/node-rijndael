<?php

class Crypt
{
    private $_opt = [];

    public function invoke($params)
    {
        $this->_opt = $params;
    }

    public function encrypt($msg)
    {
        $opt = $this->_opt;
        $iv = base64_decode($opt['iv']);
        $encrypt = mcrypt_encrypt($opt['cipher'], $opt['key'], $msg, $opt['mode'], $iv);
        return base64_encode($encrypt);
    }

    public function decrypt($data)
    {
        $opt = $this->_opt;
        $iv = base64_decode($opt['iv']);
        $data = base64_decode($data);
        return rtrim(mcrypt_decrypt($opt['cipher'], $opt['key'], $data, $opt['mode'], $iv), "\0");
    }

} // end of class

$msg = 'Goodbye, World!';
$Crypt = new Crypt;
$result_tpl = "\nCipher: `%s`\nMode: `%s`\nKey: `%s`\nIV.base64: `%s`\nMessage: `%s`\nEncrypted: `%s`\nDecrypted: `%s`\n\n";

$params = [
    'cipher' => MCRYPT_RIJNDAEL_256,
    'mode' => MCRYPT_MODE_ECB,
    'key' => 'ajd746kd63gxc',
    'iv' => 'FbRCcdAUp7yF9nd24oUxUCjoGgdZt4xTETcjNlDho8k='
];
$Crypt->invoke($params);
$params['msg'] = $msg;
$params['enc'] = $Crypt->encrypt($msg);
$params['dec'] = $Crypt->decrypt($params['enc']);
echo vsprintf($result_tpl, $params);
