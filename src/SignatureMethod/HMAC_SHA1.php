<?php

namespace Modules\OAuth\SignatureMethod;

use Modules\OAuth\Utils;

class HMAC_SHA1 implements SignatureMethodInterface{

    private  function generateSignatureBase($method, $url, $values, $parameters)
    {
        $uri         = strtok($url, '?');
        $base_str    = strtoupper($method) . '&' . Utils::encode($uri) . '&';
        $sign_values = array_merge($values, $parameters);
        $u           = parse_url($url, PHP_URL_QUERY);
        if (isset($u)) {
            $q = [];
            parse_str($u, $q);
            foreach ($q as $parameter => $value) {
                $sign_values[$parameter] = $value;
            }
        }
        ksort($sign_values);
        $base_str .= Utils::encode(http_build_query($sign_values, '', '&'));
        $base_str = strtr($base_str, ['%2B' => '%2520']);

        //$this->log('Signature base string: %s', $base_str);

        return $base_str;
    }

    public function sign($key, $url, $method, $values, $parameters)
    {
        if (!in_array('sha1', hash_algos())) {
            throw new \RuntimeException('SHA1 is not supported by the Hash extension');
        }
        $base_str = $this->generateSignatureBase($method, $url, $values, $parameters);

        return base64_encode(hash_hmac('sha1', $base_str, $key, true));
    }
}