<?php

namespace Modules\OAuth\SignatureMethod;

class Plaintext implements SignatureMethodInterface{

    public function sign($key, $url, $method, $parameters)
    {
        return $key;
    }
}