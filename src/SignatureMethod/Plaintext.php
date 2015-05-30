<?php

namespace Modules\OAuth\SignatureMethod;

class Plaintext implements SignatureMethodInterface{

    public function sign($key, $url, $method, $values, $parameters)
    {
        return $key;
    }
}