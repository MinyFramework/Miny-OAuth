<?php

namespace Modules\OAuth\SignatureMethod;

interface SignatureMethodInterface {

    public function sign($key, $url, $method, $parameters);
}