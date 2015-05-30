<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\ProviderDescriptor;

use Modules\OAuth\HTTP\Client;
use Modules\OAuth\ProviderDescriptor;
use Modules\OAuth\SignatureMethod\SignatureMethodFactory;

class OAuth10Base extends ProviderDescriptor
{
    public $signatureMethod     = SignatureMethodFactory::SIGNATURE_HMAC_SHA1;
    public $tokenRequestMethod  = Client::METHOD_GET;
    public $accept              = '*/*';
    public $urlParameters       = false;
    public $postValuesInUri     = false;
    public $authorizationHeader = false;
}