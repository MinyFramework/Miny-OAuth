<?php

namespace Modules\OAuth\SignatureMethod;

class SignatureMethodFactory
{

    const SIGNATURE_PLAINTEXT = 'PLAINTEXT';
    const SIGNATURE_HMAC_SHA1 = 'HMAC-SHA1';
    const SIGNATURE_RSA_SHA1 = 'RSA-SHA1';

    public static function create($signatureMethod)
    {
        switch ($signatureMethod) {
            case self::SIGNATURE_PLAINTEXT:
                return new Plaintext();
            case self::SIGNATURE_HMAC_SHA1:
                return new HMAC_SHA1();
            case self::SIGNATURE_RSA_SHA1:
                //return new RSA_SHA1();
        }
        throw new \UnexpectedValueException(
            "Signature method \"{$signatureMethod}\" is not supported."
        );
    }
}