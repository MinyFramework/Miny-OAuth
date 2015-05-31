<?php

namespace Modules\OAuth;

use Modules\OAuth\Client\OAuth10;
use Modules\OAuth\ProviderDescriptor\OAuth10Descriptor;
use Modules\OAuth\SignatureMethod\SignatureMethodFactory;
use Modules\OAuth\Storage\DummyStorage;

class OAuthClientTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var OAuth10
     */
    protected $object;
    protected $values     = [
        'oauth_consumer_key' => 'HkmZyQHb4pGYk99E8965w',
        'oauth_token' => '239950953-bl66iuLPi2vedrzAGZhetvlGQnxREFa5oc9Le5wg',
        'oauth_nonce' => 'c23736d774312351c0c735af0f7026f3',
        'oauth_signature_method' => 'HMAC-SHA1',
        'oauth_timestamp' => '1384280790',
        'oauth_version' => '1.0'
    ];
    protected $parameters = [
        'status' => 'Maybe he\'ll finally find his keys. #peterfalk'
    ];

    protected function setUp()
    {
        $descriptor                  = new OAuth10Descriptor(new DummyStorage());
        $descriptor->clientSecret    = '9fY7oJMTpDeQZkF5xyrP78pdaws3wgsckUBM7oXFUso';
        $descriptor->signatureMethod = SignatureMethodFactory::SIGNATURE_HMAC_SHA1;

        $token               = new AccessToken();
        $this->object        = new OAuth10($descriptor, new Request('', []));
        $token->access_token = '239950953-bl66iuLPi2vedrzAGZhetvlGQnxREFa5oc9Le5wg';
        $token->secret       = '1vZJeOoTXi2mcvU1abnbd4sfhEaaKGJEZQtOHZbL8xyRr';
        $this->object->storeAccessToken($token);
    }

    public function testAuthorizationHeader()
    {
        $expected                        = 'OAuth oauth_consumer_key="HkmZyQHb4pGYk99E8965w", oauth_nonce="c23736d774312351c0c735af0f7026f3", oauth_signature="gdj38Xw54DZsQ3UVWGcr%2B5X%2ByiM%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1384280790", oauth_token="239950953-bl66iuLPi2vedrzAGZhetvlGQnxREFa5oc9Le5wg", oauth_version="1.0"';
        $this->values['oauth_signature'] = 'gdj38Xw54DZsQ3UVWGcr+5X+yiM=';
        $actual                          = $this->object->generateAuthorizationHeader($this->values);
        $this->assertEquals($expected, $actual);
    }
}
