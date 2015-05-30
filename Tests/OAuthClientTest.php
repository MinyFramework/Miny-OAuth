<?php

namespace Modules\OAuth;

use Modules\OAuth\Storage\DummyStorage;

class OAuthClientTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var OAuthClient
     */
    protected $object;
    protected $values = [
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
        $descriptor                   = new ProviderDescriptor(new DummyStorage());
        $descriptor->client_secret    = '9fY7oJMTpDeQZkF5xyrP78pdaws3wgsckUBM7oXFUso';
        $descriptor->signature_method = 'HMAC-SHA1';

        $token               = new AccessToken();
        $this->object        = new OAuthClient($descriptor, []);
        $token->access_token = '239950953-bl66iuLPi2vedrzAGZhetvlGQnxREFa5oc9Le5wg';
        $token->secret       = '1vZJeOoTXi2mcvU1abnbd4sfhEaaKGJEZQtOHZbL8xyRr';
        $this->object->storeAccessToken($token);
    }

    public function testSignatureBase()
    {
        $expected = 'POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&oauth_consumer_key%3DHkmZyQHb4pGYk99E8965w%26oauth_nonce%3Dc23736d774312351c0c735af0f7026f3%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1384280790%26oauth_token%3D239950953-bl66iuLPi2vedrzAGZhetvlGQnxREFa5oc9Le5wg%26oauth_version%3D1.0%26status%3DMaybe%2520he%2527ll%2520finally%2520find%2520his%2520keys.%2520%2523peterfalk';

        $url    = 'https://api.twitter.com/1.1/statuses/update.json';
        $actual = $this->object->generateSignatureBase('POST', $url, $this->values, $this->parameters);
        $this->assertEquals($expected, $actual);
    }

    /**
     * @depends testSignatureBase
     */
    public function testSignature()
    {
        $expected = 'gdj38Xw54DZsQ3UVWGcr+5X+yiM=';
        $url      = 'https://api.twitter.com/1.1/statuses/update.json';
        $actual   = $this->object->signRequest('POST', $url, $this->values, $this->parameters);
        $this->assertEquals($expected, $actual);
    }

    public function testAuthorizationHeader()
    {
        $expected                        = 'OAuth oauth_consumer_key="HkmZyQHb4pGYk99E8965w", oauth_nonce="c23736d774312351c0c735af0f7026f3", oauth_signature="gdj38Xw54DZsQ3UVWGcr%2B5X%2ByiM%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1384280790", oauth_token="239950953-bl66iuLPi2vedrzAGZhetvlGQnxREFa5oc9Le5wg", oauth_version="1.0"';
        $this->values['oauth_signature'] = 'gdj38Xw54DZsQ3UVWGcr+5X+yiM=';
        $actual                          = $this->object->generateAuthorizationHeader($this->values);
        $this->assertEquals($expected, $actual);
    }
}

?>
