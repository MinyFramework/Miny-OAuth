<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\Client;

use Modules\OAuth\AccessToken;
use Modules\OAuth\Exceptions;
use Modules\OAuth\Exceptions\OAuthException;
use Modules\OAuth\HTTP\Client;
use Modules\OAuth\HTTP\Response;
use Modules\OAuth\OAuthClient;
use Modules\OAuth\ProviderDescriptor\OAuth10Base as OAuth10BaseDescriptor;
use Modules\OAuth\Request;
use Modules\OAuth\SignatureMethod\SignatureMethodFactory;
use Modules\OAuth\Utils;
use UnexpectedValueException;

abstract class OAuth10Base extends OAuthClient
{

    /**
     * @var OAuth10BaseDescriptor
     */
    private $descriptor;

    public function __construct(OAuth10BaseDescriptor $pd, Request $request)
    {
        $this->descriptor = $pd;
        parent::__construct($pd, $request);
    }

    public function signRequest($method, $url, $parameters, $clientSecret, $signatureMethod)
    {
        $key         = Utils::encode($clientSecret) . '&';
        $accessToken = $this->getAccessToken();
        if (isset($accessToken)) {
            $key .= Utils::encode($accessToken->secret);
        }

        $signatureMethodObject = SignatureMethodFactory::create($signatureMethod);
        return $signatureMethodObject->sign($key, $url, $method, $parameters);
    }

    protected function processFiles($files, $parameters, Client $http)
    {
        foreach ($files as $field_name => $info) {
            if (!isset($parameters[$field_name])) {
                throw new \OutOfBoundsException("\"{$field_name}\" is not found in the parameters array.");
            }
            if (!isset($info['file_name'])) {
                throw new \InvalidArgumentException("File name is missing from \"{$field_name}\".");
            }
            $http->addFile($field_name, isset($info['mime_type']) ? $info['file_name'] : null);
            unset($parameters[$field_name]);
        }

        return $parameters;
    }

    public function generateAuthorizationHeader($values)
    {
        $authorization = 'OAuth';
        $separator     = ' ';
        ksort($values);
        foreach ($values as $parameter => $value) {
            $authorization .= $separator . $parameter . '="' . Utils::encode($value) . '"';
            $separator = ', ';
        }

        return $authorization;
    }

    /**
     *
     * @param string $url
     * @param string $method
     * @param array $parameters
     * @param array $options
     * @return Response
     * @throws OAuthException
     */
    public function sendApiCall(
        $url,
        $method = Client::METHOD_GET,
        array $parameters = [],
        array $options = []
    ) {
        $http = new Client($this->descriptor->certificateFile);

        //$this->log('Sending API call to [%s] %s', $method, $url);

        if (isset($options['request_content_type'])) {
            $type = strtolower(trim(strtok($options['request_content_type'], ';')));
        } else {
            $type = 'application/x-www-form-urlencoded';
        }

        $post_values = [];
        $values      = [
            'oauth_consumer_key' => $this->descriptor->clientId,
            'oauth_nonce' => md5(uniqid(rand(), true)),
            'oauth_signature_method' => $this->descriptor->signatureMethod,
            'oauth_timestamp' => time(),
            'oauth_version' => '1.0'
        ];
        $move_keys   = [
            'oauth_token',
            'oauth_verifier',
            'oauth_callback'
        ];
        foreach ($move_keys as $key) {
            if (isset($options[$key])) {
                $values[$key] = $options[$key];
                unset($options[$key]);
            }
        }
        //File upload support
        $files = isset($options['files']) ? $options['files'] : [];
        if (count($files) > 0) {
            $method     = 'POST'; //force method to be POST
            $type       = 'multipart/form-data';
            $parameters = $this->processFiles($files, $parameters, $http);
        } else if ($type == 'application/x-www-form-urlencoded') {
            if ($this->descriptor->urlParameters && count($parameters)) {
                $url        = Utils::addURLParams($url, $parameters);
                $parameters = [];
            }
        }
        $values['oauth_signature'] = $this->signRequest(
            $method,
            $url,
            array_merge($values, $parameters),
            $this->descriptor->clientSecret,
            $this->descriptor->signatureMethod
        );
        ksort($values);
        $post_values_in_uri = isset($options['post_values_in_uri']) && $options['post_values_in_uri'];
        if ($method === Client::METHOD_GET || $this->descriptor->postValuesInUri || $post_values_in_uri) {
            $url = Utils::addURLParams($url, $parameters);
        } else {
            $post_values = $parameters;
        }

        $http->setUrl($url);
        $http->setRequestMethod($method);
        $http->addPostFields($post_values);

        if ($this->descriptor->authorizationHeader) {
            $http->addHeader('Authorization: ' . $this->generateAuthorizationHeader($values));
        }
        //$this->log('Content type: %s', $type);
        $http->addHeader('Content-Type: ' . $type);

        $response = $http->send($this->descriptor->curlOptions);

        $statusCode     = $response->getStatusCode();
        $responseReason = $response->getResponseReason();

        //$this->log('Response status: [%s] %s', $statusCode, $responseReason);
        if ($statusCode < 200 || $statusCode >= 300) {
            $details = $this->processResponse($response);
            //$this->log('Response headers: %s', print_r($response->getHeaders(), 1));
            //$this->log('Exception details: %s', print_r($details, 1));
            throw new OAuthException(
                "An error has occured. The error code is {$statusCode} and the message is \"{$responseReason}\"",
                $details
            );
        }

        return $response;
    }

    /**
     * @param string $url
     * @param string $method
     * @param array $parameters
     * @param array $options
     * @return Response
     * @throws OAuthException
     * @throws \UnexpectedValueException
     */
    public function call($url, $method = Client::METHOD_GET, array $parameters = [], array $options = [])
    {
        $accessToken = $this->getAccessToken();
        if ($accessToken === null) {
            throw new \UnexpectedValueException('Access token is not set.');
        }

        $options['oauth_token'] = (string)$accessToken;

        return $this->sendApiCall($url, $method, $parameters, $options);
    }

    /**
     * Interact with the OAuth provider.
     * This function redirects the user to the service provider and request an access token.
     *
     * @throws OAuthException
     */
    public function process()
    {
        $accessToken = $this->getAccessToken();

        if ($accessToken instanceof AccessToken) {
            $accessToken = $this->handleAccessToken($accessToken);
            if ($accessToken->authorized) {
                return;
            }
        } else {
            //access_token was null
            //$this->log('No access token was stored.');
            //$this->log('Creating an empty access token.');
            $accessToken = new AccessToken();
            $this->resetAccessToken();
        }

        $this->requestAccessToken($accessToken);
    }

    /**
     * @param AccessToken $accessToken
     * @return AccessToken
     */
    protected function doRequestTokenCall(AccessToken $accessToken)
    {
        if ($accessToken->authorized) {
            return $accessToken;
        }

        //$this->log('The access token is a newly created empty token.');
        //$this->log('Request an access token.');
        $values = [];
        if (isset($this->descriptor->scope) && !empty($this->descriptor->scope)) {
            $values['scope'] = $this->descriptor->getScopeString();
            //$this->log('Access token scope: ' . $values['scope']);
        }
        $response = $this->sendApiCall(
            $this->descriptor->getUrl('request_token', '', $values),
            strtoupper($this->descriptor->tokenRequestMethod),
            [],
            ['oauth_callback' => $this->getRedirectUri()]
        );

        $this->processResponse($response);
        $accessToken = AccessToken::fromResponse($response, false);
        $this->storeAccessToken($accessToken);

        return $accessToken;
    }

    protected abstract function requestAccessToken(AccessToken $accessToken);

    protected abstract function handleAccessToken(AccessToken $accessToken);
}