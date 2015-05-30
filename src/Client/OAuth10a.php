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
use Modules\OAuth\ProviderDescriptor\OAuth10aDescriptor;

class OAuth10a extends OAuth10Base
{

    /**
     * @var OAuth10aDescriptor
     */
    private $descriptor;

    public function __construct(OAuth10aDescriptor $pd, array $request)
    {
        $this->descriptor = $pd;
        parent::__construct($pd, $request);
    }

    /**
     * @param $accessToken
     * @return AccessToken
     */
    public function handleAccessToken(AccessToken $accessToken)
    {
        if (!$accessToken->authorized || $accessToken->isExpired()) {
            //$this->log('The stored access token is not authorized.');

            $token    = $this->getRequestVar('oauth_token');
            $verifier = $this->getRequestVar('oauth_verifier');

            if ($verifier === null) {
                $denied = $this->getRequestVar('denied');
                if (isset($denied) && $denied === $accessToken->access_token) {
                    throw new OAuthException('The access token was denied.');
                }

                //$this->log('The request does not include a token or verifier.');
                //$this->log('Creating an empty access token.');
                $accessToken = new AccessToken();
                $this->resetAccessToken();
            } else if ($token !== $accessToken->access_token) {
                //$this->log(
                //    'The token contained in the request does not match the stored token.'
                //);
                //$this->log('Creating an empty access token.');
                $accessToken = new AccessToken();
                $this->resetAccessToken();
            } else {
                //$this->log('Exchanging the request token for an access token.');
                $url = $this->descriptor->getUrl('access_token');
                //$this->log('Token verifier: ' . $verifier);

                $options = [
                    'oauth_token' => (string)$token,
                    'oauth_verifier' => $verifier
                ];

                $method   = strtoupper($this->descriptor->tokenRequestMethod);
                $response = $this->sendApiCall($url, $method, [], $options);

                $this->processResponse($response);
                $accessToken = AccessToken::fromResponse($response);
                $this->storeAccessToken($accessToken);
            }
        }
        return $accessToken;
    }

    /**
     * @param $accessToken
     */
    protected function requestAccessToken(AccessToken $accessToken)
    {
        $accessToken = $this->doRequestTokenCall($accessToken);

        //$this->log('Sending access token to be authorized by user.');
        $url = $this->descriptor->getURL('dialog', '', [], ['oauth_token' => (string)$accessToken]);

        //$this->log('Redirecting to ' . $url);
        $this->redirect($url);
    }
}