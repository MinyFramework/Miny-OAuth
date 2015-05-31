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
use Modules\OAuth\ProviderDescriptor\OAuth20Descriptor;
use Modules\OAuth\Request;
use Modules\OAuth\Utils;
use UnexpectedValueException;

class OAuth20 extends OAuthClient
{
    /**
     * @var OAuth20Descriptor
     */
    private $descriptor;

    public function __construct(OAuth20Descriptor $pd, Request $request)
    {
        $this->descriptor = $pd;
        parent::__construct($pd, $request);
    }

    /**
     * Interact with the OAuth provider.
     * This function redirects the user to the service provider and request an access token.
     *
     * @throws OAuthException
     */
    public function process()
    {
        //$this->log('Initializing OAuth 2.0');
        $token = $this->getAccessToken();
        if ($token instanceof AccessToken && $token->authorized) {
            //$this->log('An authorized access token is set.');

            return; //we already have a token, so stop here
        }
        $storedState = $this->getStoredState();
        $state       = $this->getRequestVar('state');
        if ($state === $storedState) {
            //$this->log('Request state matches the stored state.');
            $code = $this->getRequestVar('code');
            if (empty($code)) {
                //$this->log('Access code is empty.');
                $error = $this->getRequestVar('error');
                if ($error != null) {
                    throw new OAuthException('An error has occurred.');
                }
            }
            $this->fetchAccessToken($code);
        } else {
            $values = [
                'state' => $storedState,
                'redirect_uri' => $this->getRedirectUri()
            ];
            //$this->log('Request state does not match the stored state.');
            //$this->log('Request a new access code.');
            if (isset($this->descriptor->scope) && !empty($this->descriptor->scope)) {
                $values['scope'] = $this->descriptor->getScopeString();
                //$this->log('Access token scope: ' . $values['scope']);
            }
            //$this->log('Redirecting to %s', $dialog_url);
            $this->redirect(
                $this->descriptor->getUrl('dialog', '', $values)
            );
        }
    }

    /**
     * @return string
     */
    protected function getStoredState()
    {
        $storage = $this->getTokenStorage();
        if (!$storage->has('oauth_state')) {
            $state = md5(time() . rand());
            //$message = 'Setting stored state: %s';

            $storage->set('oauth_state', $state);
        } else {
            $state = $storage->get('oauth_state');
            //$message = 'Stored state: %s';
        }
        //$this->log($message, $state);

        return $state;
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

        $post_values = $parameters;

        $http->setUrl($url);
        $http->setRequestMethod($method);
        $http->addPostFields($post_values);

        if (!isset($authorization)) {
            $accessToken = $this->getAccessToken();
            if ($accessToken instanceof AccessToken) {
                if (strcasecmp($accessToken->type, 'bearer') == 0) {
                    $authorization = 'Bearer ' . $accessToken;
                }
            }
        }
        if (isset($authorization)) {
            //$this->log('Authorization header: %s', $authorization);
            $http->addHeader('Authorization: ' . $authorization);
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
     * @throws UnexpectedValueException
     */
    public function call($url, $method = Client::METHOD_GET, array $parameters = [], array $options = [])
    {
        $accessToken = $this->getAccessToken();
        if ($accessToken == null) {
            throw new UnexpectedValueException('Access token is not set.');
        }

        if ($accessToken->isExpired()) {
            //$this->log('Access token is expired. Trying to refresh');
            if (!isset($accessToken->refresh_token)) {
                throw new OAuthException('Access token has expired but no refresh token is set.');
            }
            $this->refreshToken();
        }

        if (strcasecmp($accessToken->type, 'bearer')) {
            $url = Utils::addURLParams(
                $url,
                ['access_token' => (string)$accessToken]
            );
        }

        return $this->sendApiCall($url, $method, $parameters, $options);
    }

    /**
     * @param array $values
     */
    public function processTokenRequest(array $values = [])
    {
        //$this->log('Processing access token request. Parameters: ' . print_r($values, 1));
        $access_token_url = $this->descriptor->getUrl('access_token', '', [], $values);
        $http_response    = $this->sendApiCall(
            $access_token_url,
            Client::METHOD_POST,
            $values,
            []
        );

        $this->processResponse($http_response);

        $old_access_token = $this->getAccessToken();
        if ($old_access_token == null) {
            $stored_refresh_token = null;
        } else {
            $stored_refresh_token = $old_access_token->refresh_token;
        }

        $token = AccessToken::fromResponse($http_response, true, $stored_refresh_token);
        $this->storeAccessToken($token);
    }

    /**
     * Refresh an access token
     */
    public function refreshToken()
    {
        $accessToken = $this->getAccessToken();
        if ($accessToken === null) {
            throw new OAuthException('Cannot refresh. Access token is not set');
        }

        $values = [
            'client_id' => $this->descriptor->clientId,
            'client_secret' => $this->descriptor->clientSecret,
            'refresh_token' => $accessToken->refresh_token,
            'grant_type' => 'refresh_token'
        ];
        if (isset($this->scope)) {
            $values['scope'] = $this->scope;
        }
        $this->processTokenRequest($values);
    }

    /**
     * Fetches an access token from the remote provider.
     *
     * @param string $access_code
     */
    public function fetchAccessToken($access_code)
    {
        $values = [
            'code' => $access_code,
            'client_id' => $this->descriptor->clientId,
            'client_secret' => $this->descriptor->clientSecret,
            'redirect_uri' => $this->getRedirectUri(),
            'grant_type' => 'authorization_code'
        ];
        if (isset($this->descriptor->scope)) {
            if (is_array($this->descriptor->scope)) {
                $values['scope'] = implode(',', $this->descriptor->scope);
            } else {
                $values['scope'] = $this->descriptor->scope;
            }
        }
        $this->processTokenRequest($values);
    }
}