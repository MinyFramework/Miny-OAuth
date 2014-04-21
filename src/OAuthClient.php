<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use InvalidArgumentException;
use Miny\HTTP\Request;
use Miny\Log\Log;
use Modules\OAuth\Exceptions\OAuthException;
use Modules\OAuth\HTTP\Client;
use Modules\OAuth\HTTP\Response;
use OutOfBoundsException;
use RuntimeException;
use UnexpectedValueException;

/**
 * OAuthClient is a client-side class for OAuth 1.0, 1.0a and 2.0 protocols.
 *
 * @author Dániel Buga
 */
class OAuthClient
{
    const SIGNATURE_PLAINTEXT = 'PLAINTEXT';
    const SIGNATURE_HMAC_SHA1 = 'HMAC-SHA1';
    const SIGNATURE_RSA_SHA1  = 'RSA-SHA1';

    /**
     *
     * @var ProviderDescriptor
     */
    private $provider;

    /**
     *
     * @var Request
     */
    private $request;

    /**
     *
     * @var Log
     */
    private $log;

    /**
     *
     * @var AccessToken
     */
    private $accessToken;

    /**
     * @param ProviderDescriptor $pd
     * @param array              $request
     * @param \Miny\Log\Log      $log
     */
    public function __construct(ProviderDescriptor $pd, array $request, Log $log = null)
    {
        $this->provider = $pd;
        $this->request  = $request;
        $this->log      = $log;
    }

    protected function log($message)
    {
        if (isset($this->log)) {
            $args = array_slice(func_get_args(), 1);
            $this->log->write(Log::DEBUG, 'OAuth', $message, $args);
        }
    }

    /**
     *
     * @param string $name
     * @param string $path
     * @param array  $options    Replacement array
     * @param array  $parameters Appended parameters
     *
     * @return string
     */
    public function getUrl($name, $path = '', array $options = array(), array $parameters = array())
    {
        return $this->provider->getUrl($name, $path, $options, $parameters);
    }

    /**
     *
     * @param string $name
     *
     * @return string|null
     * @throws UnexpectedValueException
     */
    protected function getRequestVar($name)
    {
        $allowed = array(
            'code',
            'error',
            'state',
            'oauth_token',
            'oauth_verifier',
            'denied',
            'path'
        );
        if (!in_array($name, $allowed)) {
            throw new UnexpectedValueException("Request variable \"{$name}\" can not be accessed from this scope.");
        }
        $this->log('Accessing %s request parameter', $name);

        return isset($this->request[$name]) ? $this->request[$name] : null;
    }

    /**
     * @return string
     */
    protected function getStoredState()
    {
        $storage = $this->provider->getStorage();
        if (!isset($storage->oauth_state)) {
            $state   = md5(time() . rand());
            $message = 'Setting stored state: %s';

            $storage->oauth_state = $state;
        } else {
            $state   = $storage->oauth_state;
            $message = 'Stored state: %s';
            unset($storage->oauth_state);
        }
        $this->log($message, $state);

        return $state;
    }

    public function generateSignatureBase($method, $url, $values, $parameters)
    {
        $uri         = strtok($url, '?');
        $base_str    = strtoupper($method) . '&' . Utils::encode($uri) . '&';
        $sign_values = array_merge($values, $parameters);
        $u           = parse_url($url, PHP_URL_QUERY);
        if (isset($u)) {
            $q = array();
            parse_str($u, $q);
            foreach ($q as $parameter => $value) {
                $sign_values[$parameter] = $value;
            }
        }
        ksort($sign_values);
        $base_str .= Utils::encode(http_build_query($sign_values, '', '&'));
        $base_str = strtr($base_str, array('%2B' => '%2520'));

        $this->log('Signature base string: %s', $base_str);

        return $base_str;
    }

    public function signRequest($method, $url, $values, $parameters)
    {
        $key = Utils::encode($this->provider->client_secret) . '&';
        if (isset($this->accessToken)) {
            $key .= Utils::encode($this->accessToken->secret);
        }
        $this->log('Signing method: %s', $this->provider->signature_method);
        $this->log('Signature key: %s', $key);

        switch ($this->provider->signature_method) {
            case self::SIGNATURE_PLAINTEXT:
                $signature = $key;
                break;
            case self::SIGNATURE_HMAC_SHA1:
                if (!in_array('sha1', hash_algos())) {
                    throw new RuntimeException('SHA1 is not supported by the Hash extension');
                }
                $base_str = $this->generateSignatureBase($method, $url, $values, $parameters);

                $signature = base64_encode(hash_hmac('sha1', $base_str, $key, true));
                break;
            default:
                throw new UnexpectedValueException(sprintf(
                    'Signature method "%s" is not supported.',
                    $this->provider->signature_method
                ));
        }
        $this->log('Signature: %s', $signature);

        return $signature;
    }

    private function processFiles($files, $parameters, Client $http)
    {
        foreach ($files as $field_name => $info) {
            if (!isset($parameters[$field_name])) {
                throw new OutOfBoundsException("\"{$field_name}\" is not found in the parameters array.");
            }
            if (!isset($info['file_name'])) {
                throw new InvalidArgumentException("File name is missing from \"{$field_name}\".");
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
     * @param array  $parameters
     * @param array  $options
     *
     * @throws Exceptions\OAuthException
     *
     * @return Response
     */
    public function sendApiCall(
        $url,
        $method = Client::METHOD_GET,
        array $parameters = array(),
        array $options = array()
    ) {
        $cert_file = isset($this->provider->certificate_file) ? $this->provider->certificate_file : null;
        $http      = new Client($cert_file, $this->log);

        $this->log('Sending API call to [%s] %s', $method, $url);

        $version = $this->provider->version;
        if (isset($options['request_content_type'])) {
            $type = strtolower(trim(strtok($options['request_content_type'], ';')));
        } else {
            $type = 'application/x-www-form-urlencoded';
        }
        if (intval($version) == 1) {
            $post_values = array();
            $values      = array(
                'oauth_consumer_key'     => $this->provider->client_id,
                'oauth_nonce'            => md5(uniqid(rand(), true)),
                'oauth_signature_method' => $this->provider->signature_method,
                'oauth_timestamp'        => time(),
                'oauth_version'          => '1.0'
            );
            $move_keys   = array(
                'oauth_token',
                'oauth_verifier',
                'oauth_callback'
            );
            foreach ($move_keys as $key) {
                if (isset($options[$key])) {
                    $values[$key] = $options[$key];
                    unset($options[$key]);
                }
            }
            //File upload support
            $files = isset($options['files']) ? $options['files'] : array();
            if (count($files) > 0) {
                $method     = 'POST'; //force method to be POST
                $type       = 'multipart/form-data';
                $parameters = $this->processFiles($files, $parameters, $http);
            } else {
                if ($type == 'application/x-www-form-urlencoded') {
                    if ($this->provider->url_parameters && count($parameters)) {
                        $url        = Utils::addURLParams($url, $parameters);
                        $parameters = array();
                    }
                }
            }
            $values['oauth_signature'] = $this->signRequest($method, $url, $values, $parameters);
            ksort($values);
            if ($this->provider->authorization_header) {
                $authorization = $this->generateAuthorizationHeader($values);
            }
            $post_values_in_uri = isset($options['post_values_in_uri']) && $options['post_values_in_uri'];
            if ($method === Client::METHOD_GET || $this->provider->post_values_in_uri || $post_values_in_uri) {
                $url = Utils::addURLParams($url, $parameters);
            } else {
                $post_values = $parameters;
            }
        } else {
            $post_values = $parameters;
        }
        $http->setUrl($url);
        $http->setRequestMethod($method);
        $http->addPostFields($post_values);

        if (!isset($authorization) && $this->accessToken instanceof AccessToken) {
            if (strcasecmp($this->accessToken->type, 'bearer') == 0) {
                $authorization = 'Bearer ' . $this->accessToken;
            }
        }
        if (isset($authorization)) {
            $this->log('Authorization header: %s', $authorization);
            $http->addHeader('Authorization: ' . $authorization);
        }
        $this->log('Content type: %s', $type);
        $http->addHeader('Content-Type: ' . $type);

        $response       = $http->send();
        $statusCode     = $response->getStatusCode();
        $responseReason = $response->getResponseReason();
        $this->log('Response status: [%s] %s', $statusCode, $responseReason);
        if ($statusCode < 200 || $statusCode >= 300) {
            $details = $this->processResponse($response);
            $this->log('Response headers: %s', print_r($response->getHeaders(), 1));
            $this->log('Exception details: %s', print_r($details, 1));
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
     * @param array  $parameters
     * @param array  $options
     *
     * @throws Exceptions\OAuthException
     * @throws \UnexpectedValueException
     * @return Response
     */
    public function call(
        $url,
        $method = Client::METHOD_GET,
        array $parameters = array(),
        array $options = array()
    ) {
        $access_token = $this->getAccessToken();
        if ($access_token == null) {
            throw new UnexpectedValueException('Access token is not set.');
        }
        $version = $this->provider->version;
        switch (intval($version)) {
            case 1:
                $options['oauth_token'] = (string) $access_token;
                break;
            case 2:
                if (strcmp($access_token->expiry, gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0) {
                    $this->log('Access token is expired. Trying to refresh');
                    if (!isset($access_token->refresh_token)) {
                        throw new OAuthException('Access token has expired but no refresh token is set.');
                    }
                    $this->refreshToken();
                }

                if (strcasecmp($access_token->type, 'bearer')) {
                    $url = Utils::addURLParams(
                        $url,
                        array('access_token' => (string) $access_token)
                    );
                }
                break;
            default:
                $this->versionNotSupported($version);
        }

        return $this->sendApiCall($url, $method, $parameters, $options);
    }

    /**
     * @param AccessToken $token
     */
    public function storeAccessToken(AccessToken $token)
    {
        $storage = $this->provider->getStorage();
        $this->log('Storing acces token: %s', $token);
        $storage->access_token = $token;
        $this->accessToken     = $token;
    }

    /**
     * Resets the saved access token.
     */
    public function resetAccessToken()
    {
        $storage = $this->provider->getStorage();
        $this->log('Resetting stored acces token.');
        unset($storage->access_token);
        unset($this->accessToken);
    }

    /**
     * @return null|AccessToken
     */
    public function getAccessToken()
    {
        if (!isset($this->accessToken)) {
            $storage = $this->provider->getStorage();
            if (!isset($storage->access_token)) {
                return null;
            }
            $this->accessToken = $storage->access_token;
            $this->log('Retrieving stored acces token: %s', $this->accessToken);
        }

        return $this->accessToken;
    }

    public function processResponse(Response $http_response, $callback = null)
    {
        if (isset($this->provider->http_response_processing_callback) && $callback == null) {
            $callback = $this->provider->http_response_processing_callback;
        }

        return $http_response->processBody(
            $this->provider->http_response_processing_type,
            $callback
        );
    }

    /**
     * @param array $values
     */
    public function processTokenRequest(array $values = array())
    {
        $this->log('Processing access token request. Parameters: ' . print_r($values, 1));
        $access_token_url = $this->provider->getUrl('access_token', '', array(), $values);
        $http_response    = $this->sendApiCall(
            $access_token_url,
            Client::METHOD_POST,
            $values,
            array()
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
     * Fetches an access token from the remote provider.
     *
     * @param string $access_code
     */
    public function fetchAccessToken($access_code)
    {
        $values = array(
            'code'          => $access_code,
            'client_id'     => $this->provider->client_id,
            'client_secret' => $this->provider->client_secret,
            'redirect_uri'  => $this->getRedirectUri(),
            'grant_type'    => 'authorization_code'
        );
        if (isset($this->scope)) {
            if (is_array($this->scope)) {
                $values['scope'] = implode(',', $this->scope);
            } else {
                $values['scope'] = $this->scope;
            }
        }
        $this->processTokenRequest($values);
    }

    /**
     * Refresh an access token
     */
    public function refreshToken()
    {
        $values = array(
            'client_id'     => $this->provider->client_id,
            'client_secret' => $this->provider->client_secret,
            'refresh_token' => $this->accessToken->refresh_token,
            'grant_type'    => 'refresh_token'
        );
        if (isset($this->scope)) {
            $values['scope'] = $this->scope;
        }
        $this->processTokenRequest($values);
    }

    /**
     * @return string
     */
    private function getRedirectUri()
    {
        return 'http://' . $_SERVER['HTTP_HOST'] . $this->getRequestVar('path');
    }

    private function processOAuth1()
    {
        $one_a = ($this->provider->version === '1.0a');
        $this->log('Initializing OAuth ' . (($one_a) ? '1.0a' : '1.0'));
        $access_token = $this->getAccessToken();
        if ($access_token instanceof AccessToken) {
            if (isset($access_token->expiry)) {
                $expired = strcmp($access_token->expiry, gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0;
            } else {
                $expired = false;
            }
            if (!$access_token->authorized || $expired) {
                $this->log('The stored access token is not authorized.');

                $token    = $this->getRequestVar('oauth_token');
                $verifier = $this->getRequestVar('oauth_verifier');

                if ($token === null || ($one_a && $verifier === null)) {
                    $denied = $this->getRequestVar('denied');
                    if (isset($denied) && $denied === $access_token->access_token) {
                        throw new OAuthException('The access token was denied.');
                    } else {
                        $this->log('The request does not include a token or verifier.');
                        $this->log('Creating an empty access token.');
                        $access_token = new AccessToken();
                        $this->resetAccessToken();
                    }
                } elseif ($token !== $access_token->access_token) {
                    $this->log(
                        'The token contained in the request does not match the stored token.'
                    );
                    $this->log('Creating an empty access token.');
                    $access_token = new AccessToken();
                    $this->resetAccessToken();
                } else {
                    $this->log('Exchanging the request token for an access token.');
                    $url     = $this->provider->getUrl('access_token');
                    $options = array(
                        'oauth_token' => (string) $token,
                    );
                    if ($one_a) {
                        $this->log('Token verifier: ' . $verifier);
                        $options['oauth_verifier'] = $verifier;
                    }
                    $method   = strtoupper($this->provider->token_request_method);
                    $response = $this->sendApiCall($url, $method, array(), $options);

                    $this->processResponse($response);
                    $access_token = AccessToken::fromResponse($response);
                    $this->StoreAccessToken($access_token);
                }
            }
            //we're authorized
            if ($access_token->authorized) {
                $this->log('The access token is authorized.');

                return;
            }
        } else {
            //access_token was null
            $this->log('No access token was stored.');
            $this->log('Creating an empty access token.');
            $access_token = new AccessToken();
            $this->resetAccessToken();
        }
        if (!$access_token->authorized) {
            $this->log('The access token is a newly created empty token.');
            $this->log('Request an access token.');
            $values = array();
            if (isset($this->provider->scope) && !empty($this->provider->scope)) {
                if (is_array($this->provider->scope)) {
                    $values['scope'] = implode(',', $this->provider->scope);
                } else {
                    $values['scope'] = $this->provider->scope;
                }
                $this->log('Access token scope: ' . $values['scope']);
            }
            $url      = $this->provider->getUrl('request_token', '', $values);
            $options  = array(
                'oauth_callback' => $this->getRedirectUri()
            );
            $method   = strtoupper($this->provider->token_request_method);
            $response = $this->sendApiCall($url, $method, array(), $options);

            $this->processResponse($response);
            $access_token = AccessToken::fromResponse($response, false);
            $this->storeAccessToken($access_token);
        }
        $url_options = array('oauth_token' => (string) $access_token);
        if (!$one_a) {
            $url_options['oauth_callback'] = $this->getRedirectUri();
        }
        $this->log('Sending access token to be authorized by user.');
        $url = $this->provider->getURL('dialog', '', array(), $url_options);

        $this->log('Redirecting to ' . $url);
        Utils::redirect($url);
    }

    private function processOAuth2()
    {
        $this->log('Initializing OAuth 2.0');
        $token = $this->getAccessToken();
        if ($token instanceof AccessToken && $token->authorized) {
            $this->log('An authorized access token is set.');

            return; //we already have a token, so stop here
        }
        $stored_state = $this->getStoredState();
        $state        = $this->getRequestVar('state');
        if ($state === $stored_state) {
            $this->log('Request state matches the stored state.');
            $code = $this->getRequestVar('code');
            if (empty($code)) {
                $this->log('Access code is empty.');
                $error = $this->getRequestVar('error');
                if ($error != null) {
                    throw new OAuthException('An error has occured.');
                }
            }
            $this->fetchAccessToken($code);
        } else {
            $values = array(
                'state'        => $stored_state,
                'redirect_uri' => $this->getRedirectUri()
            );
            $this->log('Request state does not match the stored state.');
            $this->log('Request a new access code.');
            if (isset($this->provider->scope) && !empty($this->provider->scope)) {
                if (is_array($this->provider->scope)) {
                    $values['scope'] = implode(',', $this->provider->scope);
                } else {
                    $values['scope'] = $this->provider->scope;
                }
                $this->log('Access token scope: ' . $values['scope']);
            }
            $dialog_url = $this->provider->getUrl('dialog', '', $values);

            //TODO: properly handle redirections using Miny's methods.
            //That way we won't interrupt the normal process.
            $this->log('Redirecting to %s', $dialog_url);
            Utils::redirect($dialog_url);
        }
    }

    /**
     * Interact with the OAuth provider.
     * This function redirects the user to the service provider and request an access token.
     *
     * @throws OAuthException
     */
    public function process()
    {
        $version = $this->provider->version;
        switch (intval($version)) {
            case 1:
                $this->processOAuth1();
                break;
            case 2:
                $this->processOAuth2();
                break;
            default:
                $this->versionNotSupported($version);
        }
    }

    /**
     * @param mixed $version
     *
     * @throws OAuthException
     */
    private function versionNotSupported($version)
    {
        $this->log('OAuth %s is not supported.', $version);
        throw new OAuthException(sprintf('OAuth %s is not supported.', $version));
    }
}
