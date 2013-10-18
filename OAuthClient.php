<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use Exception;
use InvalidArgumentException;
use Miny\HTTP\Request;
use Modules\OAuth\HTTP\Client;
use Modules\OAuth\HTTP\Response;
use OutOfBoundsException;
use RuntimeException;
use UnexpectedValueException;

if (!function_exists('curl_init')) {
    throw new Exception('OAuth needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
    throw new Exception('OAuth needs the JSON PHP extension.');
}

/**
 * OAuthClient is a client-side class for OAuth 1.0, 1.0a and 2.0 protocols.
 *
 * @author Dániel Buga
 */
class OAuthClient
{
    const SIGNATURE_PLAINTEXT = 'PLAINTEXT';
    const SIGNATURE_HMAC_SHA1 = 'HMAC-SHA1';
    const SIGNATURE_RSA_SHA1 = 'RSA-SHA1';

    /**
     *
     * @var \Modules\OAuth\ProviderDescriptor
     */
    private $provider;

    /**
     *
     * @var Request
     */
    private $request;

    /**
     *
     * @var \Modules\OAuth\AccessToken
     */
    private $access_token;

    /**
     *
     * @var string|array
     */
    public $scope;

    /**
     *
     * @param \Modules\OAuth\ProviderDescriptor $pd
     * @param Request $request
     */
    public function __construct(ProviderDescriptor $pd, Request $request)
    {
        $this->provider = $pd;
        $this->request = $request;
    }

    /**
     *
     * @param string $name
     * @param string $path
     * @param array $options Replacement array
     * @param array $parameters Appended parameters
     * @return string
     */
    public function getUrl($name, $path = '', array $options = array(), array $parameters = array())
    {
        return $this->provider->getUrl($name, $path, $options, $parameters);
    }

    /**
     *
     * @param string $name
     * @return string|null
     * @throws UnexpectedValueException
     */
    protected function getRequestVar($name)
    {
        $allowed = array('code', 'error', 'state', 'oauth_token', 'oauth_verifier', 'denied');
        if (!in_array($name, $allowed)) {
            $message = sprintf('Request variable "%s" can not be accessed from this scope.', $name);
            throw new UnexpectedValueException($message);
        }
        return isset($this->request->get[$name]) ? $this->request->get[$name] : null;
    }

    /**
     *
     * @return string
     */
    protected function getStoredState()
    {
        $storage = $this->provider->getStorage();
        if (!isset($storage->oauth_state)) {
            $storage->oauth_state = md5(time() . rand());
        }
        return $storage->oauth_state;
    }

    /**
     *
     * @param string $url
     * @param string $method
     * @param array $parameters
     * @param array $options
     * @param boolean $process_response
     * @return Response
     * @throws UnexpectedValueException
     */
    public function sendApiCall($url, $method = Client::METHOD_GET, array $parameters = array(),
                                array $options = array(), $process_response = true)
    {
        $cert_file = isset($this->provider->certificate_file) ? $this->provider->certificate_file : null;
        $http = new Client($cert_file);

        $version = $this->provider->version;
        if (isset($options['request_content_type'])) {
            $type = strtolower(trim(strtok($options['request_content_type'], ';')));
        } else {
            $type = 'application/x-www-form-urlencoded';
        }
        if (intval($version) == 1) {
            $post_values = array();
            $values = array(
                'oauth_consumer_key'     => $this->provider->client_id,
                'oauth_nonce'            => md5(uniqid(rand(), true)),
                'oauth_signature_method' => $this->provider->signature_method,
                'oauth_timestamp'        => time(),
                'oauth_version'          => '1.0'
            );
            $move_keys = array(
                'oauth_token', 'oauth_verifier', 'oauth_callback'
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
                $method = 'POST'; //force method to be POST
                $type = 'multipart/form-data';
                foreach ($files as $field_name => $info) {
                    if (!isset($parameters[$field_name])) {
                        $message = sprintf('"%s" is not found in the parameters array.', $field_name);
                        throw new OutOfBoundsException($message);
                    }
                    if (!isset($info['file_name'])) {
                        $message = sprintf('File name is missing from "%s".', $field_name);
                        throw new InvalidArgumentException($message);
                    }
                    $http->addFile($field_name, isset($info['mime_type']) ? $info['file_name'] : null);
                    unset($parameters[$field_name]);
                }
            } else if ($type == 'application/x-www-form-urlencoded') {
                if ($this->provider->url_parameters && count($parameters)) {
                    $url = Utils::addURLParams($url, $parameters);
                    $parameters = array();
                } else {
                    $values = array_merge($values, $parameters);
                }
            }

            $key = Utils::encode($this->provider->client_secret) . '&' . Utils::encode($this->access_token->secret);
            switch ($this->provider->signature_method) {
                case self::SIGNATURE_PLAINTEXT:
                    $values['oauth_signature'] = $key;
                    break;
                case self::SIGNATURE_HMAC_SHA1:
                    if (!in_array('sha1', hash_algos())) {
                        throw new RuntimeException('SHA1 is not supported by the Hash extension');
                    }
                    $uri = strtok($url, '?');
                    $sign = $method . '&' . Utils::encode($uri);
                    $sign_values = $values;
                    $u = parse_url($url, PHP_URL_QUERY);
                    if (isset($u)) {
                        $q = array();
                        parse_str($u, $q);
                        foreach ($q as $parameter => $value) {
                            $sign_values[$parameter] = $value;
                        }
                    }
                    ksort($sign_values);
                    $sign = Utils::addURLParams($sign, $sign_values);
                    $values['oauth_signature'] = base64_encode(hash_hmac('sha1', $sign, $key, true));
                    break;
                default:
                    $message = sprintf('Signature method "%s" is not supported.', $this->provider->signature_method);
                    throw new UnexpectedValueException($message);
            }
            ksort($values);
            if ($this->provider->authorization_header) {
                $authorization = 'OAuth';
                $separator = ' ';
                foreach ($values as $parameter => $value) {
                    $authorization .= $separator . $parameter . '="' . Utils::encode($value) . '"';
                    $separator = ',';
                }
            } else {
                $post_values_in_uri = isset($options['post_values_in_uri']) && $options['post_values_in_uri'];
                if ($method === Client::METHOD_GET || $this->provider->post_values_in_uri || $post_values_in_uri) {
                    $url = Utils::addURLParams($url, $values);
                } else {
                    $post_values = $values;
                }
            }
        } else {
            $post_values = $parameters;
        }
        $http->setUrl($url);
        $http->setRequestMethod($method);
        $http->addPostFields($post_values);

        if (!isset($authorization) && $this->access_token instanceof AccessToken) {
            if (strcasecmp($this->access_token->type, 'bearer') == 0) {
                $authorization = 'Bearer ' . $authorization;
            }
        }
        if (isset($authorization)) {
            $http->addHeader('Authorization: ' . $authorization);
        }
        $http->addHeader('Content-Type: ' . $type);

        //die(print_r($http, 1));
        $response = $http->send();
        if ($response->status_code < 200 || $response->status_code >= 300) {
            $message = sprintf('An error has occured. The error code is %d and the message is "%s". More information: %s',
                    $response->status_code, $response->response_reason, print_r($response, 1));
            throw new UnexpectedValueException($message);
        }
        if ($process_response) {
            if (isset($this->provider->http_response_processing_callback)) {
                $callback = $this->provider->http_response_processing_callback;
            } else {
                $callback = null;
            }
            $response->processBody($this->provider->http_response_processing_type, $callback);
        }
        return $response;
    }

    /**
     *
     * @param type $url
     * @param type $method
     * @param array $parameters
     * @param array $options
     */
    public function call($url, $method = Client::METHOD_GET, array $parameters = array(), array $options = array(),
                         $process_result = true)
    {
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
                    //access token is expired
                    if (!isset($access_token->refresh_token)) {
                        throw new RuntimeException('Access token has expired but no refresh token is set.');
                    }
                    $this->refreshToken();
                }

                if (strcasecmp($access_token->type, 'bearer')) {
                    $url = Utils::addURLParams($url, array('access_token' => (string) $access_token));
                }
                break;
            default:
                $this->versionNotSupported($version);
        }
        return $this->sendApiCall($url, $method, $parameters, $options, $process_result);
    }

    /**
     *
     * @param AccessToken $token
     */
    public function storeAccessToken(AccessToken $token)
    {
        $storage = $this->provider->getStorage();
        $storage->access_token = $token;
        $this->access_token = $token;
    }

    /**
     * Resets the saved access token.
     */
    public function resetAccessToken()
    {
        $storage = $this->provider->getStorage();
        unset($storage->access_token);
        unset($this->access_token);
    }

    /**
     *
     * @return null|AccessToken
     */
    public function getAccessToken()
    {
        if (!isset($this->access_token)) {
            $storage = $this->provider->getStorage();
            if (!isset($storage->access_token)) {
                return null;
            }
            $this->access_token = $storage->access_token;
        }
        return $this->access_token;
    }

    /**
     *
     * @return string|null
     */
    protected function getStoredRefreshToken()
    {
        $access_token = $this->getAccessToken();
        if ($access_token == null) {
            return null;
        }
        return $access_token->refresh_token;
    }

    /**
     *
     * @param array $values
     */
    public function processTokenRequest(array $values = array())
    {
        $access_token_url = $this->provider->getUrl('access_token', '', array(), $values);
        $http_response = $this->sendApiCall($access_token_url, Client::METHOD_POST, $values, array());
        //TODO: error check based on response code
        $token = AccessToken::fromResponse($http_response, true, $this->getStoredRefreshToken());
        $this->storeAccessToken($token);
    }

    /**
     * Fetches an access token from the remote provider.
     * @param type $access_code
     */
    public function fetchAccessToken($access_code)
    {
        //TODO: ellenőrizni ezt a tömböt
        //néhány elem behelyettesítődik, ha URL... muszáj request bodyban?
        $values = array(
            'code'          => $access_code,
            'client_id'     => $this->provider->client_id,
            'client_secret' => $this->provider->client_secret,
            'redirect_uri'  => $this->getRedirectUri(),
            'grant_type'    => 'authorization_code'
        );
        if (isset($this->scope)) {
            if (is_array($this->scope)) {
                $values['scope'] = impolode(',', $this->scope);
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
            'refresh_token' => $this->access_token->refresh_token,
            'grant_type'    => 'refresh_token'
        );
        if (isset($this->scope)) {
            $values['scope'] = $this->scope;
        }
        $this->processTokenRequest($values);
    }

    private function getRedirectUri()
    {
        return Utils::encode('http://' . $_SERVER['HTTP_HOST'] . $this->request->path);
    }

    private function processOAuth1()
    {
        $one_a = ($this->provider->version === '1.0a');
        $access_token = $this->getAccessToken();
        if ($access_token instanceof AccessToken) {
            $expired = strcmp($access_token->expiry, gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0;
            if (!$access_token->authorized || $expired) {

                $token = $this->getRequestVar('oauth_token');
                $verifier = $this->getRequestVar('oauth_verifier');

                if ($token === null || ($one_a && $verifier === null)) {
                    $denied = $this->getRequestVar('denied');
                    if (isset($denied) && $denied === $access_token->access_token) {
                        throw new UnexpectedValueException('The access token was denied.');
                    } else {
                        $access_token = new AccessToken();
                    }
                } elseif ($token !== $access_token->access_token) {
                    $access_token = new AccessToken();
                } else {
                    $url = $this->provider->getUrl('access_token');
                    $options = array(
                        'oauth_token' => (string) $token,
                    );
                    if ($one_a) {
                        $options['oauth_verifier'] = $verifier;
                    }
                    $method = strtoupper($this->provider->token_request_method);
                    $response = $this->sendApiCall($url, $method, array(), $options, true);
                    $access_token = AccessToken::fromResponse($response);

                    $this->StoreAccessToken($access_token);
                }
            }
            //we're authorized
            if ($access_token->authorized) {
                return true;
            }
        } else {
            //access_token was null
            $access_token = new AccessToken();
        }
        if (!$access_token->authorized) {
            $url = $this->provider->getUrl('request_token', '', array('scope' => $this->scope));
            $options = array(
                'oauth_callback' => $this->getRedirectUri()
            );
            $method = strtoupper($this->provider->token_request_method);
            $response = $this->sendApiCall($url, $method, array(), $options, true);
            $access_token = AccessToken::fromResponse($response, false);
            $this->storeAccessToken($access_token);
        }
        $url_options = array('oauth_token' => (string) $access_token);
        if (!$one_a) {
            $url_options['oauth_callback'] = $this->getRedirectUri();
        }
        $url = $this->provider->getURL('dialog', '', $url_options);
        Utils::redirect($url);
    }

    private function processOAuth2()
    {
        $token = $this->getAccessToken();
        if ($token instanceof AccessToken && $token->authorized) {
            return true; //we already have a token, so stop here
        }
        $stored_state = $this->getStoredState();
        if (strlen($stored_state) == 0) {
            throw new RuntimeException('No stored state was set.');
        }
        $state = $this->getRequestVar('state');
        if ($state === $stored_state) {
            $code = $this->getRequestVar('code');
            if (empty($code)) {
                $error = $this->getRequestVar('error');
                if ($error != null) {
                    $message = sprintf('An error has occured. The error received id "%s"', $error);
                    throw new UnexpectedValueException($message);
                }
            }
            $this->fetchAccessToken($code);
        } else {
            $values = array(
                'state'        => $stored_state,
                'redirect_uri' => $this->getRedirectUri()
            );
            if (isset($this->scope)) {
                if (is_array($this->scope)) {
                    $values['scope'] = impolode(',', $this->scope);
                } else {
                    $values['scope'] = $this->scope;
                }
            }
            $dialog_url = $this->provider->getUrl('dialog', '', $values);

            //TODO: properly handle redirections using Miny's methods.
            //That way we won't interrupt the normal process.
            Utils::redirect($dialog_url);
        }
    }

    /**
     * Interact with the OAuth provider.
     * This function redirects the user to the service provider and request an access token.
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

    private function versionNotSupported($version)
    {
        $message = sprintf('OAuth %s is not supported.', $version);
        throw new UnexpectedValueException($message);
    }

}
