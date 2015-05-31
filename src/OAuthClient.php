<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use Modules\OAuth\Exceptions\OAuthException;
use Modules\OAuth\HTTP\Client;
use Modules\OAuth\HTTP\Response;
use UnexpectedValueException;

/**
 * OAuthClient is a client-side class for OAuth 1.0, 1.0a and 2.0 protocols.
 *
 * @author Dániel Buga
 */
abstract class OAuthClient
{
    /**
     * @var Request
     */
    private $request;

    /**
     * @var AccessToken
     */
    private $accessToken;

    /**
     * @var ProviderDescriptor
     */
    private $descriptor;

    /**
     * @param ProviderDescriptor $descriptor
     * @param Request $request
     */
    public function __construct(ProviderDescriptor $descriptor, Request $request)
    {
        $this->request = $request;
        $this->descriptor = $descriptor;
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
        return $this->request->get($name);
    }

    public function getTokenStorage()
    {
        return $this->descriptor->getStorage();
    }

    /**
     * @param AccessToken $token
     */
    public function storeAccessToken(AccessToken $token)
    {
        //$this->log('Storing acces token: %s', $token);
        $this->getTokenStorage()->set('access_token', $token);
        $this->accessToken = $token;
    }

    /**
     * Resets the saved access token.
     */
    public function resetAccessToken()
    {
        //$this->log('Resetting stored acces token.');
        $this->getTokenStorage()->remove('access_token');
        unset($this->accessToken);
    }

    /**
     * @return null|AccessToken
     */
    public function getAccessToken()
    {
        if (!isset($this->accessToken)) {
            $tokenStorage = $this->getTokenStorage();
            if (!$tokenStorage->has('access_token')) {
                return null;
            }
            $this->accessToken = $tokenStorage->get('access_token');
            //$this->log('Retrieving stored access token: %s', $this->accessToken);
        }

        return $this->accessToken;
    }

    public function processResponse(Response $httpResponse, callable $callback = null)
    {
        return $httpResponse->processBody(
            $this->descriptor->httpResponseProcessingType,
            $callback ?: $this->descriptor->httpResponseProcessingCallback
        );
    }

    /**
     * @return string
     */
    protected function getRedirectUri()
    {
        return "http://{$_SERVER['HTTP_HOST']}{$this->getRequestVar('path')}";
    }

    /**
     *
     * @param string $url
     * @param string $method
     * @param array $parameters
     * @param array $options
     *
     * @throws Exceptions\OAuthException
     *
     * @return Response
     */
    public abstract function sendApiCall(
        $url,
        $method = Client::METHOD_GET,
        array $parameters = [],
        array $options = []
    );

    /**
     * @param string $url
     * @param string $method
     * @param array $parameters
     * @param array $options
     *
     * @throws Exceptions\OAuthException
     * @throws \UnexpectedValueException
     * @return Response
     */
    public abstract function call($url, $method = Client::METHOD_GET, array $parameters = [], array $options = []);

    /**
     * Interact with the OAuth provider.
     * This function redirects the user to the service provider and request an access token.
     *
     * @throws OAuthException
     */
    public abstract function process();

    /**
     * @param $dialog_url
     */
    protected function redirect($dialog_url)
    {
        //TODO: properly handle redirections using Miny's methods.
        //That way we won't interrupt the normal process.
        Utils::redirect($dialog_url);
    }
}
