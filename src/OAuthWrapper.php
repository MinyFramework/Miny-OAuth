<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use InvalidArgumentException;
use Miny\HTTP\Request as MinyRequest;
use Miny\Log\Log;
use Modules\OAuth\Exceptions\OAuthException;
use OutOfBoundsException;

/**
 * This class is a wrapper that makes it simple to manage multiple remote OAuth providers.
 *
 * @author Dániel Buga
 */
class OAuthWrapper
{
    /**
     * @var array
     */
    private $clientMap = [];

    /**
     * @var ProviderDescriptor[]
     */
    private $providers = [];

    /**
     * @var OAuthClient[]
     */
    private $clients = [];

    /**
     * @var Request
     */
    private $request;

    /**
     * @var Log
     */
    private $log;

    /**
     * @param MinyRequest $request
     * @param Log|null $log
     */
    public function __construct(MinyRequest $request, Log $log = null)
    {
        //TODO: decouple from Miny Request object
        $this->request        = new Request($request->getPath(), $request->get()->toArray());
        $this->log            = $log;
    }

    public function registerClient($providerClass, $clientClass)
    {
        if (!is_string($providerClass)) {
            throw new InvalidArgumentException('$providerClass must be a string.');
        }
        if (!is_string($clientClass)) {
            throw new InvalidArgumentException('$clientClass must be a string.');
        }
        $this->clientMap[$providerClass] = $clientClass;
    }

    /**
     * @param string $provider The alias of the provider.
     * @param ProviderDescriptor $pd
     *
     * @throws InvalidArgumentException
     * @return OAuthClient
     */
    public function registerProvider($provider, ProviderDescriptor $pd)
    {
        if (!is_string($provider)) {
            throw new InvalidArgumentException('$provider must be a string.');
        }
        $this->providers[$provider] = $pd;

        return $this->getOAuthObject($provider);
    }

    /**
     * @param string $provider
     *
     * @throws InvalidArgumentException
     */
    public function unregisterProvider($provider)
    {
        if (!is_string($provider)) {
            throw new InvalidArgumentException('$provider must be a string.');
        }
        unset($this->providers[$provider]);
    }

    /**
     * @param string $provider
     *
     * @throws \OutOfBoundsException
     * @throws \InvalidArgumentException
     * @return OAuthClient
     */
    public function getOAuthObject($provider)
    {
        if (!is_string($provider)) {
            throw new InvalidArgumentException('$provider must be a string.');
        }
        if (!isset($this->providers[$provider])) {
            throw new OutOfBoundsException("Provider \"{$provider}\" is not set");
        }
        if (!isset($this->clients[$provider])) {
            $this->clients[$provider] = $this->createClient($provider);
        }

        return $this->clients[$provider];
    }

    /**
     * @param $provider
     * @return OAuthClient
     */
    public function createClient($provider)
    {
        $descriptor = $this->providers[$provider];
        $class      = get_class($descriptor);

        if (!isset($this->clientMap[$class])) {
            throw new OAuthException("Invalid provider class: {$class}");
        }

        $clientClass = $this->clientMap[$class];
        if (!$clientClass instanceof OAuthClient) {
            throw new OAuthException("Invalid clinet class: {$clientClass}");
        }

        return new $clientClass($descriptor, $this->request, $this->log);
    }
}
