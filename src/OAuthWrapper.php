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
    private $providers = array();

    /**
     * @var array
     */
    private $clients = array();

    /**
     * @var array
     */
    private $request;

    /**
     * @var Log
     */
    private $log;

    /**
     * @param Request  $request
     * @param Log|null $log
     */
    public function __construct(Request $request, Log $log = null)
    {
        $requestArray         = $request->get()->toArray();
        $requestArray['path'] = $request->getPath();
        $this->request        = $requestArray;
        $this->log            = $log;
    }

    /**
     * @param string             $provider The alias of the provider.
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
            $this->clients[$provider] = new OAuthClient($this->providers[$provider], $this->request, $this->log);
        }

        return $this->clients[$provider];
    }

}
