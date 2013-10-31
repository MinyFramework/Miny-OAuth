<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use Miny\Log;
use OutOfBoundsException;
use RuntimeException;

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
     * @param array $request
     * @param string $request_path
     * @param Log|null $log
     */
    public function __construct(array $request, $request_path, Log $log = NULL)
    {
        $request['path'] = $request_path;
        $this->request = $request;
        $this->log = $log;
    }

    /**
     * @param string $provider The alias of the provider.
     * @param ProviderDescriptor $pd
     * @throws RuntimeException
     * @return OAuthClient
     */
    public function registerProvider($provider, ProviderDescriptor $pd)
    {
        if (!is_string($provider)) {
            throw new RuntimeException('Parameter "provider" must be of string type.');
        }
        $this->providers[$provider] = $pd;
        return $this->getOAuthObject($provider);
    }

    /**
     * @param string $provider
     * @throws RuntimeException
     */
    public function unregisterProvider($provider)
    {
        if (!is_string($provider)) {
            throw new RuntimeException('Parameter "provider" must be of string type.');
        }
        unset($this->providers[$provider]);
    }

    /**
     * @param string $provider
     * @return OAuthClient
     * @throws OutOfBoundsException
     */
    public function getOAuthObject($provider)
    {
        if (!is_string($provider)) {
            throw new RuntimeException('Provider name must be a string.');
        }
        if (!isset($this->providers[$provider])) {
            throw new OutOfBoundsException(sprintf('Provider "%s" is not set', $provider));
        }
        if (!isset($this->clients[$provider])) {
            $this->clients[$provider] = new OAuthClient($this->providers[$provider], $this->request, $this->log);
        }
        return $this->clients[$provider];
    }

}
