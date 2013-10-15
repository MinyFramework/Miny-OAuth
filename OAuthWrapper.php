<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use Miny\HTTP\Request;
use OutOfBoundsException;
use RuntimeException;

/**
 *
 * This class is a wrapper that makes it simple to manage multiple remote OAuth providers.
 *
 * @author Dániel Buga
 */
class OAuthWrapper
{
    private $providers = array();
    private $clients = array();
    private $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     *
     * @param string $provider The alias of the provider.
     * @param \Modules\OAuth\Client\ProviderDescriptor $pd
     * @throws RuntimeException
     */
    public function registerProvider($provider, ProviderDescriptor $pd)
    {
        if (!is_string($provider)) {
            throw new RuntimeException('Parameter "provider" must be of string type.');
        }
        $this->providers[$provider] = $pd;
    }

    public function unregisterProvider($provider)
    {
        if (!is_string($provider)) {
            throw new RuntimeException('Parameter "provider" must be of string type.');
        }
        unset($this->providers[$provider]);
    }

    /**
     *
     * @param string $provider
     * @return OAuthClient
     * @throws OutOfBoundsException
     */
    public function getOAuthObject($provider)
    {
        if (!is_string($provider)) {
            throw new RuntimeException('Parameter "provider" must be of string type.');
        }
        if (!isset($this->providers[$provider])) {
            throw new OutOfBoundsException(sprintf('Provider "%s" is not set', $provider));
        }
        if (!isset($this->clients[$provider])) {
            $this->clients[$provider] = new OAuthClient($this->providers[$provider], $this->request);
        }
        return $this->clients[$provider];
    }

}
