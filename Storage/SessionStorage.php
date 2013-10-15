<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\Storage;

use Miny\Session\Session;

/**
 * SessionStorage is the most basic persistance layer possible.
 * It is used to store data that should persist between requests, e.g. OAuth state.
 *
 * @author Dániel Buga
 */
class SessionStorage implements iPersistentStorage
{
    private $session;
    private $provider_name;

    public function __construct($provider_name, Session $session)
    {
        if (!isset($session['oauth'])) {
            $session['oauth'] = array();
        }
        if (!isset($session['oauth'][$provider_name])) {
            $oauth = $session['oauth'];
            $oauth[$provider_name] = array();
            $session['oauth'] = $oauth;
        }

        $this->provider_name = $provider_name;
        $this->session = $session;
    }

    public function __get($key)
    {
        return $this->session['oauth'][$this->provider_name][$key];
    }

    public function __isset($key)
    {
        if(isset($this->session['oauth'][$this->provider_name])) {
            return isset($this->session['oauth'][$this->provider_name][$key]);
        }
        return false;
    }

    public function __set($key, $value)
    {
        $this->session['oauth'][$this->provider_name][$key] = $value;
    }

    public function __unset($key)
    {
        unset($this->session['oauth'][$this->provider_name][$key]);
    }

}

