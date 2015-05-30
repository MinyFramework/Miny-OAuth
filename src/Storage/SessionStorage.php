<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\Storage;

use Miny\HTTP\Session;

/**
 * SessionStorage is the most basic persistance layer possible.
 * It is used to store data that should persist between requests, e.g. OAuth state.
 *
 * @author Dániel Buga
 */
class SessionStorage implements AccessTokenStorageInterface
{
    /**
     * @var Session
     */
    private $session;

    /**
     * @var string
     */
    private $providerName;

    /**
     * @param string $providerName
     * @param Session $session
     */
    public function __construct($providerName, Session $session)
    {
        if (!isset($session['oauth'])) {
            $session['oauth'] = [];
        }
        if (!isset($session['oauth'][$providerName])) {
            $oauth                = $session['oauth'];
            $oauth[$providerName] = [];
            $session['oauth']     = $oauth;
        }

        $this->providerName = $providerName;
        $this->session      = $session;
    }

    public function &get($key, $remove = true)
    {
        $value =& $this->session['oauth'][$this->providerName][$key];
        if ($remove) {
            $this->remove($key);
        }
        return $value;
    }

    public function has($key)
    {
        if (isset($this->session['oauth'][$this->providerName])) {
            return isset($this->session['oauth'][$this->providerName][$key]);
        }
        return false;
    }

    public function set($key, $value)
    {
        $this->session['oauth'][$this->providerName][$key] = $value;
    }

    public function remove($key)
    {
        unset($this->session['oauth'][$this->providerName][$key]);
    }
}
