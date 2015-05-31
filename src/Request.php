<?php

namespace Modules\OAuth;

class Request
{
    private static $allowedParams = [
        'code',
        'error',
        'state',
        'oauth_token',
        'oauth_verifier',
        'denied',
        'path'
    ];

    private $params = [];

    public function __construct($path, array $params)
    {
        $this->params         = array_intersect_key($params, self::$allowedParams);
        $this->params['path'] = $path;
    }

    public function get($key)
    {
        if (!in_array($key, self::$allowedParams)) {
            throw new \InvalidArgumentException("Request variable \"{$key}\" does not exist.");
        }

        return isset($this->params[$key]) ? $this->params[$key] : null;
    }

    public function isHTTPS()
    {
        return isset($_SERVER['HTTPS']) && !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    }
}