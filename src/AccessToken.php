<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use Modules\OAuth\Exceptions\OAuthException;
use Modules\OAuth\HTTP\Response;
use Serializable;

/**
 * AccessToken hold all necessary information about an access token.
 *
 * @author Dániel Buga
 */
class AccessToken implements Serializable
{
    public static $defaultAccessTokenType = '';

    public $access_token;
    public $refresh_token;
    public $expiry;
    public $authorized = false;
    public $type;

    //OAuth 1.0 specific
    public $secret;

    /**
     *
     * @param array|\Modules\OAuth\HTTP\Response $response
     * @param bool $authorized
     * @param string $reusedRefreshToken
     *
     * @throws Exceptions\OAuthException
     * @return AccessToken
     */
    public static function fromResponse(Response $response, $authorized = true, $reusedRefreshToken = null)
    {
        $data = $response->getBody();
        $accessToken = new AccessToken;
        $accessToken->authorized = $authorized;

        if (isset($data['access_token'])) {

            $accessToken->access_token = $data['access_token'];
            self::setExpiration($data, $accessToken, 'expires', 'expires_in');

        } else if (isset($data['oauth_token'])) {

            $accessToken->access_token = $data['oauth_token'];
            self::setExpiration($data, $accessToken, 'oauth_expires', 'oauth_expires_in');

        } else {
            throw new OAuthException ('Data must contain an access_token.', $data);
        }

        if (isset($data['token_type'])) {
            $accessToken->type = $data['token_type'];
        } else {
            $accessToken->type = self::$defaultAccessTokenType;
        }

        if (isset($data['refresh_token'])) {
            $accessToken->refresh_token = $data['refresh_token'];
        } else if (isset($reusedRefreshToken)) {
            $accessToken->refresh_token = $reusedRefreshToken;
        }

        if (isset($data['oauth_token_secret'])) {
            $accessToken->secret = $data['oauth_token_secret'];
        }
        return $accessToken;
    }

    /**
     * @param $data
     * @param AccessToken $accessToken
     * @param $expiresKey
     * @param $expiresInKey
     * @return array
     */
    public static function setExpiration($data, AccessToken $accessToken, $expiresKey, $expiresInKey)
    {
        if (isset($data[$expiresKey]) || isset($data[$expiresInKey])) {
            $expires_str = isset($data[$expiresKey]) ? $data[$expiresKey] : $data[$expiresInKey];
            $expires     = intval($expires_str);
            if ($expires == $expires_str && $expires > 0) {
                $accessToken->expiry = gmstrftime('%Y-%m-%d %H:%M:%S', time() + $expires);
            }
        }
    }

    public function isExpired()
    {
        if (!isset($this->expiry)) {
            return false;
        }
        return strcmp($this->expiry, gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0;
    }

    //Serializable interface
    /**
     *
     * @return string
     */
    public function serialize()
    {
        return serialize(
            [
                'access_token' => $this->access_token,
                'authorized' => $this->authorized,
                'expiry' => $this->expiry,
                'refresh_token' => $this->refresh_token,
                'type' => $this->type,
                'secret' => $this->secret
            ]
        );
    }

    /**
     *
     * @param string $serialized
     */
    public function unserialize($serialized)
    {
        $array = unserialize($serialized);

        $this->access_token  = $array['access_token'];
        $this->authorized    = $array['authorized'];
        $this->expiry        = $array['expiry'];
        $this->refresh_token = $array['refresh_token'];
        $this->type          = $array['type'];
        $this->secret        = $array['secret'];
    }

    /**
     *
     * @return string
     */
    public function __toString()
    {
        return $this->access_token;
    }
}
