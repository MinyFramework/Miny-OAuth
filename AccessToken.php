<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use Modules\OAuth\HTTP\Response;
use Serializable;
use UnexpectedValueException;

/**
 * AccessToken hold all necessary information about an access token.
 *
 * @author Dániel Buga
 */
class AccessToken implements Serializable
{
    public static $default_access_token_type = ''; //? provider specific?
    public $access_token;
    public $refresh_token;
    public $expiry;
    public $authorized = false;
    public $type;
    //OAuth 1.0 specific
    public $secret;

    /**
     *
     * @param array $response
     * @param string $reused_refresh_token
     * @return AccessToken
     */
    public static function fromResponse(Response $response, $authorized = true, $reused_refresh_token = null)
    {
        $data = $response->body;
        if (!isset($data['access_token'])) {
            throw new UnexpectedValueException('Data must contain an access_token.' . print_r($data, 1));
        }
        $access_token = new AccessToken;
        $access_token->access_token = $data['access_token'];
        $access_token->authorized = $authorized;

        if (isset($data['expires']) || isset($data['expires_in'])) {
            $expires_str = isset($data['expires']) ? $data['expires'] : $data['expires_in'];
            $expires = intval($expires_str);
            if ($expires == $expires_str) {
                if ($expires > 0) {
                    $access_token->expiry = gmstrftime('%Y-%m-%d %H:%M:%S', time() + $expires);
                }
            }
        }
        if (isset($data['oauth_expires']) || isset($data['oauth_expires_in'])) {
            $expires_str = isset($data['oauth_expires']) ? $data['oauth_expires'] : $data['oauth_expires_in'];
            $expires = intval($expires_str);
            if ($expires == $expires_str) {
                if ($expires > 0) {
                    $access_token->expiry = gmstrftime('%Y-%m-%d %H:%M:%S', time() + $expires);
                }
            }
        }
        if(isset($data['oauth_token_secret'])) {
            $access_token->secret = $data['secret'];
        }
        if (isset($data['token_type'])) {
            $access_token->type = $data['token_type'];
        } else {
            $access_token->type = self::$default_access_token_type;
        }
        if (isset($data['refresh_token'])) {
            $access_token->refresh_token = $data['refresh_token'];
        } elseif (isset($reused_refresh_token)) {
            $access_token->refresh_token = $reused_refresh_token;
        }
        return $access_token;
    }

    //Serializable interface
    public function serialize()
    {
        return serialize(array(
            'access_token'  => $this->access_token,
            'authorized'    => $this->authorized,
            'expiry'        => $this->expiry,
            'refresh_token' => $this->refresh_token,
            'type'          => $this->type
        ));
    }

    public function unserialize($serialized)
    {
        $array = unserialize($serialized);

        $this->access_token = $array['access_token'];
        $this->authorized = $array['authorized'];
        $this->expiry = $array['expiry'];
        $this->refresh_token = $array['refresh_token'];
        $this->type = $array['type'];
    }

    public function __toString()
    {
        return $this->access_token;
    }

}
