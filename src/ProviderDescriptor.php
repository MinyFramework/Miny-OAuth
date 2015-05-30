<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use InvalidArgumentException;
use Modules\OAuth\HTTP\Client;
use Modules\OAuth\HTTP\Response;
use Modules\OAuth\Storage\iPersistentStorage;
use OutOfBoundsException;
use RuntimeException;
use UnexpectedValueException;

/**
 * This class is a simple descriptor class that holds information about
 * an OAuth server.
 *
 * @author Dániel Buga
 */
class ProviderDescriptor
{
    private $version;
    private $other_options = [];
    private $replace_array;
    private $http_response_processing_type = Response::PROCESS_AUTOMATIC;
    private $http_response_processing_callback;
    private $scope;

    /**
     *
     * @var iPersistentStorage
     */
    private $persistent_storage;
    private $urls = [];
    private $client_id;
    private $client_secret;
    private $api_key;
    private $curl_options;
    private $default_access_token_type;
    private $certificate_file;

    /**
     * These are not used in OAuth 2.0
     */
    private $signature_method = OAuthClient::SIGNATURE_HMAC_SHA1;
    private $token_request_method = Client::METHOD_GET;
    private $accept = '*/*';
    private $url_parameters = false;
    private $post_values_in_uri = false;
    private $authorization_header = false;

    /**
     *
     * @param iPersistentStorage $persistent_storage
     */
    public function __construct(iPersistentStorage $persistent_storage)
    {
        $this->persistent_storage = $persistent_storage;
    }

    /**
     *
     * @return iPersistentStorage
     */
    public function getStorage()
    {
        return $this->persistent_storage;
    }

    private function getReplacementArray(array $options = [])
    {
        if (!isset($this->replace_array)) {
            $this->replace_array = [
                '{CLIENT_ID}' => $this->client_id,
                '{API_KEY}' => $this->api_key,
                '{CLIENT_SECRET}' => $this->client_secret
            ];

            foreach ($this->other_options as $key => $value) {
                $new_key = '{' . strtoupper($key) . '}';

                $this->replace_array[$new_key] = $value;
            }
        }
        $return = $this->replace_array;
        foreach ($options as $key => $value) {
            $new_key          = '{' . strtoupper($key) . '}';
            $return[$new_key] = $value;
        }

        return $return;
    }

    public function addUrl($name, $url)
    {
        if (!is_string($name)) {
            throw new UnexpectedValueException('$name must be a string.');
        }
        if (!is_string($url)) {
            throw new UnexpectedValueException('$url must be a string.');
        }
        $this->urls[$name] = $url;
    }

    /**
     *
     * @param string $name
     * @param string $path
     * @param array $options
     * @param array $parameters
     *
     * @throws \OutOfBoundsException
     * @throws \UnexpectedValueException
     * @return string
     */
    public function getUrl($name, $path = '', array $options = [], array $parameters = null)
    {
        if (!is_string($name)) {
            throw new UnexpectedValueException('$name must be a string.');
        }
        if (!isset($this->urls[$name])) {
            throw new OutOfBoundsException("URL \"{$name}\" is not set.");
        }
        $arr = $this->getReplacementArray($options);
        $url = $this->urls[$name];
        if (strlen($path) > 0) {
            if ($path[0] == '/') {
                $url = rtrim($url, '/');
            }
            $url = $url . $path;
        }
        if (!empty($parameters)) {
            $url = Utils::addURLParams($url, $parameters);
        }

        return strtr($url, $arr);
    }

    public function __set($key, $value)
    {
        if (!is_string($key)) {
            throw new InvalidArgumentException('$key must be a string.');
        }
        //Check if the value is valid
        //e.g. version can only be one of these: 1.0, 1.0a, 2.0
        switch ($key) {
            case 'version':
                if (!in_array($value, ['1.0', '1.0a', '2.0'])) {
                    throw new UnexpectedValueException('Version can only be 1.0, 1.0a or 2.0');
                }
                break;
            //TODO
        }
        //Let's unset the array that holds the replace values when something actually changes.
        unset($this->replace_array);
        if (property_exists($this, $key)) {
            $this->$key = $value;
        } else {
            $this->other_options[$key] = $value;
        }
    }

    public function __get($key)
    {
        if (!is_string($key)) {
            throw new InvalidArgumentException('$key must be a string.');
        }
        if (!isset($this->$key) && !isset($this->other_options[$key])) {
            throw new RuntimeException("Option {$key }is not set.");
        }
        if (property_exists($this, $key)) {
            return $this->$key;
        } else {
            return $this->other_options[$key];
        }
    }

    public function __isset($key)
    {
        return isset($this->$key) || array_key_exists($key, $this->other_options);
    }
}
