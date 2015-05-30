<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use InvalidArgumentException;
use Modules\OAuth\HTTP\Response;
use Modules\OAuth\Storage\AccessTokenStorageInterface;
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
    private $replaceArray;
    private $otherOptions = [];
    private $urls         = [];

    public $httpResponseProcessingType = Response::PROCESS_AUTOMATIC;
    public $httpResponseProcessingCallback;

    public $clientId;
    public $clientSecret;
    public $apiKey;
    public $scope;

    public $curlOptions = [];
    public $certificateFile;

    /**
     * @var AccessTokenStorageInterface
     */
    private $persistentStorage;

    /**
     * @param AccessTokenStorageInterface $storage
     */
    public function __construct(AccessTokenStorageInterface $storage)
    {
        $this->persistentStorage = $storage;
    }

    /**
     *
     * @return AccessTokenStorageInterface
     */
    public function getStorage()
    {
        return $this->persistentStorage;
    }

    private function getReplacementArray(array $options = [])
    {
        if (!isset($this->replaceArray)) {
            $this->replaceArray = [
                '{CLIENT_ID}' => $this->clientId,
                '{API_KEY}' => $this->apiKey,
                '{CLIENT_SECRET}' => $this->clientSecret
            ];

            foreach ($this->otherOptions as $key => $value) {
                $new_key = '{' . strtoupper($key) . '}';

                $this->replaceArray[$new_key] = $value;
            }
        }
        $return = $this->replaceArray;
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

    public function getScopeString()
    {
        if (is_array($this->scope)) {
            return implode(',', $this->scope);
        } else {
            return $this->scope;
        }
    }

    public function __set($key, $value)
    {
        if (!is_string($key)) {
            throw new InvalidArgumentException('$key must be a string.');
        }

        //Let's unset the array that holds the replace values when something actually changes.
        unset($this->replaceArray);
        if (property_exists($this, $key)) {
            $this->$key = $value;
        } else {
            $this->otherOptions[$key] = $value;
        }
    }

    public function __get($key)
    {
        if (!is_string($key)) {
            throw new InvalidArgumentException('$key must be a string.');
        }
        if (!isset($this->$key) && !isset($this->otherOptions[$key])) {
            throw new RuntimeException("Option {$key }is not set.");
        }
        if (property_exists($this, $key)) {
            return $this->$key;
        } else {
            return $this->otherOptions[$key];
        }
    }

    public function __isset($key)
    {
        return isset($this->$key) || array_key_exists($key, $this->otherOptions);
    }
}
