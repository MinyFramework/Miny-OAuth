<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\HTTP;

use BadMethodCallException;
use Exception;
use Miny\Log\Log;
use Modules\OAuth\Utils;
use RuntimeException;

if (!function_exists('curl_init')) {
    throw new Exception('HTTP Client needs the CURL PHP extension.');
}

/**
 * @author Dániel Buga
 */
class Client
{
    const METHOD_GET = 'GET';
    const METHOD_POST = 'POST';
    const METHOD_PUT = 'PUT';
    const METHOD_DELETE = 'DELETE';
    const USER_AGENT = 'MinyHTTP-Client 1.0';

    private static $log_keys = [
        CURLOPT_URL => 'URL: %s',
        CURLOPT_USERAGENT => 'User Agent: %s',
        CURLOPT_BINARYTRANSFER => 'Binary: %s',
        CURLOPT_PORT => 'Port: %s',
        CURLOPT_HTTPHEADER => 'Headers: %s',
        CURLOPT_TIMEOUT => 'Timeout: %s',
        CURLOPT_CUSTOMREQUEST => 'Method: %s',
        CURLOPT_POSTFIELDS => 'Post fields: %s'
    ];
    private $url;
    private $port;
    private $sslCert;
    private $userAgent;
    private $timeout;
    private $method = Client::METHOD_GET;
    private $headers = ['Expect:'];
    private $postFields = [];
    private $curlHandle;
    private $binary = false;
    private $followLocation = false;
    private $isFileUpload = false;

    /**
     * @var Log
     */
    private $log;

    public function __construct($ssl_cert = null, Log $log = null)
    {
        $this->sslCert = $ssl_cert;
        $this->log     = $log;
    }

    protected function log($message)
    {
        if (isset($this->log)) {
            $args = array_slice(func_get_args(), 1);
            $this->log->write(Log::DEBUG, 'OAuth', $message, $args);
        }
    }

    public function setUrl($url)
    {
        $this->url = $url;
    }

    public function setPort($port)
    {
        $this->port = $port;
    }

    public function setUserAgent($user_agent)
    {
        if (!Utils::isString($user_agent)) {
            throw new BadMethodCallException('User Agent must be a string or object with __toString method.');
        }
        $this->userAgent = $user_agent;
    }

    public function setRequestMethod($method)
    {
        $this->method = $method;
    }

    public function addHeader($header)
    {
        if (!Utils::isString($header)) {
            throw new BadMethodCallException('Header must be a string or object with __toString method.');
        }
        $this->headers[] = $header;
    }

    public function addPostField($field, $value)
    {
        $this->postFields[$field] = $value;
    }

    public function addPostFields(array $fields)
    {
        foreach ($fields as $field => $value) {
            $this->addPostField($field, $value);
        }
    }

    public function addFile($field, $file, $type = null, $filename = true)
    {
        $value = ($filename) ? '@' . $file : $file;
        if ($type) {
            $value .= ';type=' . $type;
        }
        $this->isFileUpload = true;
        $this->addPostField($field, $value);
    }

    public function setBinaryResult($binary)
    {
        $this->binary = (bool)$binary;
    }

    public function setFollowLocation($follow)
    {
        $this->followLocation = (bool)$follow;
    }

    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    /**
     *
     * @param array $curl_options
     *
     * @return Response
     */
    public function send(array $curl_options = [])
    {
        if (!isset($this->curlHandle)) {
            $this->curlHandle = curl_init();
        }
        $ch = $this->curlHandle;

        $curl_options[CURLOPT_URL]            = $this->url;
        $curl_options[CURLOPT_USERAGENT]      = $this->userAgent ?: self::USER_AGENT;
        $curl_options[CURLOPT_RETURNTRANSFER] = true;
        $curl_options[CURLOPT_HEADER]         = true;
        $curl_options[CURLOPT_BINARYTRANSFER] = $this->binary;

        $curl_options[CURLOPT_PORT] = $this->determinePort();

        if (isset($curl_options[CURLOPT_HTTPHEADER])) {
            foreach ($curl_options[CURLOPT_HTTPHEADER] as $header) {
                $this->addHeader($header);
            }
        }
        if ($this->headers) {
            $curl_options[CURLOPT_HTTPHEADER] = $this->headers;
        }
        if ($this->timeout) {
            $curl_options[CURLOPT_TIMEOUT] = $this->timeout;
        }

        $curl_options[CURLOPT_CUSTOMREQUEST] = $this->method;
        if (count($this->postFields) > 0) {
            if ($this->isFileUpload) {
                $curl_options[CURLOPT_POSTFIELDS] = $this->postFields;
            } else {
                $curl_options[CURLOPT_POSTFIELDS] = http_build_query($this->postFields, '', '&');
            }
        }
        $this->logRequest($curl_options);

        return $this->execute($ch, $curl_options);
    }

    private function logRequest(array $options)
    {
        if ($this->log === null) {
            return;
        }
        foreach ($options as $key => $option) {
            if (!isset(self::$log_keys[$key])) {
                continue;
            }
            if (is_array($option)) {
                $option = print_r($option, 1);
            } else {
                if (is_bool($option)) {
                    $option = $option ? 'yes' : 'no';
                }
            }
            $this->log(self::$log_keys[$key], $option);
        }
    }

    private function execute($ch, array $curl_options)
    {
        curl_setopt_array($ch, $curl_options);
        $result = curl_exec($ch);

        if (curl_errno($ch) == CURLE_SSL_CACERT) {
            if ($this->sslCert == null) {
                throw new RuntimeException('SSL certificate file is required but not set.');
            }
            curl_setopt($ch, CURLOPT_CAINFO, $this->sslCert);
            $result = curl_exec($ch);
        }

        if ($result === false) {
            $e = new RuntimeException(curl_error($ch), curl_errno($ch));
            curl_close($ch);
            throw $e;
        }
        curl_close($ch);

        return new Response($result);
    }

    private function determinePort()
    {
        if ($this->port) {
            return $this->port;
        }
        if (substr($this->url, 0, 5) === 'https') {
            return 443;
        }

        return 80;
    }
}
