<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\HTTP;

use BadMethodCallException;
use Modules\OAuth\Utils;
use RuntimeException;

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

    private $url;
    private $port;
    private $ssl_cert;
    private $user_agent;
    private $timeout;
    private $method = Client::METHOD_GET;
    private $headers = array('Expect:');
    private $post_fields = array();
    private $curl_handle;
    private $binary = false;
    private $follow_location = false;

    public function __construct($ssl_cert = null)
    {
        $this->ssl_cert = $ssl_cert;
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
        $this->user_agent = $user_agent;
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
        $this->post_fields[$field] = $value;
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
        $this->addPostField($field, $value);
    }

    public function setBinaryResult($binary)
    {
        $this->binary = (bool) $binary;
    }

    public function setFollowLocation($follow)
    {
        $this->follow_location = (bool) $follow;
    }

    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    /**
     *
     * @param array $curl_options
     * @return Response
     */
    public function send(array $curl_options = array())
    {
        if (!isset($this->curl_handle)) {
            $this->curl_handle = curl_init($this->url);
        }
        $ch = $this->curl_handle;

        $curl_options[CURLOPT_USERAGENT] = $this->user_agent ? : self::USER_AGENT;
        $curl_options[CURLOPT_RETURNTRANSFER] = true;
        $curl_options[CURLOPT_HEADER] = true;
        $curl_options[CURLOPT_BINARYTRANSFER] = $this->binary;

        if ($this->port) {
            $curl_options[CURLOPT_PORT] = $this->port;
        } else {
            if (substr($this->url, 0, 5) === 'https') {
                $curl_options[CURLOPT_PORT] = 443;
            } else {
                $curl_options[CURLOPT_PORT] = 80;
            }
        }
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

        switch ($this->method) {
            case self::METHOD_GET:
                break;
            case self::METHOD_POST:
                $curl_options[CURLOPT_POST] = 1;
                break;
            default:
                $curl_options[CURLOPT_CUSTOMREQUEST] = $this->method;
                break;
        }
        if (count($this->post_fields) > 0) {
            $curl_options[CURLOPT_POSTFIELDS] = $this->post_fields;
        }
        return $this->execute($ch, $curl_options);
    }

    private function execute($ch, array $curl_options)
    {
        curl_setopt_array($ch, $curl_options);
        $result = curl_exec($ch);

        if (curl_errno($ch) == CURLE_SSL_CACERT) {
            if ($this->ssl_cert == NULL) {
                throw new RuntimeException('SSL certificate file is required but not set.');
            }
            curl_setopt($ch, CURLOPT_CAINFO, $this->ssl_cert);
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

}
