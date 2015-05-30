<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\HTTP;

use Exception;
use OutOfBoundsException;
use RuntimeException;
use UnexpectedValueException;

if (!function_exists('json_decode')) {
    throw new Exception('HTTP Response needs the JSON PHP extension.');
}

/**
 * Response
 *
 * @author Dániel Buga
 */
class Response
{

    const PROCESS_NONE = 0;
    const PROCESS_AUTOMATIC = 1;
    const PROCESS_CUSTOM = 2;

    private $rawResponse;
    private $version;
    private $statusCode;
    private $responseReason;
    private $headers;
    private $body;

    /**
     * @var bool
     */
    private $bodyProcessed = false;

    public function __construct($result)
    {
        $this->rawResponse = $result;
        $this->processMeta($result);
    }

    private function processMeta($result)
    {
        if (strpos($result, "\r\n\r\n")) {
            list($header_part, $this->body) = explode("\r\n\r\n", $result, 2);
        } else {
            $header_part = $result;
        }
        $headers = explode("\r\n", $header_part);
        $status  = array_shift($headers);
        list($version, $code, $reason) = explode(' ', $status, 3);

        $this->version        = $version;
        $this->statusCode     = $code;
        $this->responseReason = $reason;
        $this->headers        = [];

        foreach ($headers as $header) {
            $header = strtolower($header);
            list($name, $info) = explode(':', $header, 2);

            if (!isset($this->headers[$name])) {
                $this->headers[$name] = trim($info);
            } else {
                if (!is_array($this->headers[$name])) {
                    $this->headers[$name] = [$this->headers[$name]];
                }
                $this->headers[$name][] = trim($info);
            }
        }
    }

    protected function processResponseByContentType()
    {
        if (!$this->hasHeader('Content-Type')) {
            return false;
        }
        $type = strtolower(trim(strtok($this->getHeader('Content-Type'), ';')));
        switch ($type) {
            case 'text/javascript':
            case 'application/json':
                return json_decode($this->body, true);

            case 'application/x-www-form-urlencoded':
            case 'text/plain':
            case 'text/html':
                $response = [];
                parse_str($this->body, $response);

                return $response;

            default:
                return $this->body;
        }
    }

    public function processBody($processType = self::PROCESS_AUTOMATIC, callable $callback = null)
    {
        if (!isset($this->body)) {
            return ''; //nothing to process
        }
        if (!$this->bodyProcessed) {
            switch ($processType) {
                case self::PROCESS_NONE:
                    break;

                case self::PROCESS_AUTOMATIC:
                    $this->body = $this->processResponseByContentType();
                    break;

                case self::PROCESS_CUSTOM:
                    $this->body = $callback($this);
                    break;

                default:
                    throw new \UnexpectedValueException("Unknown processing type: \"{$processType}\"");
            }
            $this->bodyProcessed = true;
        }

        return $this->body;
    }

    public function __toString()
    {
        return $this->rawResponse;
    }

    public function getBody()
    {
        return $this->body;
    }

    public function __get($key)
    {
        if (!is_string($key)) {
            $type = gettype($key);
            throw new \UnexpectedValueException("The key must be a string. {$type} given.");
        }
        if (!isset($this->$key)) {
            throw new \RuntimeException("{$key} is not set.");
        }

        return $this->$key;
    }

    public function hasHeader($header)
    {
        $header = strtolower($header);

        return isset($this->headers[$header]);
    }

    public function getHeader($header)
    {
        $header = strtolower($header);
        if (!isset($this->headers[$header])) {
            throw new \OutOfBoundsException("Header not set: {$header}");
        }

        return $this->headers[$header];
    }

    public function getHeaders()
    {
        return $this->headers;
    }

    public function getStatusCode()
    {
        return $this->statusCode;
    }

    public function getResponseReason()
    {
        return $this->responseReason;
    }
}
