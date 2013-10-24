<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\HTTP;

use Modules\OAuth\Utils;
use OutOfBoundsException;
use RuntimeException;
use UnexpectedValueException;

/**
 * Response
 *
 * @author Dániel Buga
 */
class Response
{
    private $raw_response;
    private $version;
    private $status_code;
    private $response_reason;
    private $headers;
    private $body;

    const PROCESS_NONE = 0;
    const PROCESS_AUTOMATIC = 1;
    const PROCESS_CUSTOM = 2;

    public function __construct($result)
    {
        $this->raw_response = $result;
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
        $status = array_shift($headers);
        list($version, $code, $reason) = explode(' ', $status, 3);
        $this->version = $version;
        $this->status_code = $code;
        $this->response_reason = $reason;
        $this->headers = array();
        foreach ($headers as $header) {
            $header = strtolower($header);
            list($name, $info) = explode(':', $header, 2);
            if (!isset($this->headers[$name])) {
                $this->headers[$name] = trim($info);
            } else {
                if (!is_array($this->headers[$name])) {
                    $this->headers[$name] = array($this->headers[$name]);
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
                $obj = json_decode($this->body);
                switch (gettype($obj)) {
                    case 'object':
                        return Utils::convertObjectToArray($obj);
                    case 'array':
                        return $obj;
                    default:
                        throw new UnexpectedValueException('Invalid JSON response.');
                }
            case 'application/x-www-form-urlencoded':
            case 'text/plain':
            case 'text/html':
                $response = array();
                parse_str($this->body, $response);
                return $response;
            default:
                return $this->body;
        }
    }

    public function processBody($process_type = self::PROCESS_AUTOMATIC, $callback = null)
    {
        if (!isset($this->body)) {
            return; //nothing to process
        }
        switch ($process_type) {
            case self::PROCESS_NONE:
                break;
            case self::PROCESS_AUTOMATIC:
                $this->body = $this->processResponseByContentType();
                break;
            case self::PROCESS_CUSTOM:
                $this->body = call_user_func($callback, $this->body, $this);
                break;
            default:
                $message = sprintf('Unknown processing type: "%s"', $process_type);
                throw new UnexpectedValueException($message);
        }
        return $this->body;
    }

    public function __toString()
    {
        return $this->raw_response;
    }

    public function __get($key)
    {
        if (!is_string($key)) {
            $message = sprintf('The key must be a string. %s given.', gettype($key));
            throw new UnexpectedValueException($message);
        }
        if (!isset($this->$key)) {
            throw new RuntimeException(sprintf('%s is not set.', $key));
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
            throw new OutOfBoundsException('Header not set: ' . $header);
        }
        return $this->headers[$header];
    }

}
