<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

/**
 * Utility class for the OAuth module
 *
 * @author Dániel
 */
class Utils
{
    /**
     *
     * @param mixed $variable
     * @return boolean
     */
    static public function isString($variable)
    {
        if (is_string($variable)) {
            return true;
        }
        if (is_object($variable) && method_exists($variable, '__toString')) {
            return true;
        }
        return false;
    }

    /**
     * Converts an object to an array.
     * @param mixed $obj
     * @return array
     */
    static public function convertObjectToArray($obj)
    {
        $arr = array();
        foreach ($obj as $k => $v) {
            if (is_object($v) || is_array($v)) {
                $arr[$k] = self::convertObjectToArray($v);
            } else {
                $arr[$k] = $v;
            }
        }
        return $arr;
    }

    /**
     * Redirects the user to $url.
     * @param string $url
     */
    static public function redirect($url)
    {
        Header('HTTP/1.0 302 OAuth Redirection');
        Header('Location: ' . $url);
    }

    /**
     *
     * @param string $url
     * @param array $params
     * @param string $numeric_prefix
     * @param string $separator
     * @return string
     */
    public static function addURLParams($url, array $params, $numeric_prefix = '', $separator = '&')
    {
        $first_separator = (strpos($url, '?') === false) ? '?' : '&';
        return $url . $first_separator . http_build_query($params, $numeric_prefix, $separator);
    }

    /**
     * Simple shorthand method for a common use case.
     * @param string $string
     * @param array $replace
     * @return string
     */
    public static function replaceString($string, array $replace)
    {
        return str_replace(array_keys($replace), $replace, $string);
    }

    /**
     * Encodes a string / array of string as per RFC3986 Section 2.3
     * @param string|array $value
     * @return string|array
     */
    public static function encode($value)
    {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                $value[$k] = $this->encode($v);
            }
            return $value;
        } else {
            return Utils::replaceString($value,
                            array(
                        '%7E' => '~',
                        '+'   => ' '
            ));
        }
    }

}

