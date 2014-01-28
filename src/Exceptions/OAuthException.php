<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\Exceptions;

use RuntimeException;

class OAuthException extends RuntimeException
{
    private $details;

    public function __construct($message, $details, $code = 0, Exception $previous = NULL)
    {
        $this->details = $details;
        parent::__construct($message, $code, $previous);
    }

    public function getDetails()
    {
        return $this->details;
    }

}
