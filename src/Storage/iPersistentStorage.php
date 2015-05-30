<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\Storage;

/**
 *
 * @author Dániel Buga
 */
interface iPersistentStorage
{
    public function __set($key, $value);

    public function &__get($key);

    public function __isset($key);

    public function __unset($key);
}
