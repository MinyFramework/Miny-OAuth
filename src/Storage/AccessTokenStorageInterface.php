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
interface AccessTokenStorageInterface
{
    public function set($key, $value);

    public function &get($key, $remove = true);

    public function has($key);

    public function remove($key);
}
