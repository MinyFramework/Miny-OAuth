<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\Storage;

/**
 * DummyStorage is implemented for cases
 * when storing OAuth state is not necessary by the module.
 *
 * @author Dániel Buga
 */
class DummyStorage implements iPersistentStorage
{

    /**
     * @var array
     */
    private $data;

    public function __construct()
    {
        $this->data = [];
    }

    public function toArray()
    {
        return $this->data;
    }

    public function &__get($key)
    {
        return $this->data[$key];
    }

    public function __isset($key)
    {
        return isset($this->data[$key]);
    }

    public function __set($key, $value)
    {
        $this->data[$key] = $value;
    }

    public function __unset($key)
    {
        unset($this->data[$key]);
    }
}
