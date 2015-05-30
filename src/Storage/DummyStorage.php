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
class DummyStorage implements AccessTokenStorageInterface
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

    public function &get($key, $remove = true)
    {
        $value =& $this->data[$key];
        if ($remove) {
            $this->remove($key);
        }
        return $value;
    }

    public function has($key)
    {
        return isset($this->data[$key]);
    }

    public function set($key, $value)
    {
        $this->data[$key] = $value;
    }

    public function remove($key)
    {
        unset($this->data[$key]);
    }
}
