<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth\Storage;

use Modules\ORM\Parts\Table;

/**
 * @author Dániel Buga
 */
class ORMStorage implements iPersistentStorage
{

    /**
     * @var Table
     */
    private $table;

    /**
     * @var Row
     */
    private $row;

    /**
     * @var int
     */
    private $userId;

    /**
     * @var string
     */
    private $providerName;

    /**
     * @var array
     */
    private $data;

    /**
     * @param string $provider_name
     * @param Table  $table
     * @param        $user_id
     */
    public function __construct($provider_name, Table $table, $user_id)
    {
        $this->table        = $table;
        $this->providerName = $provider_name;
        $this->userId       = $user_id;

        $row = $table->where('user_id = ? and social_network = ?', $user_id, $provider_name)->get();
        if ($row) {
            $this->row  = $row;
            $this->data = unserialize($row['data']);
        } else {
            $this->data = array();
        }

        register_shutdown_function(array($this, 'save'));
    }

    public function save()
    {
        $data = serialize($this->data);
        if (isset($this->row)) {
            $this->row['data'] = $data;
            $this->row->save();
        } else {
            $this->table->insert(
                array(
                    'user_id'        => $this->userId,
                    'social_network' => $this->providerName,
                    'data'           => $data
                )
            );
        }
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
