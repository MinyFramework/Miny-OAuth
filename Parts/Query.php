<?php

/**
 * This file is part of the Miny framework.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version accepted by the author in accordance with section
 * 14 of the GNU General Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @package   Miny/Modules/ORM/Parts
 * @copyright 2012 Dániel Buga <daniel@bugadani.hu>
 * @license   http://www.gnu.org/licenses/gpl.txt
 *            GNU General Public License
 * @version   1.0
 */

namespace Modules\ORM\Parts;

class Query implements \Iterator, \Countable
{
    private $table;
    private $with;
    private $columns;
    private $where;
    private $where_params = array();
    private $having;
    private $having_params = array();
    private $order;
    private $group;
    private $limit;
    private $offset;
    private $lock = false;
    private $rows = array();
    private $single = false;

    public function __construct(Table $table)
    {
        $this->table = $table;
        $this->manager = $table->manager;
    }

    public function with()
    {
        $this->with = func_get_args();
        return $this;
    }

    public function select()
    {
        $this->columns = func_get_args();
        return $this;
    }

    public function where($condition)
    {
        $condition = '(' . $condition . ')';
        $params = func_get_args();
        array_shift($params);
        if (is_null($this->where)) {
            $this->where = $condition;
            $this->where_params = $params;
        } else {
            $this->where .= ' AND ' . $condition;
            $this->where_params = array_merge($this->where_params, $params);
        }
        return $this;
    }

    public function having($condition)
    {
        $condition = '(' . $condition . ')';
        $params = func_get_args();
        array_shift($params);
        if (is_null($this->having)) {
            $this->having = $condition;
            $this->having_params = $params;
        } else {
            $this->having .= ' AND ' . $condition;
            $this->having_params = array_merge($this->having_params, $params);
        }
        return $this;
    }

    public function order($order)
    {
        $this->order = $order;
        return $this;
    }

    public function limit($limit, $offset = 0)
    {
        $this->limit = $limit;
        $this->offset = $offset;
        return $this;
    }

    public function group($group)
    {
        $this->group = $group;
        return $this;
    }

    public function lock($lock = true)
    {
        $this->lock = $lock;
        return $this;
    }

    public function __toString()
    {
        return $this->getQuery();
    }

    public function getQuery()
    {
        $table = $this->table->getTableName();
        if (!empty($this->with)) {
            $descriptor = $this->table->descriptor;
            $table_id = $descriptor->name;
            $table_name = $table;
            $columns = $this->columns ? : $this->table->descriptor->fields;

            $table_join_field = $this->table->getForeignKey($descriptor->name);
            $primary_key = $descriptor->primary_key;
            foreach ($columns as $k => $name) {
                $columns[$k] = $table_name . '.' . $name . ' as ' . $table_id . '_' . $name;
            }

            foreach ($this->with as $name) {
                $relation = $descriptor->getRelation($name);
                $related = $this->table->getRelatedTable($name);
                $related_descriptor = $related->descriptor;
                $related_table = $related->getTableName();
                $related_table_id = $related_descriptor->name;
                $related_primary = $related_descriptor->primary_key;

                foreach ($related_descriptor->fields as $related_field) {
                    $columns[] = $related_table . '.' . $related_field . ' as ' . $related_table_id . '_' . $related_field;
                }

                $join_pattern = ' LEFT JOIN %1$s ON (%1$s.%2$s = %3$s.%4$s)';
                $foreign_key = $this->table->getForeignKey($name);

                if ($relation == TableDescriptor::RELATION_MANY_MANY) {
                    $join_table = $this->table->getJoinTable($name);

                    $table .= sprintf($join_pattern, $join_table, $table_join_field, $table_name, $primary_key);
                    $table .= sprintf($join_pattern, $related_table, $related_primary, $join_table, $foreign_key);
                } else {
                    $table .= sprintf($join_pattern, $related_table, $related_primary, $table_name, $foreign_key);
                }
            }
        } else {
            $columns = $this->columns ? : array('*');
        }
        $sql = sprintf('SELECT %s FROM %s', implode(', ', $columns), $table);
        if (!is_null($this->where)) {
            $sql .= ' WHERE ' . $this->where;
        }
        if (!is_null($this->group)) {
            $sql .= ' GROUP BY ' . $this->group;
        }
        if (!is_null($this->having)) {
            $sql .= ' HAVING ' . $this->having;
        }
        if (!is_null($this->order)) {
            $sql .= ' ORDER BY ' . $this->order;
        }
        if (!is_null($this->limit) && empty($this->with)) {
            $sql .= ' LIMIT ' . $this->limit;
            if (!is_null($this->offset)) {
                $sql .= ' OFFSET ' . $this->offset;
            }
        }
        $sql .= $this->lock ? ' FOR UPDATE' : '';
        return $sql;
    }

    public function execute()
    {
        $stmt = $this->table->manager->connection->prepare($this->getQuery());
        $i = 0;
        foreach ($this->where_params as $param) {
            $stmt->bindValue(++$i, $param);
        }
        foreach ($this->having_params as $param) {
            $stmt->bindValue(++$i, $param);
        }
        $stmt->execute();
        if (empty($this->with)) {
            $rows = $stmt->fetchAll();
            if (empty($rows)) {
                return array();
            }
            if ($this->single || count($rows) == 1) {
                return new Row($this->table, current($rows));
            } else {
                $return = array();
                $pkfield = $this->table->getPrimaryKey();
                foreach ($rows as $row) {
                    if (isset($row[$pkfield])) {
                        $return[$row[$pkfield]] = new Row($this->table, $row);
                    } else {
                        $return[] = new Row($this->table, $row);
                    }
                }
                return $return;
            }
        } else {
            return $this->process($stmt);
        }
    }

    private function process($statement)
    {
        $table_fields = array();
        $relations_fields = array();
        $table = $this->table->descriptor->name;
        $pk_field = $this->table->descriptor->primary_key;
        foreach ($this->table->descriptor->fields as $name) {
            $table_fields[$name] = $table . '_' . $name;
        }
        foreach ($this->with as $name) {
            $relations_fields[$name] = array();
            foreach ($this->table->getRelatedTable($name)->descriptor->fields as $field) {
                $relations_fields[$name][$field] = $name . '_' . $field;
            }
        }
        $return = array();
        $last_pk = NULL;
        $relation_last_pks = array();
        $relations = array();
        $row_num = -1;
        $fetched = 0;
        while ($row = $statement->fetch(\PDO::FETCH_ASSOC)) {
            if ($last_pk != $row[$table_fields[$pk_field]]) {
                if ($this->limit && $fetched == $this->limit) {
                    break;
                }
                if ($this->single && $fetched == 1) {
                    break;
                }
                $rowdata = $this->getFieldsFromRow($row, $table_fields);
                $last_pk = $rowdata[$pk_field];
                ++$row_num;
                if ($this->offset && $row_num < $this->offset) {
                    continue;
                }
                ++$fetched;
                $return[$last_pk] = new Row($this->table, $rowdata);
                $relations[$last_pk] = array();
            }
            foreach ($this->with as $name) {
                $relation_type = $this->table->descriptor->getRelation($name);
                $relation_table = $this->table->getRelatedTable($name);
                $relation_pk = $relation_table->getPrimaryKey();
                $relation_pk_alias = $relations_fields[$name][$relation_pk];

                $relation_pk_value = $row[$relation_pk_alias] ? : NULL;

                if (isset($relation_last_pks[$name]) && $relation_last_pks[$name] == $relation_pk_value) {
                    continue;
                }

                if (!isset($relations[$last_pk][$name])) {
                    $relations[$last_pk][$name] = array();
                }

                if (empty($relation_pk_value)) {
                    continue;
                }

                $relation_last_pks[$name] = $relation_pk_value;
                $data = $this->getFieldsFromRow($row, $relations_fields[$name]);
                $relation_row = new Row($relation_table, $data);
                if ($relation_type == TableDescriptor::RELATION_BELONGS_TO) {
                    //no need to store it in $relations - assign directly
                    $return[$last_pk]->$name = $relation_row;
                } else {
                    $relations[$last_pk][$name][$relation_pk_value] = $relation_row;
                }
            }
        }
        foreach ($relations as $pk => $array) {
            if (isset($return[$pk])) {
                foreach ($array as $name => $data) {
                    $return[$pk]->$name = $data;
                }
            }
        }
        if ($this->single) {
            $return = current($return);
        }
        return $return;
    }

    private function getFieldsFromRow(array $row, array $fields)
    {
        $rowdata = array();
        foreach ($fields as $field => $alias) {
            if (isset($row[$alias])) {
                $rowdata[$field] = $row[$alias];
            }
        }
        return $rowdata;
    }

    public function get($single = true)
    {
        $this->single = $single;
        return $this->execute();
    }

    public function current()
    {
        return current($this->rows);
    }

    public function key()
    {
        return key($this->rows);
    }

    public function next()
    {
        return next($this->rows);
    }

    public function rewind()
    {
        if (empty($this->rows)) {
            $this->rows = $this->execute();
            if (!is_array($this->rows)) {
                $this->rows = array($this->rows);
            }
        }
        reset($this->rows);
    }

    public function valid()
    {
        $val = key($this->rows);
        return $val !== NULL && $val !== false;
    }

    public function count()
    {
        if (empty($this->rows)) {
            $this->rows = $this->execute();
            if (!is_array($this->rows)) {
                $this->rows = array($this->rows);
            }
        }
        return count($this->rows);
    }

}