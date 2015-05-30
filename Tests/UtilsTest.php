<?php

namespace Modules\OAuth;

class UtilsTest extends \PHPUnit_Framework_TestCase
{
    public function testIsString()
    {
        $this->assertTrue(Utils::isString('string'));
        $this->assertTrue(Utils::isString(new AccessToken()));
        $this->assertFalse(Utils::isString(new \stdClass()));
        $this->assertFalse(Utils::isString(5));
        $this->assertFalse(Utils::isString(5.2));
        $this->assertFalse(Utils::isString(true));
    }

    public function testConvertObjectToArray()
    {
        $obj = new \stdClass();

        $obj->foo      = 'bar';
        $obj->bar      = new \stdClass();
        $obj->bar->baz = 'foobar';

        $array = [
            'foo' => 'bar',
            'bar' => ['baz' => 'foobar']
        ];

        $this->assertEquals($array, Utils::convertObjectToArray($obj));
    }
}
