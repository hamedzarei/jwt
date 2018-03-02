<?php
/**
 * Created by PhpStorm.
 * User: zrhm7232
 * Date: 3/3/18
 * Time: 12:04 AM
 */
require_once(dirname(__FILE__)."/../src/JWT.php");

class JWTTest extends \PHPUnit\Framework\TestCase
{
    public function testCreateToken()
    {
        $jwt = "";
        $jwtClass = new \Zrhm7232\Jwt\JWT();
        $jwt = $jwtClass->createToken();

        $this->assertNotEmpty($jwt);
    }

    public function testInvalidate()
    {
        $app = new \Illuminate\Container\Container();
        $app->singleton('app', 'Illuminate\Container\Container');
        $app->singleton('cache', 'Illuminate\Support\Facades\Cache');
        \Illuminate\Support\Facades\Facade::setFacadeApplication($app);

        $jwt = "";
        $jwtClass = new \Zrhm7232\Jwt\JWT();
        $jwtClass->ttl = 100;
        $jwt = $jwtClass->createToken();
        $status = $jwtClass->invalidateToken($jwt['data']);

        $this->assertArrayHasKey('status', $status);

    }
}