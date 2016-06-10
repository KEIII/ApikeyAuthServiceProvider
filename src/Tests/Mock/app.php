<?php

use KEIII\SilexApikeyAuth\ApikeyAuthServiceProvider;
use KEIII\SilexApikeyAuth\JwtUserProvider;
use Silex\Application;
use Symfony\Component\Debug\Debug;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\UserInterface;

$loader = require_once __DIR__.'/../../../vendor/autoload.php';
Debug::enable();
$app = new Application(['debug' => true]);
$app->register(new ApikeyAuthServiceProvider(), [
    'security.firewalls' => [
        'api_foo' => [
            'pattern' => '^/api/foo',
            'anonymous' => true,
            'apikey' => true,
            'users' => function (Application $app) {
                return new JwtUserProvider($app['jwt'], new InMemoryUserProvider([
                    'John' => [
                        'roles' => ['ROLE_USER'],
                        'password' => 'foo',
                    ],
                ]));
            },
        ],
        'api_bar' => [
            'pattern' => '^/api/bar',
            'apikey' => true,
            'users' => function (Application $app) {
                return new JwtUserProvider($app['jwt'], new InMemoryUserProvider([
                    'Anna' => [
                        'roles' => ['ROLE_USER'],
                        'password' => 'bar',
                    ],
                ]));
            },
        ],
    ],
    'security.access_rules' => [
        ['^/api/(foo|bar)/public', 'IS_AUTHENTICATED_ANONYMOUSLY'],
        ['^/api', 'ROLE_USER'],
    ],
    'jwt.issuer' => '',
    'jwt.audience' => '',
]);

$app->get('/api/{area}/{security}/', function () use ($app) {
    $name = $app['user'] instanceof UserInterface ? $app['user']->getUsername() : 'anon.';

    return 'Hello, '.$name.'!';
});

$app->error(function (\Exception $ex) {
    $statusCode = ($ex instanceof HttpException) ? $ex->getStatusCode() : ($ex->getCode() ?: 500);

    return new Response($ex->getMessage(), $statusCode);
});

return $app;
