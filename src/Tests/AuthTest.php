<?php

namespace Tests;

use KEIII\SilexApikeyAuth\JWT;
use Silex\WebTestCase;

/**
 * TestAuth.
 */
class AuthTest extends WebTestCase
{
    /**
     * {@inheritdoc}
     */
    public function createApplication()
    {
        return require __DIR__.'/Mock/app.php';
    }

    public function testResponse()
    {
        /** @var JWT $jwt */
        $jwt = $this->app['jwt'];
        $jwtJohn = (string)$jwt->create('John', 'foo');
        $jwtAnna = (string)$jwt->create('Anna', 'bar');
        $badJwt = (string)$jwt->create('John', 'foo_bar');

        $requests = [
            [
                'uri' => '/api/foo/public/',
                'jwt' => null,
                'assert' => [
                    'code' => 200,
                    'text' => 'Hello, anon.!',
                ],
            ],
            [
                'uri' => '/api/foo/public/',
                'jwt' => $jwtJohn,
                'assert' => [
                    'code' => 200,
                    'text' => 'Hello, John!',
                ],
            ],
            [
                'uri' => '/api/foo/secured/',
                'jwt' => $jwtJohn,
                'assert' => [
                    'code' => 200,
                    'text' => 'Hello, John!',
                ],
            ],
            [
                'uri' => '/api/foo/secured/',
                'jwt' => $jwtAnna,
                'assert' => [
                    'code' => 401,
                    'text' => 'Unauthorized',
                ],
            ],
            [
                'uri' => '/api/foo/secured/',
                'jwt' => $badJwt,
                'assert' => [
                    'code' => 401,
                    'text' => 'Unauthorized',
                ],
            ],
            [
                'uri' => '/api/foo/secured/',
                'jwt' => null,
                'assert' => [
                    'code' => 403,
                    'text' => 'Forbidden',
                ],
            ],
            [
                'uri' => '/api/bar/public/',
                'jwt' => $jwtAnna,
                'assert' => [
                    'code' => 200,
                    'text' => 'Hello, Anna!',
                ],
            ],
            [
                'uri' => '/api/bar/secured/',
                'jwt' => $jwtJohn,
                'assert' => [
                    'code' => 401,
                    'text' => 'Unauthorized',
                ],
            ],
        ];

        $client = $this->createClient();
        foreach ($requests as $request) {
            $server = ($request['jwt'] !== null) ? ['HTTP_X_ACCESS_TOKEN' => $request['jwt']] : [];
            $crawler = $client->request('GET', $request['uri'], [], [], $server);
            $this->assertEquals($request['assert']['code'], $client->getResponse()->getStatusCode());
            $this->assertEquals($request['assert']['text'], $crawler->text());
        }
    }
}
