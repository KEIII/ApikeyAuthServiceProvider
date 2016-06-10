# ApikeyAuthServiceProvider

[![Build Status](https://travis-ci.org/KEIII/ApikeyAuthServiceProvider.svg?branch=master)](https://travis-ci.org/KEIII/ApikeyAuthServiceProvider)

By default it accept *x-access-token* header.

## Install
```bash
composer require keiii/silex-apikey-auth
```

## Registering
```php
$app->register(new \KEIII\SilexApikeyAuth\ApikeyAuthServiceProvider(), [
    'security.firewalls' => [
        'api' => [
            'pattern' => '^/api',
            'apikey' => true,
            'users' => $app['user_provider'],
            // ...
        ],
    ],
    // ...
]);
```

## Parameters
- **users**: Instance of \KEIII\SilexApikeyAuth\Interfaces\ApikeyUserProviderInterface.
- **anonymous** (optional): http://silex.sensiolabs.org/doc/master/providers/security.html#allowing-anonymous-users.
- **extractor** (optional): Instance of \KEIII\SilexApikeyAuth\Interfaces\ApikeyExtractorInterface.
