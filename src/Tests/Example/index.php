<?php

use KEIII\SilexApikeyAuth\Tests\Example\QueryExtractor;

require_once __DIR__.'/../Mock/app.php';

$app['security.apikey_extractor'] = function () {
    return new QueryExtractor();
};

$app->run();
