<?php

namespace KEIII\SilexApikeyAuth\Tests\Example;

use KEIII\SilexApikeyAuth\Interfaces\ApikeyExtractorInterface;
use Symfony\Component\HttpFoundation\Request;

class QueryExtractor implements ApikeyExtractorInterface
{
    /**
     * {@inheritdoc}
     */
    public function extract(Request $request)
    {
        return (string)$request->get('apikey');
    }
}
