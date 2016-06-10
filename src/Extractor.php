<?php

namespace KEIII\SilexApikeyAuth;

use KEIII\SilexApikeyAuth\Interfaces\ApikeyExtractorInterface;
use Symfony\Component\HttpFoundation\Request;

class Extractor implements ApikeyExtractorInterface
{
    /**
     * {@inheritdoc}
     */
    public function extract(Request $request)
    {
        return (string)$request->headers->get('x-access-token');
    }
}
