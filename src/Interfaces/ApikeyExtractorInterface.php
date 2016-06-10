<?php

namespace KEIII\SilexApikeyAuth\Interfaces;

use Symfony\Component\HttpFoundation\Request;

interface ApikeyExtractorInterface
{
    /**
     * Extract apikey from request.
     *
     * @param Request $request
     *
     * @return string The apikey
     */
    public function extract(Request $request);
}
