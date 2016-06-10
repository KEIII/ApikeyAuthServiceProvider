<?php

namespace KEIII\SilexApikeyAuth;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * Apikey token.
 */
class ApikeyToken extends AbstractToken
{
    /**
     * @var string
     */
    private $providerKey = '';

    /**
     * @var string
     */
    private $apikey = '';

    /**
     * Constructor.
     *
     * @param string $providerKey
     * @param string $apikey      the users API key
     * @param array  $roles       an array of optional user roles
     */
    public function __construct($providerKey, $apikey, array $roles = [])
    {
        parent::__construct($roles);
        parent::setAuthenticated(count($roles) > 0);

        $this->providerKey = (string)$providerKey;
        $this->apikey = (string)$apikey;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthenticated($isAuthenticated)
    {
        if ($isAuthenticated) {
            throw new \LogicException('Cannot set this token to trusted after instantiation.');
        }

        parent::setAuthenticated(false);
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return (string)$this->apikey;
    }

    /**
     * @return string
     */
    public function getProviderKey()
    {
        return (string)$this->providerKey;
    }
}
