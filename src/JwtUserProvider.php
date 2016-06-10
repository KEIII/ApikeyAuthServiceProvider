<?php

namespace KEIII\SilexApikeyAuth;

use KEIII\SilexApikeyAuth\Interfaces\ApikeyUserProviderInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * JWT user provider.
 */
class JwtUserProvider implements ApikeyUserProviderInterface
{
    /**
     * @var JWT
     */
    private $jwt;

    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * Constructor.
     *
     * @param JWT                   $jwt
     * @param UserProviderInterface $userProvider
     */
    public function __construct(JWT $jwt, UserProviderInterface $userProvider)
    {
        $this->jwt = $jwt;
        $this->userProvider = $userProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByApikey($apikey)
    {
        $token = $this->jwt->parse($apikey);
        $username = $token->getClaim('username');
        $user = $this->userProvider->loadUserByUsername($username);

        if (!$this->jwt->verify($token, $user->getPassword())) {
            throw new UsernameNotFoundException();
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        throw new \LogicException();
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        // The token is sent in each request,
        // so authentication can be stateless. Throwing this exception
        // is proper to make things stateless
        throw new UnsupportedUserException();
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return $this->userProvider->supportsClass($class);
    }
}
