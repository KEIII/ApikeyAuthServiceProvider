<?php

namespace KEIII\SilexApikeyAuth;

use KEIII\SilexApikeyAuth\Interfaces\ApikeyUserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\LockedException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\AdvancedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Authentication provider.
 */
class AuthProvider implements AuthenticationProviderInterface
{
    /**
     * @var string
     */
    private $providerKey;

    /**
     * @var ApikeyUserProviderInterface
     */
    private $userProvider;

    /**
     * Constructor.
     *
     * @param string                      $providerKey
     * @param ApikeyUserProviderInterface $userProvider
     */
    public function __construct(
        $providerKey,
        ApikeyUserProviderInterface $userProvider
    ) {
        $this->providerKey = (string)$providerKey;
        $this->userProvider = $userProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $apikey = $token->getCredentials();

        try {
            $user = $this->userProvider->loadUserByApikey($apikey);
            if (!$user instanceof UserInterface) {
                throw new UsernameNotFoundException();
            }
        } catch (UsernameNotFoundException $ex) {
            throw new AuthenticationException();
        }

        if ($user instanceof AdvancedUserInterface) {
            if (!$user->isAccountNonLocked()) {
                throw new LockedException();
            }

            if (!$user->isEnabled()) {
                throw new DisabledException();
            }
        }

        $token = new ApiKeyToken($this->providerKey, $apikey, $user->getRoles());
        $token->setUser($user);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof ApikeyToken
            && $token->getProviderKey() === $this->providerKey;
    }
}
