<?php

namespace KEIII\SilexApikeyAuth\Interfaces;

use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Represents a class that loads UserInterface objects from some source for the authentication system.
 */
interface ApikeyUserProviderInterface extends UserProviderInterface
{
    /**
     * Loads the user for the given apikey.
     *
     * This method must throw UsernameNotFoundException if the user is not
     * found.
     *
     * @param string $apikey The apikey
     *
     * @return UserInterface
     *
     * @throws UsernameNotFoundException if the user is not found
     */
    public function loadUserByApikey($apikey);
}
