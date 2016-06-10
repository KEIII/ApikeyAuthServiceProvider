<?php

namespace KEIII\SilexApikeyAuth;

use KEIII\SilexApikeyAuth\Interfaces\ApikeyExtractorInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

/**
 * Authentication listener.
 */
class AuthListener implements ListenerInterface
{
    /**
     * @var string
     */
    private $providerKey;

    /**
     * @var ApikeyExtractorInterface
     */
    private $extractor;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var AuthenticationManagerInterface
     */
    private $authenticationManager;

    /**
     * Constructor.
     *
     * @param string                         $providerKey
     * @param ApikeyExtractorInterface       $extractor
     * @param TokenStorageInterface          $tokenStorage
     * @param AuthenticationManagerInterface $authenticationManager
     */
    public function __construct(
        $providerKey,
        ApikeyExtractorInterface $extractor,
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager
    ) {
        $this->providerKey = $providerKey;
        $this->authenticationManager = $authenticationManager;
        $this->extractor = $extractor;
        $this->tokenStorage = $tokenStorage;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event)
    {
        $apikey = $this->extractor->extract($event->getRequest());

        if (empty($apikey)) {
            // unset previous token
            if ($this->tokenStorage->getToken() instanceof ApikeyToken) {
                $this->tokenStorage->setToken(null);
            }

            return;
        }

        $preAuthToken = new ApikeyToken($this->providerKey, $apikey);
        $token = $this->authenticationManager->authenticate($preAuthToken);
        $this->tokenStorage->setToken($token);
    }
}
