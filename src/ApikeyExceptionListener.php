<?php

namespace KEIII\SilexApikeyAuth;

use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\LogoutException;
use Symfony\Component\Security\Http\Firewall\ExceptionListener;

/**
 * Apikey exception listener.
 */
class ApikeyExceptionListener extends ExceptionListener
{
    /** @noinspection PhpMissingParentConstructorInspection */
    public function __construct()
    {
        // override parent constructor
    }

    /**
     * {@inheritdoc}
     */
    public function onKernelException(GetResponseForExceptionEvent $event)
    {
        $ex = $event->getException();

        do {
            if ($ex instanceof AuthenticationException) {
                $event->setException(new UnauthorizedHttpException(null, 'Unauthorized'));
            } elseif ($ex instanceof AccessDeniedException) {
                $event->setException(new AccessDeniedHttpException('Forbidden'));
            } elseif ($ex instanceof LogoutException) {
                // do nothing
            }
        } while (null !== ($ex = $ex->getPrevious()));
    }
}
