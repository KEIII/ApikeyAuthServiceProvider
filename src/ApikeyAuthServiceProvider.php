<?php

namespace KEIII\SilexApikeyAuth;

use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Application;
use Silex\Provider\SecurityServiceProvider;
use Symfony\Component\Security\Http\Firewall;

/**
 * Provides apikey security system.
 */
class ApikeyAuthServiceProvider implements ServiceProviderInterface
{
    const KEY = 'apikey';

    /**
     * {@inheritdoc}
     */
    public function register(Container $app)
    {
        if (!$app->offsetExists('security.firewall')) {
            $app->register(new SecurityServiceProvider());
        }

        $app['jwt'] = function (Application $app) {
            return new JWT([
                'issuer' => $app['jwt.issuer'],
                'audience' => $app['jwt.audience'],
            ]);
        };

        $app['security.apikey_extractor'] = function () {
            return new Extractor();
        };

        $app['security.apikey_exception_listener'] = function () {
            return new ApikeyExceptionListener();
        };

        // build apikey firewall services
        $firewallRaw = $app->raw('security.firewall');
        $app['security.firewall'] = function (Application $app) use ($firewallRaw) {
            $firewalls = $app['security.firewalls'];
            foreach ($firewalls as $name => &$firewall) {
                if (!isset($firewall[self::KEY]) || $firewall[self::KEY] !== true) {
                    continue;
                }

                $firewall['stateless'] = true;

                $userProvider = 'security.user_provider.'.$name;
                if (!$app->offsetExists($userProvider)) {
                    $app[$userProvider] = $firewall['users'];
                }

                $extractor = 'security.apikey_extractor.'.$name;
                if (!$app->offsetExists($extractor)) {
                    $app[$extractor] = isset($firewall['extractor']) ? $firewall['extractor'] : $app['security.apikey_extractor'];
                }

                $app['security.exception_listener.'.$name] = $app['security.apikey_exception_listener'];

                // unset
                foreach (['logout', 'pre_auth', 'guard', 'form', 'http', 'remember_me' /*,'anonymous'*/, 'users', 'encoder', 'extractor'] as $key) {
                    unset($firewall[$key]);
                }
            }
            $app['security.firewalls'] = $firewalls;

            return $firewallRaw($app);
        };

        $app['security.authentication_listener.factory.'.self::KEY] = $app->protect(
            function ($name, $options) use ($app) {
                unset($options); // not used

                $provider = 'security.authentication_provider.'.$name.'.'.self::KEY;
                $listener = 'security.authentication_listener.'.$name.'.'.self::KEY;

                $app[$provider] = function (Application $app) use ($name) {
                    return new AuthProvider(
                        $name,
                        $app['security.user_provider.'.$name]
                    );
                };

                $app[$listener] = function (Application $app) use ($name) {
                    return new AuthListener(
                        $name,
                        $app['security.apikey_extractor.'.$name],
                        $app['security.token_storage'],
                        $app['security.authentication_manager']
                    );
                };

                return [
                    $provider,
                    $listener,
                    null, // the entry point id
                    'pre_auth', // the position of the listener in the stack
                ];
            }
        );
    }
}
