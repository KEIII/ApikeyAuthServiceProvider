#!/usr/bin/env bash

# Fix code style in php files used PHP-CS-Fixer
# https://github.com/FriendsOfPHP/PHP-CS-Fixer

DIR=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)
${DIR}/vendor/bin/php-cs-fixer fix --config-file=${DIR}/.php_cs
