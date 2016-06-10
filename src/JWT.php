<?php

namespace KEIII\SilexApikeyAuth;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;

class JWT
{
    /**
     * @var array
     */
    private $config;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var Parser
     */
    private $parser;

    /**
     * Constructor.
     *
     * @param array $config
     */
    public function __construct(array $config)
    {
        $this->config = $config;
        $this->signer = new Sha256();
        $this->parser = new Parser();
    }

    /**
     * Create a new JWT token.
     *
     * @param string $username
     * @param string $key
     *
     * @return Token
     */
    public function create($username, $key)
    {
        return (new Builder())
            ->setIssuer($this->config['issuer']) // iss
            ->setAudience($this->config['audience']) // aud
            ->setId(mt_rand(), true) // jti
            ->setIssuedAt(time()) // iat
            ->setNotBefore(time() + 60) // nbf
            ->setExpiration(time() + 3600 * 14) // nbf
            ->set('username', (string)$username)
            ->sign($this->signer, (string)$key)
            ->getToken()
        ;
    }

    /**
     * Parses the JWT and returns a token.
     *
     * @param string $str
     *
     * @return Token
     */
    public function parse($str)
    {
        return $this->parser->parse((string)$str);
    }

    /**
     * Verify if the key matches with the one that created the signature.
     *
     * @param Token  $token
     * @param string $key
     *
     * @return bool
     */
    public function verify(Token $token, $key)
    {
        return $token->verify($this->signer, (string)$key);
    }
}
