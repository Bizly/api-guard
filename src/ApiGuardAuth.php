<?php

namespace Chrisbjr\ApiGuard;

use Chrisbjr\ApiGuard\Contracts\Providers\Auth;
use Chrisbjr\ApiGuard\Repositories\ApiKeyRepository;
use JWTAuth;

class ApiGuardAuth
{

    protected $auth;

    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Authenticate a user via the API key.
     *
     * @param ApiKeyRepository $apiKey
     * @return bool|mixed
     */
    public function authenticate(ApiKeyRepository $apiKey)
    {

        // Problem. The user_id on the api key is not the user_id that we want to use. We desire the user id from JWT token.
        try {
            return JWTAuth::parseToken()->authenticate();
        } catch (\Exception $e) {
            return false;
        }

    }

    /**
     * Determines if we have an authenticated user
     *
     * @return bool
     */
    public function isAuthenticated()
    {
        $user = $this->getUser();

        if (!isset($user)) {
            return false;
        }

        return true;
    }

    /**
     * Get the authenticated user.
     */
    public function getUser()
    {
        try {
            return JWTAuth::parseToken()->authenticate();
        } catch (\Exception $e) {
            return null;
        }
    }

}
