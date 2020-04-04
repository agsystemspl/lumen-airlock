<?php

namespace AGSystems\Lumen\Airlock;

use Carbon\Carbon;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;

class Guard
{
    use GuardHelpers, Macroable {
        __call as macroCall;
    }

    /**
     * The number of minutes tokens should be allowed to remain valid.
     *
     * @var int
     */
    protected $expiration;

    /**
     * Create a new guard instance.
     *
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param int $expiration
     * @return void
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Determine if the tokenable model supports API tokens.
     *
     * @param mixed $tokenable
     * @return bool
     */
    protected function supportsTokens($tokenable = null)
    {
        return in_array(HasApiTokens::class, class_uses_recursive(
            $tokenable ? get_class($tokenable) : null
        ));
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        $this->user = $user = $this->provider->retrieveByCredentials($credentials);
        return $this->hasValidCredentials($user, $credentials);
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param mixed $user
     * @param array $credentials
     *
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * @return \Illuminate\Contracts\Auth\Authenticatable|void|null
     */
    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        if ($token = $this->request->bearerToken()) {
            $model = Airlock::$personalAccessTokenModel;
            $accessToken = $model::where('token', hash('sha256', $token))->first();

            if (!$accessToken ||
                $accessToken->revoked_at ||
                $this->provider->getModel() != get_class($accessToken->tokenable) ||
                ($accessToken->expires_at && Carbon::now()->gte($accessToken->expires_at))
            ) {
                return;
            }

            return $this->supportsTokens($accessToken->tokenable) ? $this->user = $accessToken->tokenable->withAccessToken(
                tap($accessToken->forceFill(['last_used_at' => Carbon::now()]))->save()
            ) : null;
        }

        return $this->user = null;
    }
}
