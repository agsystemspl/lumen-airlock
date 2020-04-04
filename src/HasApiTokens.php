<?php

namespace AGSystems\Lumen\Airlock;

use Carbon\Carbon;
use Illuminate\Support\Str;

trait HasApiTokens
{
    /**
     * The access token the user is using for the current request.
     *
     * @var \AGSystems\Lumen\Airlock\Contracts\HasAbilities
     */
    protected $accessToken;

    /**
     * Get the access tokens that belong to model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany
     */
    public function tokens()
    {
        return $this->morphMany(Airlock::$personalAccessTokenModel, 'tokenable');
    }

    /**
     * Determine if the current API token has a given scope.
     *
     * @param string $ability
     * @return bool
     */
    public function tokenCan(string $ability)
    {
        return $this->accessToken ? $this->accessToken->can($ability) : false;
    }

    /**
     * Create a new personal access token for the user.
     *
     * @param string $name
     * @param array $abilities
     * @return \AGSystems\Lumen\Airlock\NewAccessToken
     */
    public function createToken(string $name, int $expires_in = null, array $abilities = ['*'])
    {
        $expires_at = null;

        if ($expires_in === null) {
            if (config('airlock.expiration') !== null)
                $expires_at = Carbon::now()->addMinutes(config('airlock.expiration'));
        } else {
            $expires_at = Carbon::now()->addMinutes($expires_in);
        }

        $token = $this->tokens()->create([
            'name' => $name,
            'token' => hash('sha256', $plainTextToken = Str::random(80)),
            'expires_at' => $expires_at,
            'abilities' => $abilities,
        ]);

        return new NewAccessToken($token, $plainTextToken);
    }

    /**
     * Get the access token currently associated with the user.
     *
     * @return \AGSystems\Lumen\Airlock\Contracts\HasAbilities
     */
    public function currentAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Set the current access token for the user.
     *
     * @param \AGSystems\Lumen\Airlock\Contracts\HasAbilities $accessToken
     * @return $this
     */
    public function withAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    public function revoke()
    {
        $this->revoked_at = Carbon::now();
        $this->save();
    }
}
