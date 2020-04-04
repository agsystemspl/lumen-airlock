<?php

namespace AGSystems\Lumen\Airlock;

use Illuminate\Support\ServiceProvider;
use Laravel\Lumen\Application;

class AirlockServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->configure('airlock');

        $path = realpath(__DIR__ . '/../config/config.php');
        $this->mergeConfigFrom($path, 'airlock');

    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->registerMigrations();

            $this->publishes([
                __DIR__ . '/../database/migrations' => database_path('migrations'),
            ], 'airlock-migrations');

            $this->publishes([
                __DIR__ . '/../config/config.php' => $this->app->configPath('airlock.php'),
            ], 'airlock-config');
        }

        $this->configureGuard();
    }

    /**
     * Register Airlock's migration files.
     *
     * @return void
     */
    protected function registerMigrations()
    {
        if (Airlock::shouldRunMigrations()) {
            return $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        }
    }

    /**
     * Configure the Airlock authentication guard.
     *
     * @return void
     */
    protected function configureGuard()
    {
        //
        $this->app['auth']->extend('airlock', function (Application $app, $name, array $config) {
            return new Guard(
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );
        });
    }
}
