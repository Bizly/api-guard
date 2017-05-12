<?php

namespace Chrisbjr\ApiGuard\Http\Middleware;

use App;
use Bizly\Helpers\BizlyHelper;
use Chrisbjr\ApiGuard\Builders\ApiResponseBuilder;
use Chrisbjr\ApiGuard\Models\ApiKey;
use Chrisbjr\ApiGuard\Models\ApiLog;
use Chrisbjr\ApiGuard\Repositories\ApiKeyRepository;
use Chrisbjr\ApiGuard\Repositories\ApiLogRepository;
use Closure;
use Config;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Str;
use Log;
use Route;

class ApiGuard
{

    /**
     * @var ApiKey
     */
    protected $apiKey;

    /**
     * @var ApiLog
     */
    protected $apiLog;

    protected $apiMethods = [];

    /**
     * Handle an incoming request.
     *
     * @param  Request $request
     * @param  Closure $next
     * @param null $serializedApiMethods
     * @return mixed
     * @throws Exception
     */
    public function handle(Request $request, Closure $next, $serializedApiMethods = null)
    {
        // Unserialize parameters
        if (!is_null($serializedApiMethods)) {
            $this->apiMethods = unserialize($serializedApiMethods);
        }

        // Let's instantiate the response class first
        $response = ApiResponseBuilder::build();

        // Let's get the method
        $method = $this->getRouteMethod();

        if (empty($method)) {
            // There is no method
            return $response->errorMethodNotAllowed();
        }

        // We should check if key authentication is enabled for this method
        $keyAuthentication = true;

        if (isset($this->apiMethods[$method]['keyAuthentication']) && $this->apiMethods[$method]['keyAuthentication'] === false) {
            $keyAuthentication = false;
        }

        if ($keyAuthentication === true) {

            $key = $request->header(config('apiguard.keyName', 'X-Authorization'));

            if (empty($key)) {
                // Try getting the key from elsewhere
                $key = $request->get(config('apiguard.keyName', 'X-Authorization'));
            }

            if (empty($key)) {
                // It's still empty!
                return $response->errorUnauthorized('Bizly API Access Denied : Api Key Not Provided.');
            }

            $apiKeyModel = App::make(config('apiguard.models.apiKey', 'Chrisbjr\ApiGuard\Models\ApiKey'));

            if (!$apiKeyModel instanceof ApiKeyRepository) {
                Log::error('[ApiGuard] Your ApiKey model should be an instance of ApiKeyRepository.');
                throw new Exception("You ApiKey model should be an instance of ApiKeyRepository.");
            }

            $this->apiKey = $apiKeyModel->getByKey($key, config('apiguard.rememberApiKeyDuration', 0));

            if (empty($this->apiKey)) {
                return $response->errorUnauthorized('Bizly API Access Denied : Invalid API Key Provided. Please check your key or contact Bizly.');
            }

            // API key exists
            // Check level of API
            if (!empty($this->apiMethods[$method]['level'])) {
                if ($this->apiKey->level < $this->apiMethods[$method]['level']) {
                    return $response->errorForbidden();
                }
            }
        }

        $apiLog = App::make(config('apiguard.models.apiLog', 'Chrisbjr\ApiGuard\Models\ApiLog'));

        if (!$apiLog instanceof ApiLogRepository) {
            Log::error('[ApiGuard] Your ApiLog model should be an instance of ApiLogRepository.');
            throw new Exception("You ApiLog model should be an instance of ApiLogRepository.");
        }

        // Then check the limits of this method
        if (!empty($this->apiMethods[$method]['limits'])) {
            if (config('apiguard.logging', true) === false) {
                Log::warning("[ApiGuard] You specified a limit in the $method method but API logging needs to be enabled in the configuration for this to work.");
            }
            $limits = $this->apiMethods[$method]['limits'];
            // We get key level limits first
            if ($this->apiKey != null && !empty($limits['key'])) {
                $keyLimit = (!empty($limits['key']['limit'])) ? $limits['key']['limit'] : 0;
                if ($keyLimit == 0 || is_integer($keyLimit) == false) {
                    Log::warning("[ApiGuard] You defined a key limit to the " . Route::currentRouteAction() . " route but you did not set a valid number for the limit variable.");
                } else {
                    if (!$this->apiKey->ignore_limits) {
                        // This means the apikey is not ignoring the limits
                        $keyIncrement = (!empty($limits['key']['increment'])) ? $limits['key']['increment'] : config('apiguard.keyLimitIncrement', '1 hour');
                        $keyIncrementTime = strtotime('-' . $keyIncrement);
                        if ($keyIncrementTime == false) {
                            Log::warning("[ApiGuard] You have specified an invalid key increment time. This value can be any value accepted by PHP's strtotime() method");
                        } else {
                            // Count the number of requests for this method using this api key
                            $apiLogCount = $apiLog->countApiKeyRequests($this->apiKey->id, Route::currentRouteAction(), $request->getMethod(), $keyIncrementTime);
                            if ($apiLogCount >= $keyLimit) {
                                Log::warning("[ApiGuard] The API key ID#{$this->apiKey->id} has reached the limit of {$keyLimit} in the following route: " . Route::currentRouteAction());

                                return $response->setStatusCode(429)->withError('You have reached the limit for using this API.', 'GEN-TOO-MANY-REQUESTS');
                            }
                        }
                    }
                }
            }

            // Then the overall method limits
            if (!empty($limits['method'])) {

                $methodLimit = (!empty($limits['method']['limit'])) ? $limits['method']['limit'] : 0;

                if ($methodLimit == 0 || is_integer($methodLimit) == false) {
                    Log::warning("[ApiGuard] You defined a method limit to the " . Route::currentRouteAction() . " route but you did not set a valid number for the limit variable.");
                } else {

                    if ($this->apiKey != null && $this->apiKey->ignore_limits == true) {
                        // then we skip this
                    } else {
                        $methodIncrement = (!empty($limits['method']['increment'])) ? $limits['method']['increment'] : config('apiguard.keyLimitIncrement', '1 hour');
                        $methodIncrementTime = strtotime('-' . $methodIncrement);
                        if ($methodIncrementTime == false) {
                            Log::warning("[ApiGuard] You have specified an invalid method increment time. This value can be any value accepted by PHP's strtotime() method");
                        } else {
                            // Count the number of requests for this method
                            $apiLogCount = $apiLog->countMethodRequests(Route::currentRouteAction(), $request->getMethod(), $methodIncrementTime);
                            if ($apiLogCount >= $methodLimit) {
                                Log::warning("[ApiGuard] The API has reached the method limit of {$methodLimit} in the following route: " . Route::currentRouteAction());

                                return $response->setStatusCode(429)->withError('The limit for using this API method has been reached', 'GEN-TOO-MANY-REQUESTS');
                            }
                        }
                    }
                }
            }
        }

        // End of cheking limits
        if (config('apiguard.logging', true)) {
            // Default to log requests from this action
            $logged = true;

            if (isset($this->apiMethods[$method]['logged']) && $this->apiMethods[$method]['logged'] === false) {
                $logged = false;
            }

            if ($logged) {
                // Log this API request
                $this->apiLog = App::make(config('apiguard.models.apiLog', 'Chrisbjr\ApiGuard\Models\ApiLog'));

                if (isset($this->apiKey)) {
                    $this->apiLog->api_key_id = $this->apiKey->id;
                }

                // TODO : update this for Bizly Needs:
                $user_id = BizlyHelper::current_user()->id ?? null;
                $this->apiLog->create([
                    'api_key_id' => (isset($this->apiKey)) ? $this->apiKey->id : null,
                    'route' => Route::currentRouteAction(),
                    'method' => $request->getMethod(),
                    'params' => json_encode(Input::all()),
                    'ip_address' => $request->getClientIp(),
                    'user_id' => $user_id,
                ]);
            }
        }

        return $next($request);
    }

    private function getRouteMethod()
    {
        $routeArray = Str::parseCallback(Route::currentRouteAction(), null);

        return last($routeArray);
    }

}
