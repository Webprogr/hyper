<?php
declare(strict_types=1);

namespace App\Application\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface as Middleware;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

/*
class SessionMiddleware implements Middleware
{
    
    public function process(Request $request, RequestHandler $handler): Response
    {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            session_start();
            $request = $request->withAttribute('session', $_SESSION);
        }

        return $handler->handle($request);
    }
}
*/





use Slim\Exception\HttpForbiddenException;
use Slim\Exception\HttpUnauthorizedException;

class ApiKeyAuthMiddleware implements Middleware
{
    private $config;

    public function __construct($config)
    {
        $this->config = $config;
    }
    public function process(Request $request, RequestHandler $handler): Response
   
     {
        $apiKey = $request->getHeaderLine(HEADER_X_API_KEY);

        if (!$apiKey) {
            throw new HttpUnauthorizedException($request, 'ERROR_401_API_KEY_MISSING');
        }
  /*
        if (!in_array($apiKey, $this->config->api_keys)) {
            throw new HttpForbiddenException($request, 'ERROR_403_API_KEY_MISSING_OR_WRONG');
        }
*/
        // Everything is OK
        return $handler->handle($request);
    }

}

