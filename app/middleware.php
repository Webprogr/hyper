<?php
declare(strict_types=1);

use App\Application\Middleware\SessionMiddleware;
// use App\Application\Middleware\ApiKeyAuthMiddleware;
use Slim\App;

return function (App $app) {
    $app->add(SessionMiddleware::class);
    //$app->add(ApiKeyAuthMiddleware::class);
    $app->addRoutingMiddleware();
    $app->addBodyParsingMiddleware();
    $app->addErrorMiddleware(true, true, true);
};
