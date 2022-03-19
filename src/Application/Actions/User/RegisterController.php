<?php
namespace App\Application\Actions\User;


use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class Test1Controller
{
    public function __invoke(
        ServerRequestInterface $request, 
        ResponseInterface $response
    ): ResponseInterface {
        $response->getBody()->write(json_encode(['mysuccess' => true]));

         return $response->withHeader('Content-Type', 'application/json')
                           ->withStatus(422);
    }
}
