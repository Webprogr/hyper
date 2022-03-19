<?php
namespace App\Application\Actions\User;


use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
final class Test2Controller
{
    
    private $logger;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function __invoke(
        ServerRequestInterface $request, 
        ResponseInterface $response
    ): ResponseInterface {
       $response->getBody()->write(json_encode(['success' => true]));
       $this->logger->warning("message test2 works");
       $this->logger->info('Test2  page handler dispatched');
      
         return $response->withHeader('Content-Type', 'application/json')
                           ->withStatus(422);
    }
}
