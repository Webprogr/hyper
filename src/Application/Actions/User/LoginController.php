<?php
namespace App\Application\Actions\User;

// use App\Exception\HttpValidationException;
// use App\Model\ValidationException;

use App\Models\db;
use \Firebase\JWT\JWT;
use Tuupola\Base62;
use PDO;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use Slim\Psr7\Response;
use Slim\App;
final class LoginController implements RequestHandlerInterface
{
    private $logger;
    
    private PDO $db;
    public function __construct( LoggerInterface $logger, PDO $db)
    {
        
        $this->logger = $logger;
        $this->pdo = $db;
        
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $data = (array)$request->getParsedBody();
        /* if (! isset($data->email)) {
             exit; //throw new User('The field "email" is required.', 400);
        }
        if (! isset($data->password)) {
            exit;// throw new User('The field "password" is required.', 400);
        } */
        $email = $data["email"];
        $this->logger->info("Creating a new user", ['data' => $data]);

        
        try {
            // $db = $this->get(PDO::class);
            $sql = 'SELECT * FROM users WHERE email=?' ;
            $sth = $this->pdo->prepare($sql);
            //$sth = $this->pdo->query($sql);
             //$sth = $db->query($sql);
             $this->logger->info("These stuffs", ['sth' => $sth]);
             
            //$sth = $db->prepare($sql);
            //$sth->bindParam(':email', $input['email']);
            
            $sth->execute([$email]);
            $this->logger->info("These stuffs", ['sth2' => $sth]);
            $user = $sth->fetch();
            $this->logger->info("These stuffs", ['sth3' => $sth]);
            if(!$user) {
                  $response = new Response();
                  $response->getBody()->write(json_encode(['error' => true,
		            'message' => 'These credentials do not match our records.']));
                     $this->logger->info("These credentials do not match our records", ['data' => $data]);
                   return $response;
                     } 
            if ($user && password_verify($input["pword"], $user['password'])) 
               {
                 $factory = new \PsrJwt\Factory\Jwt();
                 $builder = $factory->builder();
                 $token = $builder->setContentType('JWT')
                    ->setHeaderClaim('info', 'foo')
                    ->setSecret('!secReT$123*')
                    ->setIssuer('webprogrcom')
                    ->setSubject('admins')
                    ->setAudience('https://google.com')
                    ->setExpiration(time() + 3000)
                    ->setNotBefore(time() - 3000)
                    ->setIssuedAt(time())
                    ->setJwtId('123ABC')
                    ->setPayloadClaim('uid', 12)
                    ->build();
                      echo $token->getToken();
                       $token = $token->getToken();
                                $this->logger->info("Slim-API-Skeleton '/'These credentials do  match our records'");        
                         $this->logger->info('User logged in', ['token'=>$token]);        
           $response = new Response();
           $response->$this->getBody()->write(json_encode(['token' => $token,'error' => false,  'message' => 'These credentials  match our records.']));
            return $response;
         
                   } // if end
          else {
          $response = new Response();
          $response->getBody()->write(json_encode(['error' => true,
          'message' => 'These creds do not match our records.'])); 
          $this->logger->warning("Slim-API-Skeleton '/'These credentials do not match our records'");        
           return $response;
            }
        } catch (PDOException $e) {
             $error = array(
              "message" => $e->getMessage()
              );
              $response = new Response();
              $response->getBody()->write(json_encode($error));
              return $response
                ->withHeader('content-type', 'application/json')
                ->withStatus(500);
           }
    }
}
