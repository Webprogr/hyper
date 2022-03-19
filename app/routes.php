<?php

/*Index.php
*Revision 20
*Mar 3, 2021
*rnk
*/
declare(strict_types=1);
use App\Models\db;
use Slim\Interfaces\RouteCollectorInterface;
use App\Application\Actions\User\ListUsersAction;
use App\Application\Actions\User\ViewUserAction;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;

use \Firebase\JWT\JWT;
use Tuupola\Base62;
use Psr\Log\LoggerInterface;
use Slim\App;
use Slim\Interfaces\RouteCollectorProxyInterface as Group;

return function (App $app) {
    
    $app->options('/{routes:.*}', function (Request $request, Response $response) {
        // CORS Pre-Flight OPTIONS Request Handler
        return $response;
    });

    $app->add(function ($request, $handler) {
    $response = $handler->handle($request);
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
   });
   
    $app->get('/', function (Request $request, Response $response) {
        $response->getBody()->write('SORRY! Ask admin');
        return $response;
    });
    
    $app->get('/foo', function (Request $request, Response $response, array $args) {
    $payload = json_encode(['hello' => 'You gotta ask admin'], JSON_PRETTY_PRINT);
    $response->getBody()->write($payload);
    return $response->withHeader('Content-Type', 'application/json');
     });
     
    /*Expected inputemail and inputpass
    * Checked for empty, filter sanitized
    * Logged all
    */
    $app->post('/login', function (Request $request, Response $response, array $args)
    {
          $expected = $request->getParsedBody();
          
          $logger = $this->get(LoggerInterface::class);
          $this->logger = $logger;          
          
          $postemail = filter_var($expected["cuEmail"],FILTER_SANITIZE_EMAIL);
          $postpass= filter_var($expected["cuPassword"], FILTER_SANITIZE_STRING);
          
          if(empty($postpass && $postemail)){
            $this->logger->info('Login fields unfilled', ['payload'=>$expected]);  
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'Required credentials']));
            return $response;
          }
           
        
        $this->logger->info('Login ', ['payload'=>$postemail]);  
        //$data = json_decode(file_get_contents('php://input'), true);
        
        $db = $this->get(PDO::class);
        $sql = "SELECT * FROM hyper_users WHERE cuEmail= :postemail";
        $sth = $db->prepare($sql);
        $sth->bindParam(":postemail", $expected['inputemail']);
        $sth->execute();
        $user = $sth->fetch();
        if (!$user)
        {   $this->logger->info('These credentials do not match our records.', ['payload'=>$user]);  
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'These credentials do not match our records.']));
            return $response;
        }
        if ($user && password_verify($expected["cuPassword"], $user['cuPassword']))
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
            $this->logger->info('JWT Token sent.', ['payload'=>$token]);  
            $response->getBody()
                ->write(json_encode(['token' => $token, 'error' => false, 'message' => 'These credentials  match our records.']));
            return $response;

        } // if end
        else
        {   $this->logger->info('Creds do not match.', ['payload'=>$expected]);  
             
            $response->getBody()
                   ->write(json_encode(['error' => true, 'message' => 'These creds do not match our records.']));
            return $response;
        }
    });
    //Login function ends
  
 /* ------------- User registering ---------------------- */      
/*Expected inputemail and inputpass
    * Checked for empty, filter sanitized
    * Logged all
    */
    
    $app->post('/register', function (Request $request, Response $response, array $args)
    {
        $data = $request->getParsedBody();
        $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger; 
          
        $cuName = filter_var($data['cuName'],FILTER_SANITIZE_STRING);
        $cuEmail =  filter_var($data['cuEmail'],FILTER_SANITIZE_STRING);
        $cuMobileNo = filter_var($data['cuMobileNo'],FILTER_SANITIZE_EMAIL);
        $cuPassword = filter_var($data['cuPassword'],FILTER_SANITIZE_STRING);
        $cuDob = filter_var($data['cuDob'],FILTER_SANITIZE_STRING);
        $cuGender = filter_var($data['cuGender'],FILTER_SANITIZE_STRING);
        
        if(empty($cuName && $cuEmail && $cuPassword)){
            $this->logger->info('Registration fields unfilled', ['payload'=>$data]);  
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'Required all registration fields']));
            return $response;
          }
        
        
        $cuName = htmlentities($cuName, ENT_QUOTES, 'UTF-8');
       
        $cuEmail = htmlentities($cuEmail, ENT_QUOTES, 'UTF-8');
        $cuPassword = htmlentities($cuPassword, ENT_QUOTES, 'UTF-8');
        $cuDob = htmlentities($cuDob, ENT_QUOTES, 'UTF-8');
        $cuGender = htmlentities($cuGender, ENT_QUOTES, 'UTF-8');

        // For htmlentities
        $cuName = trim($cuName);
        
        $cuEmail = trim($cuEmail);
        $cuPassword = trim($cuPassword);
        $cuDob = trim($cuDob);
        $cuGender = trim($cuGender);

        // Generate Just a api_key-need not be jwt. We shall do jwt actual on login
        $api_key = implode('-', str_split(substr(strtolower(md5(microtime() . rand(1000, 9999))) , 0, 30) , 6));

        $code = rand(100, 999);

				
				
				$stmt->bindParam("api_key", $api_key);
        $sql = "INSERT INTO hyper_users (cuName, cuEmail, cuMobileNo, password_hash, cuDob, cuGender, api_key) VALUES (:cuName, :cuEmail, :cuMobileNo, :password_hash, :cuDob, :cuGender, :api_key))";
        // Generating password hash

            $password_hash = PassHash::hash($cuPassword);
			
			// Generating API key

			$api_key = $this->generateApiKey($api_key);
        
        try
        {
            $db = $this->get(PDO::class);
            
            $stmt = $db->prepare($sql);
           
				$stmt->bindParam("cuName", $cuName);
				$stmt->bindParam("cuEmail", $cuEmail);
				$stmt->bindParam("cuMobileNo", $cuMobileNo);
				$stmt->bindParam("password_hash", $password_hash);
				$stmt->bindParam("cuDob", $cuDob);
				$stmt->bindParam("cuGender", $cuGender);
            $result = $stmt->execute();
            // Check for successful insertion
            $status = "first";

            if ($result) {

			try {
				
				$sql = "UPDATE hyper_users SET refCode =:code WHERE cuEmail=:cuEmail";
				$stmt = $db->prepare($sql);
				$stmt->bindParam("code", $code);
				$stmt->bindParam("cuEmail", $cuEmail);
				$stmt->execute();
				$db = null; 
				} catch(PDOException $e) {
				echo '{"error":{"text":'. $e->getMessage() .'}}'; 
			}
                
                $db = null;
            $this->logger->info('Registration success', ['payload'=>$data]);  
            $response->getBody()
                ->write(json_encode(['error' => false, 'message' => 'You have registered successfully!']));
            return $response->withHeader('content-type', 'application/json')
                ->withStatus(200); 
            }
            else {
                
                $error = array(
                "message" => $e->getMessage()
            );
            $this->logger->warning('Registration fails', ['payload'=>$error]);  
          
            $response->getBody()
                ->write(json_encode($error));
            return $response->withHeader('content-type', 'application/json')
                ->withStatus(500);
            }
            
            
           
        }
        catch(PDOException $e)
        {
            $error = array(
                "message" => $e->getMessage()
            );
            $this->logger->warning('Registration fails', ['payload'=>$error]);  
          
            $response->getBody()
                ->write(json_encode($error));
            return $response->withHeader('content-type', 'application/json')
                ->withStatus(500);
        }

    });

    /* 
 
 *  Booking
  
 */
 
$app->post('/booking', function (Request $request, Response $response, array $args)
    {   $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger; 
        
        $data = $request->getParsedBody();
        $this->logger->info('Booking appointment', ['payload'=>$data]);  
      
        
        if(!empty($data['type'])){
         $type = filter_var($data['type'],FILTER_SANITIZE_STRING);
         $type = htmlentities($treatment_type, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['cuAddress'])){
         $cuAddress= filter_var($data['cuAddress'],FILTER_SANITIZE_STRING);
         $cuAddress = htmlentities($chosenAppoDate, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['houseNo'])){
         $houseNo= filter_var($data['houseNo'],FILTER_SANITIZE_STRING);
         $houseNo = htmlentities($clinic_id, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['packageDetails'])){
         $packageDetails= filter_var($data['packageDetails'],FILTER_SANITIZE_STRING);
         $packageDetails = htmlentities($app_time, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['packLength'])){
         $packLength= filter_var($data['packLength'],FILTER_SANITIZE_STRING);
         $packLength = htmlentities($app_date, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['packWidth'])){
         $packWidth= filter_var($data['packWidth'],FILTER_SANITIZE_STRING);
         $packWidth = htmlentities($customerId, ENT_QUOTES, 'UTF-8');
         }
         if(!empty($data['packHeight'])){
         $packHeight= filter_var($data['packHeight'],FILTER_SANITIZE_STRING);
         $packHeight = htmlentities($doctor_id, ENT_QUOTES, 'UTF-8');
         }
          if(!empty($data['cuMobileNo'])){
         $cuMobileNo= filter_var($data['cuMobileNo'],FILTER_SANITIZE_STRING);
         $cuMobileNo = htmlentities($totalFees, ENT_QUOTES, 'UTF-8');
         }
          if(!empty($data['quoteId'])){
         $quoteId= filter_var($data['quoteId'],FILTER_SANITIZE_STRING);
         $quoteId = htmlentities($duration, ENT_QUOTES, 'UTF-8');
         }
         
         if(empty($data )){
            $this->logger->warning('No customer id and other params');  
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'No customer id and other params']));
            return $response;
          }
     $status = 1;
     $consult_status = 0;
     $arrive_status = 0;
     $app_id = 0;
       try {
				$db = $this->get(PDO::class);
                   
			    $sql = "INSERT INTO hyper_booking (customerId,type,cuAddress,houseNo,packageDetails,packLength,packWidth,packHeight,cuMobileNo,quoteId,bookingDate) 
				VALUES (:customerId,:type,:cuAddress,:houseNo,:packageDetails, :packLength,:packWidth,:packHeight,:cuMobileNo,:quoteId,:bookingDate";
                $stmt = $db->prepare($sql);
								
				$stmt->bindParam("customerId", $customerId);
				$stmt->bindParam("type", $type);
				$stmt->bindParam("cuAddress", $cuAddress);
				$stmt->bindParam("houseNo", $houseNo);
				$stmt->bindParam("packageDetails", $packageDetails);
				$stmt->bindParam("packLength", $packLength);
				$stmt->bindParam("packWidth", $packWidth);
				$stmt->bindParam("packHeight", $packHeight);
				$stmt->bindParam("cuMobileNo", $cuMobileNo);
				$stmt->bindParam("quoteId", $quoteId);
				$stmt->bindParam("bookingDate", $bookingDate);
				$result = $stmt->execute();
				$app_id = $db->lastInsertId();
				$db = null;
                $this->logger->info('Booking ', ['payload'=>$result]);  
       
                if ($result) { 
                    
                     $response->getBody()
                    ->write(json_encode(['error' => false, 'result'=>$result,'message' => 'Bookservice Form inserted successfully']));
                      return $response->withHeader('content-type', 'application/json')
                          ->withStatus(200);
                   }                 
                    
        } catch(PDOException $e)
              {
               $error = array(
                "message" => $e->getMessage()
               );
               
               $response->getBody()
                ->write(json_encode(['error' => true,'message' => 'Failed to insert form. Please try again' ]));
               return $response->withHeader('content-type', 'application/json')
                ->withStatus(500);
              }
    })->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));
    
    
    
      /* 
 
 *  quoting
  
 */
 
$app->post('/quoting', function (Request $request, Response $response, array $args)
    {   $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger; 
        
        $data = $request->getParsedBody();
       
        
        if(!empty($data['carType'])){
         $carType = filter_var($data['carType'],FILTER_SANITIZE_STRING);
         $carType = htmlentities($carType, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['pickupAddress'])){
         $pickupAddress= filter_var($data['pickupAddress'],FILTER_SANITIZE_STRING);
         $pickupAddress = htmlentities($pickupAddress, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['dropoffAddress'])){
         $dropoffAddress= filter_var($data['dropoffAddress'],FILTER_SANITIZE_STRING);
         $dropoffAddress = htmlentities($dropoffAddress, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['cuLatitude1'])){
         $cuLatitude1= filter_var($data['cuLatitude1'],FILTER_SANITIZE_STRING);
         $cuLatitude1 = htmlentities($cuLatitude1, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['cuLongitude1'])){
         $cuLongitude1= filter_var($data['cuLongitude1'],FILTER_SANITIZE_STRING);
         $cuLongitude1 = htmlentities($cuLongitude1, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['cuLatitude2'])){
         $cuLatitude2= filter_var($data['cuLatitude2'],FILTER_SANITIZE_STRING);
         $cuLatitude2 = htmlentities($cuLatitude2, ENT_QUOTES, 'UTF-8');
         }
         if(!empty($data['cuLongitude2'])){
         $cuLongitude2= filter_var($data['cuLongitude2'],FILTER_SANITIZE_STRING);
         $cuLongitude2 = htmlentities($cuLongitude2, ENT_QUOTES, 'UTF-8');
         }
          if(!empty($data['travelKm'])){
         $travelKm= filter_var($data['travelKm'],FILTER_SANITIZE_STRING);
         $travelKm = htmlentities($travelKm, ENT_QUOTES, 'UTF-8');
         }
          if(!empty($data['travelTiming'])){
         $travelTiming= filter_var($data['travelTiming'],FILTER_SANITIZE_STRING);
         $travelTiming = htmlentities($travelTiming, ENT_QUOTES, 'UTF-8');
         }
     if(!empty($data['hyperPromoCode'])){
         $hyperPromoCode= filter_var($data['hyperPromoCode'],FILTER_SANITIZE_STRING);
         $hyperPromoCode = htmlentities($hyperPromoCode, ENT_QUOTES, 'UTF-8');
         }
          $rate = 2;
    $extra = 50;
    $fix = 65;
    $above = 110;
    $next=55;
    $min=3;
    $cons = 4;
      if (10>$travelKm){

                $cost = $fix; 

              }
              else if (10<$travelKm && 20>$travelKm)
                {
		    $cost = (($travelKm * $rate) + ($extra));
                }
                else if (20<$travelKm && 30>$travelKm)
                {
                    $cost = (($travelKm * $rate) + ($next));
                }
                else if (30<$travelKm && 50>$travelKm)
                {
                    $cost = ((($travelKm - 30) *$cons) + ($above));
                }
                else
                {
                    $cost = ((($travelKm - 50) * $travelTiming) + 130);
                }

               $fare = $cost * 0.11 + $cost;
			  
               $price = round($fare*100)/100;
        
       try {
				$db = $this->get(PDO::class);
                 $sql = "SELECT voucherId from hyper_coupon WHERE hyperPromoCode=:hyperPromoCode";

	  
			    
                $stmt = $db->prepare($sql);
								
				$stmt->bindParam(":hyperPromoCode", $hyperPromoCode);
				
				$stmt->execute();

		$res = $stmt->fetchColumn();
		
   		 if ($res > 0) {

	if($hyperPromoCode == "PSR25"){

	    $totalPrice = $price - 10;

	}else if($hyperPromoCode == "PSR26"){
		
	    $totalPrice = $price - 20;

	}else{
	
            $totalPrice = $price;

	}

	$discountPrice = $totalPrice - $price;
             
             $sql = "INSERT INTO hyper_location (customerId,carType,pickupAddress,dropoffAddress,cuLatitude1,cuLongitude1,cuLatitude2,cuLongitude2,travelKm,travelTiming,bookingDate, price, discountPrice, totalPrice, hyperPromoCode) 
				VALUES (:customerId, :carType, :pickupAddress, :dropoffAddress, :cuLatitude1, :cuLongitude1,:cuLatitude2, :cuLongitude2,:travelKm, :travelTiming, :bookingDate, :price, :discountPrice, :totalPrice, :hyperPromoCode)";

				$stmt = $db->prepare($sql);
				$stmt->bindParam("customerId", $customerId);
				$stmt->bindParam("carType", $carType);
				$stmt->bindParam("pickupAddress", $pickupAddress);
				$stmt->bindParam("dropoffAddress", $dropoffAddress);
				$stmt->bindParam("cuLatitude1", $cuLatitude1);
				$stmt->bindParam("cuLongitude1", $cuLongitude1);
				$stmt->bindParam("cuLatitude2", $cuLatitude2);
				$stmt->bindParam("cuLongitude2", $cuLongitude2);
				$stmt->bindParam("travelKm", $travelKm);
				$stmt->bindParam("travelTiming", $travelTiming);
				$stmt->bindParam("bookingDate", $bookingDate);
				$stmt->bindParam("price", $price);
				$stmt->bindParam("discountPrice", $discountPrice);
				$stmt->bindParam("totalPrice", $totalPrice);
				$stmt->bindParam("hyperPromoCode", $hyperPromoCode);
				$result = $stmt->execute();
                     }else{

	$hyperPromoCode = "null";

	$totalPrice = $price;

	$discountPrice = $totalPrice - $price;

	  $sql = "INSERT INTO hyper_location (customerId,carType,pickupAddress,dropoffAddress,cuLatitude1,cuLongitude1,cuLatitude2,cuLongitude2,travelKm,travelTiming,bookingDate, price, discountPrice, totalPrice, hyperPromoCode) 
				VALUES (:customerId, :carType, :pickupAddress, :dropoffAddress, :cuLatitude1, :cuLongitude1,:cuLatitude2, :cuLongitude2,:travelKm, :travelTiming, :bookingDate, :price, :discountPrice, :totalPrice, :hyperPromoCode)";

				$stmt = $db->prepare($sql);
				$stmt->bindParam("customerId", $customerId);
				$stmt->bindParam("carType", $carType);
				$stmt->bindParam("pickupAddress", $pickupAddress);
				$stmt->bindParam("dropoffAddress", $dropoffAddress);
				$stmt->bindParam("cuLatitude1", $cuLatitude1);
				$stmt->bindParam("cuLongitude1", $cuLongitude1);
				$stmt->bindParam("cuLatitude2", $cuLatitude2);
				$stmt->bindParam("cuLongitude2", $cuLongitude2);
				$stmt->bindParam("travelKm", $travelKm);
				$stmt->bindParam("travelTiming", $travelTiming);
				$stmt->bindParam("bookingDate", $bookingDate);
				$stmt->bindParam("price", $price);
				$stmt->bindParam("discountPrice", $discountPrice);
				$stmt->bindParam("totalPrice", $totalPrice);
				$stmt->bindParam("hyperPromoCode", $hyperPromoCode);
				$result = $stmt->execute();
                     $response->getBody()
                    ->write(json_encode(['error' => false, 'result'=>$result,'message' => 'Location Form inserted successfully']));
                      return $response->withHeader('content-type', 'application/json')
                          ->withStatus(200);
                   }                 
                    
        } catch(PDOException $e)
              {
               $error = array(
                "message" => $e->getMessage()
               );
               
               $response->getBody()
                ->write(json_encode(['error' => true,'message' => 'Failed to insert form. Please try again' ]));
               return $response->withHeader('content-type', 'application/json')
                ->withStatus(500);
              }
    })->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));  
    
    
    
    
     $app->get('/order', function (Request $request, Response $response)
    {
        $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger;
        //$data = $request->getParsedBody();
        $params = $request->getQueryParams('customerId', $default = null);
       
       
        if(empty($params )){
          
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'Required customerId']));
            return $response;
          }
        $customerId= $params['customerId'];
        
        $this->logger->info('Got customerId', ['payload'=>$customerId]);  
       
        $db = $this->get(PDO::class);
        $sth = $db->prepare("SELECT loc.customerId, loc.carType, loc.pickupAddress, loc.dropoffAddress, loc.cuLatitude1, loc.cuLongitude1, loc.cuLatitude2, loc.cuLongitude2,

 loc.price, loc.travelKm, loc.travelTiming , loc.totalPrice , book.type, book.cuAddress, book.houseNo, book.packageDetails,book.packWidth, book.packLength,

 book.packHeight, book.cuMobileNo, book.quoteId, book.bookingDate FROM hyper_booking book INNER JOIN hyper_location loc

ON book.customerId = loc.customerId WHERE book.customerId = $customerId order by loc.locationId DESC, book.bookId DESC LIMIT 1");
        $sth->execute();
        $data = $sth->fetchAll(PDO::FETCH_ASSOC);
        $payload = json_encode($data);
        $this->logger->info('Got order details', ['payload'=>$payload]);  
       
        $response->getBody()
            ->write($payload);
        return $response->withHeader('Content-Type', 'application/json');
    }) ->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));
    
    
    
     $app->get('/orderconfirm', function (Request $request, Response $response)
    {
        $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger;
        //$data = $request->getParsedBody();
        $params = $request->getQueryParams('customerId', $default = null);
       
       
        if(empty($params )){
          
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'Required customerId']));
            return $response;
          }
        $customerId= $params['customerId'];
        
        $this->logger->info('Got customerId', ['payload'=>$customerId]);  
       
        $db = $this->get(PDO::class);
        $sth = $db->prepare("SELECT cfm.orderId,cfm.customerId, cfm.type, cfm.cuAddress, cfm.houseNo, cfm.packageDetails, cfm.packLength, cfm.packWidth, cfm.packHeight, 

cfm.cuMobileNo, cfm.carType,cfm.travelKm, cfm.travelTiming,cfm.pickupAddress ,cfm.dropoffAddress, cfm.cuLatitude1 ,cfm.cuLongitude1,cfm.cuLatitude2 ,

cfm.cuLongitude2,cfm.totalPrice, cfm.quoteId FROM hyper_cnfmbook cfm WHERE cfm.customerId = $customerId order by cfm.orderId DESC LIMIT 1");
        $sth->execute();
        $data = $sth->fetchAll(PDO::FETCH_ASSOC);
        $payload = json_encode($data);
       
        $response->getBody()
            ->write($payload);
        return $response->withHeader('Content-Type', 'application/json');
    }) ->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));
    
    
      $app->get('/driverdetails', function (Request $request, Response $response)
    {
        $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger;
        //$data = $request->getParsedBody();
        $params = $request->getQueryParams('customerId', $default = null);
       
       
        if(empty($params )){
          
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'Required customerId']));
            return $response;
          }
        $customerId= $params['customerId'];
        
        $this->logger->info('Got customerId', ['payload'=>$customerId]);  
       
        $db = $this->get(PDO::class);
        $sth = $db->prepare("SELECT driverId,cuAddress,pickupAddress,dropoffAddress,drLatitude,drLongitude from hyper_driverbook order by deliveryId DESC LIMIT 1");
        $sth->execute();
        $data = $sth->fetchAll(PDO::FETCH_ASSOC);
        $payload = json_encode($data);
       
        $response->getBody()
            ->write($payload);
        return $response->withHeader('Content-Type', 'application/json');
    }) ->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
 $app->post('/changePassByEmail', function (Request $request, Response $response, array $args)
    {   $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger; 
        
        $data = $request->getParsedBody();
        $this->logger->info('changePassByEmail', ['payload'=>$data]);  
       
        
        if(!empty($data['inputID'])){
         $customerId = filter_var($data['inputID'],FILTER_SANITIZE_STRING);
         $customerId = htmlentities($customerId, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['inputOldPassword'])){
         $oldpass = filter_var($data['inputOldPassword'],FILTER_SANITIZE_STRING);
         $oldpass = htmlentities($oldpass, ENT_QUOTES, 'UTF-8');
         }
         if(!empty($data['inputNewPassword'])){
         $newpass = filter_var($data['inputNewPassword'],FILTER_SANITIZE_STRING);
         $newpass = htmlentities($newpass, ENT_QUOTES, 'UTF-8');
         }
          if(!empty($data['inputConPassword'])){
          $conpass = filter_var($data['inputConPassword'],FILTER_SANITIZE_STRING);
          $conpass = htmlentities($conpass, ENT_QUOTES, 'UTF-8');
         }
    if(empty($data )){
            $this->logger->warning('No new and old pass params');  
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'Required new and old pass params']));
            return $response;
          }
    $sql = "SELECT customerId,cuName from hyper_users WHERE cuEmail=:cuEmail AND customerId=:customerId";
    $db = $this->get(PDO::class);
    $stmt = $db->prepare($sql);
    $stmt->bindParam("customerId", $customerId);
    $stmt->execute();
    //  $result = $sth->fetch(PDO::FETCH_ASSOC);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $token = $row["customer_token"];
    if (password_verify($oldpass, $row['cuPassword']))
    {
    /* The password is correct. */
    $login = TRUE;
     }
    if ($login) {
        if ($newpass == $conpass) {
        $newpass1 = password_hash($newpass, PASSWORD_DEFAULT);  //NEEDS PHP 5.5 OR PHP7, NO SALT NEEDED
           //var_dump($newpass1);
           $sql = "UPDATE hyper_users SET cuPassword =:newpass1 WHERE customerId=:customerId";

            try {
                $db = $this->get(PDO::class);
                $stmt = $db->prepare($sql);
                $stmt->bindParam("newpass1", $newpass1);
                $stmt->bindParam("customerId", $customerId);
                $result=$stmt->execute();
                $this->logger->info("Changing Password, ['payload'=>$result]");  
                $db = null;
                $response->getBody()
                ->write(json_encode(['error' => false, 'message' => 'Password changed!']));
                  return $response->withHeader('content-type', 'application/json')
                ->withStatus(200);
            }
            catch(PDOException $e)
           {
            $error = array(
                "message" => $e->getMessage()
            );
            $this->logger->info('Change Password error, try later', ['payload'=>$error]);  
           
            $response->getBody()
                ->write(json_encode($error));
            return $response->withHeader('content-type', 'application/json')
                ->withStatus(500);
           }
        }
       }
    })
        ->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));

/* 
 
   FORGOT cuPassword 
  
 */
 $app->post('/forgotpassbyemail', function (Request $request, Response $response, array $args)
    {   $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger; 
        
        $data = $request->getParsedBody();
        $this->logger->info('forgotPassByEmail', ['payload'=>$data]);  
       
        
        if(!empty($data['cuEmail'])){
         $cuEmail = filter_var($data['cuEmail'],FILTER_SANITIZE_STRING);
         $cuEmail = htmlentities($cuEmail, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['command'])){
         $command = filter_var($data['command'],FILTER_SANITIZE_STRING);
         $command = htmlentities($command, ENT_QUOTES, 'UTF-8');
         }
      if(empty($data )){
            $this->logger->warning('No customer email and other params');  
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'No customer email and other params']));
            return $response;
          }
        $sql = "select customerId from hyper_users where cuEmail=:cuEmail";
        $db = $this->get(PDO::class);
        $stmt = $db->prepare($sql);  
        $stmt->bindParam("cuEmail", $cuEmail);
        $stmt->execute();
        $res = $stmt->fetchColumn();
        
        if ($res > 0) {
         $this->logger->info('res >0');  
         $this->logger->info("res, ['payload'=>$res]"); 
         $selector = bin2hex(random_bytes(8));
         $validator = random_bytes(32);
         $link = "https://www.webprogr.com/webapps/doclab/customer/reset.php?selector=".$selector."&validator=". bin2hex($validator);
         $expries = date("U") + 1800;

        $fgstmt = $db->prepare("DELETE FROM customer_reset WHERE reset_email = :reset_email");
        $fgstmt->bindParam("reset_email", $cuEmail);
        $fgstmt->execute();
       
        $hashedToken = password_hash($validator, PASSWORD_DEFAULT);
        $fgstmt = $db->prepare("INSERT INTO customer_reset (reset_email, reset_selector, reset_token, reset_expires) VALUE (:reset_email,:reset_selector,:reset_token,:reset_expires)");
        $fgstmt->bindParam("reset_email", $cuEmail);
            $fgstmt->bindParam("reset_selector", $selector);
            $fgstmt->bindParam("reset_token", $hashedToken);
            $fgstmt->bindParam("reset_expires", $expries);        
        $fgstmt->execute();
       // $this->logger->info("fgstmt, ['payload'=>$fgstmt]"); 
       
        $db=null;
        
        $t = ""; //what is this?
            $fg_subject = "Reset Password";
            $fg_title = "Reset Password";
            $fg_content = "The activation link is sent to your email id. Click the activation link to change your cuPassword";
        mail($cuEmail, $fg_subject, $fg_title, $fg_content, $link);        $this->logger->info("fgstmt, ['message'=>'The activation link is sent to your email id. Click the activation link to change your cuPassword']"); 
        $response->getBody()
                ->write(json_encode(['error' => false, 'message' => 'The activation link is sent to your email id. Click the activation link to change your cuPassword!']));
            return $response->withHeader('content-type', 'application/json')
                ->withStatus(200);
           
        } 
        else {        
            $this->logger->warning('Forgot Password - system error, try later');  
           
            $response->getBody()
                ->write(json_encode(['error' => true,'message' => 'There has been some error' ]));
            return $response->withHeader('content-type', 'application/json')
                ->withStatus(500);
        }
 });


// CANCEL APPOINTMENT
  $app->post('/appointmentCancel', function (Request $request, Response $response, array $args)
    {   $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger; 
        
        $data = $request->getParsedBody();
        $this->logger->info('Canceling appointment', ['payload'=>$data]);  
       
        
        if(!empty($data['app_id'])){
         $app_id = filter_var($data['app_id'],FILTER_SANITIZE_STRING);
         $app_id = htmlentities($app_id, ENT_QUOTES, 'UTF-8');
         }
        if(empty($data['app_id'] )){
            $this->logger->warning('No appointment id and other params');  
            $response->getBody()
            ->write(json_encode(['error' => true, 'message' => 'No appointment id and other params']));
            return $response;
          }
        
        $db = $this->get(PDO::class);
        $sql = "UPDATE appointment SET status = 2 WHERE app_id =:app_id";
        $stmt = $db->prepare($sql);
        $stmt->bindParam("app_id", $app_id);
        $result = $stmt->execute();
        if ($result) {
             $this->logger->info("All OK, ['message'=>'The appointment cancelled by customer']"); 
                     $response->getBody()
                    ->write(json_encode(['error' => false, 'result'=>$result,'message' => 'APPOINTMENT CANCELLED!']));
                      return $response->withHeader('content-type', 'application/json')
                          ->withStatus(200);
        } else {
            $this->logger->warning("Cancellation fails, ['message'=>'The appointment not cancelled. Sorry please  try again']"); 
                     $response->getBody()
                    ->write(json_encode(['error' => true, 'message' => 'APPOINTMENT NOT CANCELLED, please try again!']));
                      return $response->withHeader('content-type', 'application/json')
                          ->withStatus(500);
        }
 
})->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));


/*
*   PUSH NOTIFICATIONS
*/
 
    $app->post('/pushRegistration', function (Request $request, Response $response, array $args)
    {   $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger; 
        
        $data = $request->getParsedBody();
        $this->logger->info('Canceling appointment', ['payload'=>$data]);  
        $lastInsertId = '';
        $cuEmail ='ab@c';
        
        if(!empty($data['fcmRegId'])){
         $fcmRegId = filter_var($data['fcmRegId'],FILTER_SANITIZE_STRING);
         $fcmRegId = htmlentities($fcmRegId, ENT_QUOTES, 'UTF-8');
         }
        if(!empty($data['apikey'])){
         $apikey = filter_var($data['apikey'],FILTER_SANITIZE_STRING);
         $apikey = htmlentities($apikey, ENT_QUOTES, 'UTF-8');
         }
         if(!empty($data['cuEmail'])){
         $cuEmail = filter_var($data['cuEmail'],FILTER_SANITIZE_STRING);
         $cuEmail = htmlentities($fcmRegId, ENT_QUOTES, 'UTF-8');
         }
       try {
           $db = $this->get(PDO::class);
           $sql = "INSERT INTO push_notifications (id, fcmRegId, apikey,cuEmail, createdOn) 
				VALUES (default, :fcmRegId, :apikey,:cuEmail, default)";

				$stmt = $db->prepare($sql);				
				$stmt->bindParam("fcmRegId", $fcmRegId);
				$stmt->bindParam("apikey", $apikey);
			    $stmt->bindParam("cuEmail", $cuEmail);
                
				$result = $stmt->execute();
				$lastInsertId = $db->lastInsertId();
                $this->logger->info("Push registered, ['message'=>'The push fcm registered','last insert Id' => $lastInsertId, 'result' =>$result]"); 
                $response->getBody()
                    ->write(json_encode(['error' => false, 'result'=>$result,'message' => 'PUSH REGISTERED!']));
                      return $response->withHeader('content-type', 'application/json')
                          ->withStatus(200);  		
        }
        catch(PDOException $e) {
         
               $error = array(
                "message" => $e->getMessage()
               );
               $this->logger->warning('Push registration system error', ['payload'=>$error]);  
               $response->getBody()
                ->write(json_encode(['error' => true,'message' => 'There has been some push registration error' ]));
               return $response->withHeader('content-type', 'application/json')
                ->withStatus(500);
            
        }
    });
$app->post('/file-upload', function(Request $request, Response $response, $args) {
    $data = $request->getParsedBody();
    $data['customerId'] =21; //Must come from upload form
    $logger = $this->get(LoggerInterface::class);
    $this->logger = $logger; 
    //$settings = $this->get(SettingsInterface::class);
    //$this->settings = $settings; 
    //$settings = $this->get('settings');
    //From settings uploadDir' => __DIR__ . '/../uploads',
    //$directory = $settings['uploadDir'];
    $directory = "../uploads";
    
    $uploadedFiles = $request->getUploadedFiles();
    $uploadedFile = $uploadedFiles['user_file']; //Note this in form <input type="file" name="user_file" required />
    if ($uploadedFile->getError() === UPLOAD_ERR_OK) {
        do {
           // $fileName = sha1(rand()).toString();substr(md5(rand()), 0, 7);
            $fileName = bin2hex(openssl_random_pseudo_bytes(10)); //substr(md5(rand()), 0, 7);
            
        } while(file_exists($directory . DIRECTORY_SEPARATOR . $fileName));
        try {
            //moveTo can throw exception on failure
            $uploadedFile->moveTo($directory . DIRECTORY_SEPARATOR . $fileName);
        } catch(Exception $e) {
            //file move exception
            $this->logger->info("Upload fails, ['message'=>'Upload fails. Try again, 'directory' =>$directory]"); 
               
            $this->logger->error($e->getMessage());
            exit($e->getMessage());
        }
        try {
            
            $db = $this->get(PDO::class);
            $sql= 'INSERT INTO fileupload (customerId, filename, file_name_orig, file_type) VALUES (:idp, :fn, :fno, :ft)';
            $stmt = $db->prepare($sql);            
            $stmt->bindValue(':idp', $data['customerId']);
            $stmt->bindValue(':fn', $fileName);
            $stmt->bindValue(':fno', $uploadedFile->getClientFilename());
            $stmt->bindValue(':ft', $uploadedFile->getClientMediaType());
            $stmt->execute();
            //$routeParser = $app->getRouteCollector()->getRouteParser();
            //return $response->withHeader('Location', $this->router->urlFor('upload'));
           // return $response->withHeader(' Location', $this->$routeParser->fullUrlFor('uploads'));
             $this->logger->info("file uploaded, ['message'=>'The files uploaded, 'filename' =>$fileName]"); 
                $response->getBody()
                    ->write(json_encode(['error' => false, 'filename'=>$fileName,'ORIGINAL FILE NAME'=>$uploadedFile->getClientFilename()  ,'message' => 'FILES UPLOADED!']));
                      return $response->withHeader('content-type', 'application/json')
                          ->withStatus(200); 
        } catch(PDOException $e) {
            //delete the file
            unlink($directory . DIRECTORY_SEPARATOR . $fileName);
            //DB exception
            $this->logger->error($e->getMessage());
            exit($e->getMessage());
        }
    } else {
        exit('File upload failed.');
    }
})->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));


$app->get('/fetch-file', function(Request $request, Response $response, $args) {
    $params = $request->getQueryParams('id',$default = null);
    $id= $params['id'];
    
    $logger = $this->get(LoggerInterface::class);
    $this->logger = $logger; 
    //$stream = $this->get(StreamFactoryInterface::class);
    
    if(!empty($id)) {
        try {
            $db = $this->get(PDO::class);
            $sql= 'SELECT * FROM fileupload WHERE id = :id';
            $stmt = $db->prepare($sql);
            $stmt->bindValue(':id', $id);
            $stmt->execute();
            $fileInfo = $stmt->fetch();
            if($fileInfo) {
                //now you can check if visitor has privilege to download requested file
                //$settings = $this->get('settings');
                //$directory = $settings['uploadDir'];
                $directory = "../uploads";
                $fh = fopen($directory . DIRECTORY_SEPARATOR . $fileInfo['filename'], 'r');
                //$stream = new Stream($fh);
                //$stream = new \Slim\Http\Stream($fh);
                //$stream = $this->streamFactory->createStreamFromFile($fh);
                //syslog(LOG_INFO, 'name: '.$file->getClientFilename().' type: '.$file->getClientMediaType().' size: '.$file->getSize());
                $this->logger->info("file uploaded, [$file_stream->getClientFilename(),$file_stream->getClientMediaType(),'message'=>'The files uploaded, 'filename' =>$fileName]"); 
            
                $origName = $fileInfo['file_name_orig'];
                //set headers and send file contents
                //return $response->withBody(\Nyholm\Psr7\Stream::create($stream));
                return $response->withHeader('Cache-Control', 'private')
                    ->withHeader('Content-Type', $fileInfo['file_type'])
                    ->withHeader('Content-Disposition', 'inline; filename="' . $origName . '"')
                    ->withHeader('Expires', '0')
                    ->withBody(\Nyholm\Psr7\Stream::create($fh));
                    // return $response->withBody(new \Slim\Http\Stream($stream));
                    //->withHeader('Accept-Ranges', filesize($file))
              } else {
                return $response->withStatus(404)->write('File not found');
            }
        } catch(PDOException $e) {
            return $response->withStatus(500)->write($e->getMessage());
        }
    } else {
        return $response->withStatus(403)->write('Specify file id');
    }
})->setName('download') ->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));
;
/*-------------------------For next revision------------------------------------*/
    
    
    $app->group('/users', function (Group $group) {
        $group->get('', ListUsersAction::class);
        $group->get('/{id}', ViewUserAction::class);
       
    });
  
/* the database tables must be constructed for following queries sample  */
$app->post('/customers-data/add', function (Request $request, Response $response, array $args) {
 $data = $request->getParsedBody();
 $name = $data["name"];
 $email = $data["email"];
 $phone = $data["phone"];

 $sql = "INSERT INTO customers (name, email, phone) VALUES (:name, :email, :phone)";

 try {
   $db = new Db();
   $conn = $db->connect();
  
   $stmt = $conn->prepare($sql);
   $stmt->bindParam(':name', $name);
   $stmt->bindParam(':email', $email);
   $stmt->bindParam(':phone', $phone);

   $result = $stmt->execute();

   $db = null;
   $response->getBody()->write(json_encode(['error' => false,
		'message' => 'Thank you for posting data.']));
   return $response
     ->withHeader('content-type', 'application/json')
     ->withStatus(200);
 } catch (PDOException $e) {
   $error = array(
     "message" => $e->getMessage()
   );

   $response->getBody()->write(json_encode($error));
   return $response
     ->withHeader('content-type', 'application/json')
     ->withStatus(500);
 }
})->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));

/* the database tables must be constructed for following queries sample  */
$app->put( '/customers-data/update/{id}',
    function (Request $request, Response $response, array $args) 
{
 $id = $request->getAttribute('id');
 $data = $request->getParsedBody();
 $name = $data["name"];
 $email = $data["email"];
 $phone = $data["phone"];

 $sql = "UPDATE customers SET
           name = :name,
           email = :email,
           phone = :phone
 WHERE id = $id";

 try {
   $db = new Db();
   $conn = $db->connect();
  
   $stmt = $conn->prepare($sql);
   $stmt->bindParam(':name', $name);
   $stmt->bindParam(':email', $email);
   $stmt->bindParam(':phone', $phone);

   $result = $stmt->execute();

   $db = null;
   echo "Update successful! ";
   $response->getBody()->write(json_encode($result));
   return $response
     ->withHeader('content-type', 'application/json')
     ->withStatus(200);
 } catch (PDOException $e) {
   $error = array(
     "message" => $e->getMessage()
   );

   $response->getBody()->write(json_encode($error));
   return $response
     ->withHeader('content-type', 'application/json')
     ->withStatus(500);
 }
})->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));


/* the database tables must be constructed for following queries sample  */
$app->get('/tests/get-routes/', function ($request, $response, $args) use ($app) {
    $routes = $app->getRouteCollector()->getRoutes();
    foreach ($routes as $route) {
        echo $route->getIdentifier() . " â†’ ";
        echo ($route->getName() ?? "(unnamed)") . " â†’ ";
        echo $route->getPattern();
        echo "<br><br>";
    }

    return $response;
});
/*
From there, one can use something like this to get the URL for a given route:

$routeParser = \Slim\Routing\RouteContext::fromRequest($request)->getRouteParser();
$path = $routeParser->urlFor($nameofroute, $data, $queryParams);

*/
/* the database tables must be constructed for following queries sample  */
$app->get('/db-test', function (Request $request, Response $response) {
        $db = $this->get(PDO::class);
        $sth = $db->prepare("SELECT * FROM tasks ORDER BY task");
        $sth->execute();
        $data = $sth->fetchAll(PDO::FETCH_ASSOC);
        $payload = json_encode($data);
        $response->getBody()->write($payload);
        
        $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger;
        $this->logger->info("Slim-API-Skeleton '/' route");
        $this->logger->info('db-test works', ['payload'=>$payload]);        
   
    
        $this->logger->warning("message test2 works");
     
        return $response->withHeader('Content-Type', 'application/json');
    });
    
    $app->post('/jwt', function (Request $request, Response $response) {
         $logger = $this->get(LoggerInterface::class);
        $this->logger = $logger;
        $this->logger->info("Slim-API-Skeleton Jwt works ");
    $response->getBody()->write("JSON Web Token is Valid!");

    return $response;
     })->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));
	   
    $app->post('/register22', \App\Application\Actions\User\RegisterController::class)->setName('register');

    $app->post('/login22', \App\Application\Actions\User\LoginController::class)->setName('login');
     
    $app->get('/test2', \App\Application\Actions\User\Test2Controller::class)->setName('home');
    $app->get('/test1', \App\Application\Actions\User\Test1Controller::class)->setName('home')->add(\PsrJwt\Factory\JwtMiddleware::html('!secReT$123*', 'jwt', 'Authorisation Failed'));;


};  //END