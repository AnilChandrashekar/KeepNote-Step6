package com.stackroute.keepnote.controller;

import java.util.Date;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.stackroute.keepnote.model.User;
import com.stackroute.keepnote.service.UserAuthenticationService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/*
 * As in this assignment, we are working on creating RESTful web service, hence annotate
 * the class with @RestController annotation. A class annotated with the @Controller annotation
 * has handler methods which return a view. However, if we use @ResponseBody annotation along
 * with @Controller annotation, it will return the data directly in a serialized 
 * format. Starting from Spring 4 and above, we can use @RestController annotation which 
 * is equivalent to using @Controller and @ResposeBody annotation
 */
@RestController
public class UserAuthenticationController {

    /*
	 * Autowiring should be implemented for the UserAuthenticationService. (Use Constructor-based
	 * autowiring) Please note that we should not create an object using the new
	 * keyword
	 */

	private Log log = LogFactory.getLog(getClass());
	UserAuthenticationService authicationService;
	
    public UserAuthenticationController(UserAuthenticationService authicationService) {
    	this.authicationService =authicationService;
	}

/*
	 * Define a handler method which will create a specific user by reading the
	 * Serialized object from request body and save the user details in the
	 * database. This handler method should return any one of the status messages
	 * basis on different situations:
	 * 1. 201(CREATED) - If the user created successfully. 
	 * 2. 409(CONFLICT) - If the userId conflicts with any existing user
	 * 
	 * This handler method should map to the URL "/api/v1/auth/register" using HTTP POST method
	 */
    @PostMapping("/api/v1/auth/register")
	public ResponseEntity<?> createUser(@RequestBody User user) {
		log.info("createUser : STARTED");
		HttpHeaders headers = new HttpHeaders();
		try {
			user.setUserAddedDate(new Date());
			if(authicationService.saveUser(user))
			{
				return new ResponseEntity<>(headers, HttpStatus.CREATED);
			}
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>(headers, HttpStatus.CONFLICT);
		}
		log.info("createUser : ENDED");
		return new ResponseEntity<>(headers, HttpStatus.CREATED);
	}



	/* Define a handler method which will authenticate a user by reading the Serialized user
	 * object from request body containing the username and password. The username and password should be validated 
	 * before proceeding ahead with JWT token generation. The user credentials will be validated against the database entries. 
	 * The error should be return if validation is not successful. If credentials are validated successfully, then JWT
	 * token will be generated. The token should be returned back to the caller along with the API response.
	 * This handler method should return any one of the status messages basis on different
	 * situations:
	 * 1. 200(OK) - If login is successful
	 * 2. 401(UNAUTHORIZED) - If login is not successful
	 * 
	 * This handler method should map to the URL "/api/v1/auth/login" using HTTP POST method
	*/

    @PostMapping("/api/v1/auth/login")
   	public ResponseEntity<?> validateUser(@RequestBody User user) {
   		log.info("validateUser : STARTED");
   		HttpHeaders headers = new HttpHeaders();
   		try {
   			user.setUserAddedDate(new Date());
   			if(authicationService.findByUserIdAndPassword(user.getUserId(), user.getUserPassword())!=null)
   		//	if(true)
   			{
   				log.info("user authenticated : Generating token");
   				String token = getToken(user.getUserId(), user.getUserPassword());
   				log.info("token : "+token);
   				return new ResponseEntity<>(token, HttpStatus.OK);
   			}
   		} catch (Exception e) {
   			e.printStackTrace();
   			return new ResponseEntity<>(headers, HttpStatus.CONFLICT);
   		}
   		log.info("validateUser : ENDED");
   		return new ResponseEntity<>(headers, HttpStatus.UNAUTHORIZED);
   	}





// Generate JWT token
	public String getToken(String username, String password) throws Exception {
		 //The JWT signature algorithm we will be using to sign the token
	   // SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

	    /*long nowMillis = System.currentTimeMillis();
	    Date now = new Date(nowMillis);

	    //We will sign our JWT with our ApiKey secret
	    byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
	    Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

	    //Let's set the JWT Claims
	    JwtBuilder builder = Jwts.builder().setId(id)
	            .setIssuedAt(now)
	            .setSubject(subject)
	            .setIssuer(issuer)
	            .signWith(signatureAlgorithm, signingKey);
	  
	    //if it has been specified, let's add the expiration
	    if (ttlMillis > 0) {
	        long expMillis = nowMillis + ttlMillis;
	        Date exp = new Date(expMillis);
	        builder.setExpiration(exp);
	    }  
	  
	    //Builds the JWT and serializes it to a compact, URL-safe string
	    return builder.compact();*/
	    
	    Claims claims = Jwts.claims().setSubject(username);
        claims.put("username", username + "");
        claims.put("password", password);
        claims.put("role", "ADMIN");

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, "secret")
                .compact();
}


}
