package com.example.demojwt.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	/*************************************************************************************************************
	 * THE SECRETkey given below will be generated from a key generator 
	 *************************************************************************************************************/
	
		private static final String SECRET_KEY="CStH2B0XMKvlGE/iFKFZmmEY9pdPtXVhdPL6/3CvAfnv/RQgkkXvQCfVR5ltnS";
			

		public String extractUsername(String token) {
				
			return extractClaim(token,Claims::getSubject);
		}
	
	    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
	    	final Claims claims = extractAllClaims(token);
	    	
			return claimsResolver.apply(claims);
	    	
	    }
	    
	 /*************************************************************************************************************
	  * Generates token out of user details only 
	  * @param userDetails
	  * @return token
	  *************************************************************************************************************/
	    
	    public String generateToken (UserDetails userDetails) {
	    	return generateToken(new HashMap<>(), userDetails);
	    }
	    
	  /*************************************************************************************************************
	   * Generates token out of extra claims and user details 
	   * @param extraClaims
	   * @param userDetails
	   * @return token
	   *************************************************************************************************************/
	    
	    public String generateToken (Map<String, Object> extraClaims,UserDetails userDetails) {
	    	return Jwts
	    			.builder()
	    			.setClaims(extraClaims)
	    			.setSubject(userDetails.getUsername())
	    			.setIssuedAt(new Date(System.currentTimeMillis()))
	    			.setExpiration(new Date(System.currentTimeMillis() + 10000 * 60 *24))
	    			.signWith(getSignInKey(),SignatureAlgorithm.HS256)
	    			.compact();
	    }
	   
	   /*************************************************************************************************************
	    * Validates a token whether it belongs to the user details or not and the token should not be expired 
	    * @param token
	    * @param userDetails
	    * @return true or false 
	    *************************************************************************************************************/
	    
	 	public boolean isTokenValid(String token , UserDetails userDetails) {
	    	
	    	final String username = extractUsername(token);
	    	return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	    	
	    }
	   
	 
	   /*************************************************************************************************************
	 	 * Checks whether token is expired or not 
	 	 * @param token
	 	 * @return true or false 
	 	 ***********************************************************************************************************/
		private boolean isTokenExpired(String token) {
			
			return extractExpiration(token).before(new Date());
		}
		
	   /*************************************************************************************************************
	    * Checks for token expire date 
	    * @param token
	    * @return Token Date of expiration 
	    *************************************************************************************************************/

		private Date extractExpiration(String token) {
			// TODO Auto-generated method stub
			return extractClaim(token , Claims::getExpiration);
		}

		public Claims extractAllClaims (String token) {
			return Jwts
					.parserBuilder()
					.setSigningKey(getSignInKey())
			        .build()
			        .parseClaimsJws(token)
			        .getBody();
			  
		 }
	  
		private Key getSignInKey() {
		     byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
			return Keys.hmacShaKeyFor(keyBytes);
		}
}
