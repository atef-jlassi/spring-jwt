package com.defense.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/**
 *  JwtService is a class that provides methods for creating and validating JSON web tokens.
 *  @author Atef Jlassi
 *  @version 1.0
 */
@Service
public class JwtService {

  private static final String SECRET_KEY = "655368566D5971337436763979244226452948404D635166546A576E5A723475";

  /**
   *  Extracts the username from the given token.
   *  @param token the token to extract the username from
   *  @return the username contained in the token
   */
  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  /**
   * Extracts a claim from the given token using the specified claim resolver function.
   * @param token the token to extract the claim from
   * @param claimsResolver the function to use to resolve the claim
   * @param <R> the type of the claim
   * @return the extracted claim
   */
  public <R> R extractClaim(String token, Function<Claims, R> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }
  /**
   *  Generates a token for the specified user details.
   *  @param userDetails the user details to use to generate the token
   *  @return the generated token
   */
  public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails);
  }

  /**
   *  Generates a token for the specified user details and extra claims.
   *  @param extraClaims the extra claims to include in the token
   *  @param userDetails the user details to use to generate the token
   *  @return the generated token
   */
  public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
    return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  /**
   *  Checks if the specified token is valid for the given user details.
   *  @param token the token to check
   *  @param userDetails the user details to use for validation
   *  @return true if the token is valid, false otherwise
   */
  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername()) && !this.isTokenExpired(token));
  }

  /**
   *  Checks if the specified token is expired.
   *  @param token the token to check
   *  @return true if the token is expired, false otherwise
   */
  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  /**
   *   Extracts the expiration
   *   date from the given token.
   *  @param token the token to extract the expiration date from
   *  @return the expiration date contained in the token
   */
  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  /**
   * Extracts all claims from the given token.
   * @param token the token to extract the claims from
   * @return the claims contained in the token
   */
  private Claims extractAllClaims(String token) {
    return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token)
        .getBody();
  }

  /**
   * Gets the signing key to be used for creating and validating tokens.
   *
   * @return the signing key
   */
  private Key getSignInKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
