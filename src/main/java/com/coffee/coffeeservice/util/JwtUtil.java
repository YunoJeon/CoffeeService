package com.coffee.coffeeservice.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

  @Value("${jwt.secret}")
  private String SECRET_KEY;

  public String generateToken(String email) {

    Date expirationTime = Date.from(LocalDateTime.now().plusMonths(1).toInstant(ZoneOffset.UTC));

    return JWT.create()
        .withSubject(email)
        .withIssuedAt(new Date())
        .withExpiresAt(expirationTime)
        .sign(Algorithm.HMAC256(SECRET_KEY));
  }

  public String validateToken(String token) {

    JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET_KEY)).build();
    DecodedJWT decodedJWT = verifier.verify(token);
    return decodedJWT.getSubject();
  }
}