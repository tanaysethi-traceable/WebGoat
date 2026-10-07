/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.impl.TextCodec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@Slf4j
@SpringBootTest
@TestPropertySource(
    properties = {
      "jwt.refresh.jwt_password=bm5n3SkxCX4kKRy4",
      "spring.datasource.url=jdbc:hsqldb:mem:test"
    })
public class TokenTest {

  @Autowired(required = false)
  private JWTRefreshEndpoint jwtRefreshEndpoint;

  private String jwtPassword = "bm5n3SkxCX4kKRy4"; // Default test value

  @BeforeEach
  void setup() {
    if (jwtRefreshEndpoint != null && jwtRefreshEndpoint.PASSWORD != null) {
      // Use injected password if available (for integration tests)
    } else {
      // Use default value for unit tests
      jwtPassword = "bm5n3SkxCX4kKRy4";
    }
  }

  @Test
  public void test() {
    String key = "qwertyqwerty1234";
    Map<String, Object> claims =
        Map.of("username", "Jerry", "aud", "webgoat.org", "email", "jerry@webgoat.com");
    String token =
        Jwts.builder()
            .setHeaderParam("kid", "webgoat_key")
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, key)
            .compact();
    log.debug(token);
    Jwt jwt = Jwts.parser().setSigningKey("qwertyqwerty1234").parse(token);
    jwt =
        Jwts.parser()
            .setSigningKeyResolver(
                new SigningKeyResolverAdapter() {
                  @Override
                  public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                    return TextCodec.BASE64.decode(key);
                  }
                })
            .parse(token);
  }

  @Test
  public void testRefresh() {
    Instant now = Instant.now(); // current date
    Claims claims = Jwts.claims().setIssuedAt(Date.from(now.minus(Duration.ofDays(10))));
    claims.setExpiration(Date.from(now.minus(Duration.ofDays(9))));
    claims.put("admin", "false");
    claims.put("user", "Tom");
    String token =
        Jwts.builder()
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, jwtPassword)
            .compact();
    log.debug(token);
  }
}
