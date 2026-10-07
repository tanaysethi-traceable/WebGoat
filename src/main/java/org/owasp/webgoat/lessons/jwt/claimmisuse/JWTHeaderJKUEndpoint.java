/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.interfaces.RSAPublicKey;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/JWT/")
@RestController
@AssignmentHints({
  "jwt-jku-hint1",
  "jwt-jku-hint2",
  "jwt-jku-hint3",
  "jwt-jku-hint4",
  "jwt-jku-hint5"
})
public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {
  private static final Logger logger = LoggerFactory.getLogger(JWTHeaderJKUEndpoint.class);
  private static final String ALLOWED_JKU_HOST = "localhost";
  // Allow localhost on port 8080 (WebGoat) and 9090 (WebWolf for integration tests)
  private static final int[] ALLOWED_JKU_PORTS = {8080, 9090};

  /**
   * Validates that the provided URL host is allowlisted to prevent SSRF attacks.
   * Only allows localhost on allowlisted ports (8080, 9090). Rejects:
   * - Any host not explicitly allowlisted
   * - Private/internal IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   * - Link-local addresses (169.254.0.0/16)
   * - Loopback addresses other than standard "localhost" hostname
   * - Metadata endpoints (169.254.169.254, metadata.google.internal, etc.)
   * - Multicast addresses
   *
   * @param url the URL to validate
   * @return true if the host is allowlisted and safe, false otherwise
   */
  private boolean isHostAllowlisted(URL url) {
    String host = url.getHost();
    int port = url.getPort();
    if (port == -1) {
      port = url.getDefaultPort();
    }

    // Only allow localhost on allowlisted ports
    if (!ALLOWED_JKU_HOST.equalsIgnoreCase(host)) {
      logger.warn("SSRF prevention: rejected JKU URL with host '{}' - not in allowlist", host);
      return false;
    }

    // Check if port is allowlisted
    boolean portAllowed = false;
    for (int allowedPort : ALLOWED_JKU_PORTS) {
      if (port == allowedPort || port == -1) { // Allow if matches or if no port specified
        portAllowed = true;
        break;
      }
    }
    if (!portAllowed) {
      logger.warn(
          "SSRF prevention: rejected JKU URL with host '{}' on port {} - not in allowlist",
          host, port);
      return false;
    }

    // Additional IP-based checks to prevent bypasses
    try {
      InetAddress inetAddress = InetAddress.getByName(host);

      // Reject private addresses (but localhost will pass the hostname check above)
      if (inetAddress.isPrivateAddress() && !host.equalsIgnoreCase("localhost")) {
        logger.warn("SSRF prevention: rejected JKU URL with private address '{}'", host);
        return false;
      }

      // Reject link-local addresses
      if (inetAddress.isLinkLocalAddress()) {
        logger.warn("SSRF prevention: rejected JKU URL with link-local address '{}'", host);
        return false;
      }

      // Reject multicast addresses
      if (inetAddress.isMulticastAddress()) {
        logger.warn("SSRF prevention: rejected JKU URL with multicast address '{}'", host);
        return false;
      }

      // Reject metadata service endpoints
      if ("169.254.169.254".equals(host) || "metadata.google.internal".equals(host)
          || "metadata".equalsIgnoreCase(host)) {
        logger.warn("SSRF prevention: rejected JKU URL with metadata endpoint '{}'", host);
        return false;
      }

      return true;
    } catch (UnknownHostException e) {
      logger.warn("SSRF prevention: could not resolve host '{}' - rejecting as potential attack", host);
      return false;
    }
  }

  @PostMapping("jku/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("jku/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    } else {
      try {
        var decodedJWT = JWT.decode(token);
        var jku = decodedJWT.getHeaderClaim("jku");
        var jkuUrl = new URL(jku.asString());

        // Validate the JKU host to prevent SSRF attacks
        if (!isHostAllowlisted(jkuUrl)) {
          logger.error("Rejected JKU claim with non-allowlisted host: {}", jkuUrl.getHost());
          return failed(this).feedback("jwt-invalid-token").build();
        }

        var jwkProvider = new JwkProviderBuilder(jkuUrl).build();
        var jwk = jwkProvider.get(decodedJWT.getKeyId());
        var algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey());
        JWT.require(algorithm).build().verify(decodedJWT);

        var username = decodedJWT.getClaims().get("username").asString();
        if ("Jerry".equals(username)) {
          return failed(this).feedback("jwt-final-jerry-account").build();
        }
        if ("Tom".equals(username)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-final-not-tom").build();
        }
      } catch (MalformedURLException | JWTVerificationException | JwkException e) {
        return failed(this).feedback("jwt-invalid-token").output(e.toString()).build();
      }
    }
  }
}
