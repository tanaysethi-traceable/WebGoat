/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  private static final Set<String> ALLOWED_HOSTS = Set.of("ifconfig.pro");

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    if (url.matches("http://ifconfig\\.pro")) {
      // Validate URL to prevent SSRF attacks
      if (!isValidUrl(url)) {
        return getFailedResult("Invalid URL");
      }

      String html;
      try (InputStream in = new URL(url).openStream()) {
        html =
            new String(in.readAllBytes(), StandardCharsets.UTF_8)
                .replaceAll("\n", "<br>"); // Otherwise the \n gets escaped in the response
      } catch (MalformedURLException e) {
        return getFailedResult(e.getMessage());
      } catch (IOException e) {
        // in case the external site is down, the test and lesson should still be ok
        html =
            "<html><body>Although the http://ifconfig.pro site is down, you still managed to solve"
                + " this exercise the right way!</body></html>";
      }
      return success(this).feedback("ssrf.success").output(html).build();
    }
    var html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
    return getFailedResult(html);
  }

  /**
   * Validates a URL to prevent SSRF attacks.
   *
   * @param urlString the URL string to validate
   * @return true if the URL is safe to fetch, false otherwise
   */
  private boolean isValidUrl(String urlString) {
    try {
      URI uri = new URI(urlString);

      // Only allow http and https schemes
      String scheme = uri.getScheme();
      if (scheme == null || (!scheme.equals("http") && !scheme.equals("https"))) {
        return false;
      }

      // Validate host is in allowlist
      String host = uri.getHost();
      if (host == null) {
        return false;
      }

      // Check if host is in the allowlist
      if (!ALLOWED_HOSTS.contains(host)) {
        return false;
      }

      // Validate that the host does not resolve to a private/internal IP
      InetAddress addr = InetAddress.getByName(host);
      if (addr.isLoopbackAddress()
          || addr.isLinkLocalAddress()
          || addr.isSiteLocalAddress()
          || addr.isAnyLocalAddress()) {
        return false;
      }

      return true;
    } catch (URISyntaxException | java.net.UnknownHostException e) {
      return false;
    }
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
