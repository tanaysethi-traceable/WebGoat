/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.sastdemo;

import java.sql.ResultSet;
import java.sql.Statement;
import org.owasp.webgoat.container.LessonDataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * NOTE: intentionally vulnerable fixtures used only to validate SAST tool detection coverage.
 * Not wired into the WebGoat lesson framework. Do not deploy publicly.
 */
@RestController
public class SastDemoController {
  private final LessonDataSource dataSource;

  public SastDemoController(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  // CWE-89: SQL Injection - user input concatenated directly into the query string.
  @GetMapping("/sastdemo/sqli")
  @ResponseBody
  public String sqli(@RequestParam("user") String user) throws Exception {
    try (var connection = dataSource.getConnection();
        Statement statement = connection.createStatement()) {
      ResultSet resultSet =
          statement.executeQuery("SELECT * FROM users WHERE username = '" + user + "'");
      StringBuilder result = new StringBuilder();
      while (resultSet.next()) {
        result.append(resultSet.getString(1)).append('\n');
      }
      return result.toString();
    }
  }

  // CWE-78: OS Command Injection - user input passed unsanitized to the shell.
  @GetMapping("/sastdemo/ping")
  @ResponseBody
  public String ping(@RequestParam("host") String host) throws Exception {
    Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
    process.waitFor();
    return "Pinged " + host;
  }
}
