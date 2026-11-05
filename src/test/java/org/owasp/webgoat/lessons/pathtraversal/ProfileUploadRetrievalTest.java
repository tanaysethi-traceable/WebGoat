/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.File;
import java.net.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
class ProfileUploadRetrievalTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void solve() throws Exception {
    // Look at the response
    mockMvc
        .perform(get("/PathTraversal/random-picture"))
        .andExpect(status().is(200))
        .andExpect(header().exists("Location"))
        .andExpect(header().string("Location", containsString("?id=")))
        .andExpect(content().contentTypeCompatibleWith(MediaType.IMAGE_JPEG));
  }

  @Test
  void pathTraversalWithDoubleDotsIsBlocked() throws Exception {
    // Browse the directories - should now be blocked
    var uri = new URI("/PathTraversal/random-picture?id=%2E%2E%2F%2E%2E%2F");
    mockMvc
        .perform(get(uri))
        .andExpect(status().is(400))
        .andExpect(content().string(containsString("Path traversal attempt detected")));
  }

  @Test
  void secretFileCannotBeAccessedViaSeparator() throws Exception {
    // Retrieve the secret file via path traversal - should now be blocked (note: .jpg is added by the server)
    var uri = new URI("/PathTraversal/random-picture?id=%2E%2E%2F%2E%2E%2Fpath-traversal-secret");
    mockMvc
        .perform(get(uri))
        .andExpect(status().is(400))
        .andExpect(content().string(containsString("Path traversal attempt detected")));
  }

  @Test
  void shouldReceiveRandomPicture() throws Exception {
    mockMvc
        .perform(get("/PathTraversal/random-picture"))
        .andExpect(status().is(200))
        .andExpect(header().exists("Location"))
        .andExpect(content().contentTypeCompatibleWith(MediaType.IMAGE_JPEG));
  }

  @Test
  void unknownFileShouldGiveDirectoryContents() throws Exception {
    mockMvc
        .perform(get("/PathTraversal/random-picture?id=test"))
        .andExpect(status().is(404))
        .andExpect(content().string(containsString("cats" + File.separator + "8.jpg")));
  }
}
