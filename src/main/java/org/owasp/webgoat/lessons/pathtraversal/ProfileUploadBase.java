/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Getter
public class ProfileUploadBase implements AssignmentEndpoint {

  private final String webGoatHomeDirectory;

  public ProfileUploadBase(String webGoatHomeDirectory) {
    this.webGoatHomeDirectory = webGoatHomeDirectory;
  }

  protected AttackResult execute(MultipartFile file, String fullName, String username) {
    if (file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    if (StringUtils.isEmpty(fullName)) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }

    File uploadDirectory = cleanupAndCreateDirectoryForUser(username);

    try {
      // Canonicalize fullName and validate it doesn't escape the upload directory
      File uploadedFile = validateAndResolveUploadPath(uploadDirectory, fullName);
      if (uploadedFile == null) {
        return failed(this).feedback("path-traversal-profile-attempt").build();
      }

      uploadedFile.createNewFile();
      FileCopyUtils.copy(file.getBytes(), uploadedFile);

      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(uploadedFile.getAbsoluteFile())
          .build();

    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  /**
   * Sanitizes a path segment to prevent directory traversal attacks. Removes or replaces
   * characters that could be used to escape the intended directory.
   *
   * @param pathSegment the path segment to sanitize (e.g., username)
   * @return a sanitized path segment safe for use in file paths
   */
  private String sanitizePathSegment(String pathSegment) {
    if (pathSegment == null || pathSegment.isEmpty()) {
      return "default";
    }
    // Remove path traversal sequences
    return pathSegment.replaceAll("\\.\\.[\\\\/]|[\\\\/]\\.\\.|\\.\\.|[\\\\/]", "_");
  }

  @SneakyThrows
  protected File cleanupAndCreateDirectoryForUser(String username) {
    // Sanitize username to prevent directory traversal
    String sanitizedUsername = sanitizePathSegment(username);
    var uploadDirectory = new File(this.webGoatHomeDirectory, "/PathTraversal/" + sanitizedUsername);
    // Verify the resolved path is within the intended parent directory
    File pathTraversalDir = new File(this.webGoatHomeDirectory, "/PathTraversal");
    String parentCanonical = pathTraversalDir.getCanonicalPath();
    String uploadCanonical = uploadDirectory.getCanonicalPath();
    if (!uploadCanonical.startsWith(parentCanonical + File.separator) && !uploadCanonical.equals(parentCanonical)) {
      throw new IOException("Path traversal attempt detected: " + username);
    }
    if (uploadDirectory.exists()) {
      FileSystemUtils.deleteRecursively(uploadDirectory);
    }
    Files.createDirectories(uploadDirectory.toPath());
    return uploadDirectory;
  }

  /**
   * Validates that the upload path does not escape the intended upload directory and resolves
   * it to an absolute canonical path.
   *
   * @param uploadDirectory the intended upload directory
   * @param filename the user-supplied filename
   * @return the validated File object if safe, null if path traversal detected
   * @throws IOException if canonicalization fails
   */
  private File validateAndResolveUploadPath(File uploadDirectory, String filename) throws IOException {
    // Resolve the canonical paths to detect any traversal attempts
    String uploadDirCanonical = uploadDirectory.getCanonicalPath();
    File uploadedFile = new File(uploadDirectory, filename);
    String uploadedFileCanonical = uploadedFile.getCanonicalPath();

    // Ensure the resolved file is within the upload directory
    if (!uploadedFileCanonical.startsWith(uploadDirCanonical + File.separator)
        && !uploadedFileCanonical.equals(uploadDirCanonical)) {
      return null; // Path traversal detected
    }

    return uploadedFile;
  }

  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64(username));
  }

  protected byte[] getProfilePictureAsBase64(String username) {
    // Sanitize username to prevent directory traversal
    String sanitizedUsername = sanitizePathSegment(username);
    var profilePictureDirectory = new File(this.webGoatHomeDirectory, "/PathTraversal/" + sanitizedUsername);
    var profileDirectoryFiles = profilePictureDirectory.listFiles();

    if (profileDirectoryFiles != null && profileDirectoryFiles.length > 0) {
      return Arrays.stream(profileDirectoryFiles)
          .filter(file -> FilenameUtils.isExtension(file.getName(), List.of("jpg", "png")))
          .findFirst()
          .map(
              file -> {
                try (var inputStream = new FileInputStream(profileDirectoryFiles[0])) {
                  return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
                } catch (IOException e) {
                  return defaultImage();
                }
              })
          .orElse(defaultImage());
    } else {
      return defaultImage();
    }
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
