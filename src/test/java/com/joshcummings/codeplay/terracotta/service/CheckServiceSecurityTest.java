/*
 * Copyright 2015-2023 Josh Cummings
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.joshcummings.codeplay.terracotta.service;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.testng.Assert.*;

/**
 * Security test for the CheckService class focusing on path traversal vulnerabilities
 */
public class CheckServiceSecurityTest {
    private CheckService checkService;
    private Path tempDir;
    private String originalCheckImageLocation;

    @BeforeMethod
    public void setup() throws IOException {
        // Create a temporary directory for test
        tempDir = Files.createTempDirectory("check-service-test");
        
        // Create test check image directory
        Files.createDirectories(tempDir.resolve("images/checks"));
        
        // Create a sample check file
        Files.write(tempDir.resolve("images/checks/validCheck"), "test check content".getBytes());
        
        // Initialize the service with test configuration
        checkService = new CheckService();
        
        // Save original location and set the test location using reflection
        try {
            java.lang.reflect.Field field = CheckService.class.getDeclaredField("CHECK_IMAGE_LOCATION");
            field.setAccessible(true);
            originalCheckImageLocation = (String)field.get(null);
            field.set(null, tempDir.resolve("images/checks").toString());
        } catch (Exception e) {
            fail("Could not configure test environment", e);
        }
    }

    @AfterMethod
    public void cleanup() throws IOException {
        // Restore original location
        try {
            java.lang.reflect.Field field = CheckService.class.getDeclaredField("CHECK_IMAGE_LOCATION");
            field.setAccessible(true);
            field.set(null, originalCheckImageLocation);
        } catch (Exception e) {
            // Log error but continue cleanup
            e.printStackTrace();
        }
        
        // Clean up test directory
        deleteDirectory(tempDir.toFile());
    }
    
    /**
     * Helper method to recursively delete a directory
     */
    private void deleteDirectory(File directory) {
        if (directory.exists()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirectory(file);
                    } else {
                        file.delete();
                    }
                }
            }
            directory.delete();
        }
    }

    @Test
    public void testFindCheckImage_ValidCheckNumber() {
        // Arrange
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        
        // Act
        checkService.findCheckImage("validCheck", output);
        
        // Assert
        assertEquals(new String(output.toByteArray()), "test check content");
    }

    @Test(expectedExceptions = IllegalArgumentException.class, 
          expectedExceptionsMessageRegExp = ".*Invalid check number.*")
    public void testFindCheckImage_PathTraversalAttempt() {
        // Arrange
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        
        // Act - This should throw an IllegalArgumentException
        checkService.findCheckImage("../../../etc/passwd", output);
        
        // We should never reach this point
        fail("Path traversal attack was not prevented");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testFindCheckImage_NonExistentFile() {
        // Arrange
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        
        // Act - This should throw an IllegalArgumentException
        checkService.findCheckImage("nonexistent", output);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
          expectedExceptionsMessageRegExp = ".*Invalid check number.*")
    public void testUpdateCheckImage_PathTraversalAttempt() throws IOException {
        // Arrange
        byte[] content = "malicious content".getBytes();
        
        // Act - This should throw an IllegalArgumentException
        checkService.updateCheckImage("../../../dangerous", new java.io.ByteArrayInputStream(content));
    }
}