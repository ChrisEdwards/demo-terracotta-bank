/*
 * Copyright 2015-2018 Josh Cummings
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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.testng.Assert.*;

/**
 * Security tests for the CheckService to verify protection against path traversal
 */
public class CheckServiceSecurityTest {
    private CheckService checkService;

    @BeforeMethod
    public void setup() {
        checkService = new CheckService();
    }

    @Test
    public void testValidCheckNumberValidation() {
        // Valid check numbers
        assertTrue(checkService.isValidCheckNumber("12345"));
        assertTrue(checkService.isValidCheckNumber("abc123"));
        assertTrue(checkService.isValidCheckNumber("check-123"));
        assertTrue(checkService.isValidCheckNumber("check_123"));
    }

    @Test
    public void testInvalidCheckNumberValidation() {
        // Invalid check numbers - should detect path traversal attempts
        assertFalse(checkService.isValidCheckNumber("../etc/passwd"));
        assertFalse(checkService.isValidCheckNumber("..\\Windows\\System32\\config"));
        assertFalse(checkService.isValidCheckNumber("/etc/passwd"));
        assertFalse(checkService.isValidCheckNumber("\\Windows\\System32"));
        assertFalse(checkService.isValidCheckNumber("check/test.jpg"));
        assertFalse(checkService.isValidCheckNumber("check\\test.jpg"));
        assertFalse(checkService.isValidCheckNumber("invalid;character"));
        assertFalse(checkService.isValidCheckNumber("invalid/character"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testFindCheckImageRejectsPathTraversal() {
        // Should throw exception for path traversal attempt
        checkService.findCheckImage("../etc/passwd", new ByteArrayOutputStream());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testUpdateCheckImageRejectsPathTraversal() {
        // Should throw exception for path traversal attempt
        byte[] testData = "test data".getBytes();
        checkService.updateCheckImage("../etc/passwd", new ByteArrayInputStream(testData));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testUpdateCheckImageRejectsEscapingNormalizedPath() {
        // This pattern can sometimes bypass simple validation
        byte[] testData = "test data".getBytes();
        checkService.updateCheckImage("valid/../../../etc/passwd", new ByteArrayInputStream(testData));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testUpdateCheckImagesBulkRejectsPathTraversal() throws Exception {
        // Create a malicious ZIP with path traversal attempts
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        
        ZipEntry entry = new ZipEntry("../etc/passwd");
        zos.putNextEntry(entry);
        zos.write("fake passwd file".getBytes());
        zos.closeEntry();
        zos.close();
        
        InputStream is = new ByteArrayInputStream(baos.toByteArray());
        
        // Should throw exception
        checkService.updateCheckImagesBulk("12345", is);
    }
}