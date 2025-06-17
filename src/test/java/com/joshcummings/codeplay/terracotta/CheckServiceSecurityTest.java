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
package com.joshcummings.codeplay.terracotta;

import com.joshcummings.codeplay.terracotta.service.CheckService;

import org.testng.annotations.*;
import static org.testng.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class CheckServiceSecurityTest {
    private CheckService checkService;
    
    @BeforeMethod
    public void setUp() {
        checkService = new CheckService();
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class, description = "Test path traversal prevention for findCheckImage")
    public void testFindCheckImageWithPathTraversal() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        checkService.findCheckImage("../../../etc/passwd", baos);
        // Should throw an IllegalArgumentException
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class, description = "Test path traversal prevention for updateCheckImage")
    public void testUpdateCheckImageWithPathTraversal() {
        ByteArrayInputStream bais = new ByteArrayInputStream("test content".getBytes());
        checkService.updateCheckImage("../../../etc/passwd", bais);
        // Should throw an IllegalArgumentException
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class, description = "Test path traversal prevention for updateCheckImagesBulk")
    public void testUpdateCheckImagesBulkWithPathTraversal() {
        ByteArrayInputStream bais = createTestZipWithPathTraversal();
        checkService.updateCheckImagesBulk("validnumber", bais);
        // Should throw an IllegalArgumentException
    }
    
    @Test(description = "Test valid check number is accepted")
    public void testValidCheckNumber() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            // The test will fail if an exception is thrown
            // Note: This test might fail if the file doesn't exist, which is expected
            // We're just testing that the validation passes, not that the file exists
            try {
                checkService.findCheckImage("123456", baos);
            } catch (IllegalArgumentException e) {
                // Check if it's a file not found exception (acceptable) vs validation error
                if (e.getCause() instanceof IOException) {
                    // This is likely a file not found exception, which is fine for this test
                } else {
                    // Rethrow if it's not an IO exception as that would indicate validation failed
                    throw e;
                }
            }
        } catch (IllegalArgumentException e) {
            if (!(e.getCause() instanceof IOException)) {
                fail("Valid check number should not fail validation");
            }
        }
    }
    
    private ByteArrayInputStream createTestZipWithPathTraversal() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            // Add an entry with path traversal
            ZipEntry entry = new ZipEntry("../../../etc/passwd");
            zos.putNextEntry(entry);
            zos.write("malicious content".getBytes());
            zos.closeEntry();
        } catch (IOException e) {
            fail("Failed to create test zip file: " + e.getMessage());
        }
        return new ByteArrayInputStream(baos.toByteArray());
    }
}