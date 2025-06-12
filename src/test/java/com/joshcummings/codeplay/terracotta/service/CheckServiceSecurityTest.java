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
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.testng.Assert.assertThrows;

public class CheckServiceSecurityTest {
    private CheckService checkService;
    private static final String TEST_CHECK_NUMBER = "test-check-123";
    private static final String TEST_CHECK_CONTENT = "test check image content";
    private static final String CHECK_IMAGE_LOCATION = "images/checks";

    @BeforeMethod
    public void setup() throws Exception {
        checkService = new CheckService();
        
        // Create test directory and file if they don't exist
        new File(CHECK_IMAGE_LOCATION).mkdirs();
        File testFile = new File(CHECK_IMAGE_LOCATION, TEST_CHECK_NUMBER);
        try (FileOutputStream fos = new FileOutputStream(testFile)) {
            fos.write(TEST_CHECK_CONTENT.getBytes(StandardCharsets.UTF_8));
        }
    }
    
    @Test
    public void testPathTraversalPrevention() {
        // Test with path traversal attempt
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // Path traversal attempt using parent directory references
        assertThrows(IllegalArgumentException.class, 
            () -> checkService.findCheckImage("../../../etc/passwd", baos));
        
        // Test with encoded traversal
        assertThrows(IllegalArgumentException.class,
            () -> checkService.findCheckImage("%2e%2e%2f%2e%2e%2fetc%2fpasswd", baos));
            
        // Test with null input
        assertThrows(IllegalArgumentException.class,
            () -> checkService.findCheckImage(null, baos));
    }
    
    @Test
    public void testValidCheckImageRetrieval() throws Exception {
        // Test with legitimate check number
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        checkService.findCheckImage(TEST_CHECK_NUMBER, baos);
        
        // Verify content is returned correctly for valid check numbers
        String result = new String(baos.toByteArray(), StandardCharsets.UTF_8);
        assert result.equals(TEST_CHECK_CONTENT);
    }
    
    @Test
    public void testPathTraversalPreventionInUpdate() throws Exception {
        // Test with path traversal attempt for update
        ByteArrayInputStream bais = new ByteArrayInputStream("malicious content".getBytes(StandardCharsets.UTF_8));
        
        // Path traversal attempt using parent directory references
        assertThrows(IllegalArgumentException.class, 
            () -> checkService.updateCheckImage("../../../etc/passwd", bais));
        
        // Test with encoded traversal
        bais.reset();
        assertThrows(IllegalArgumentException.class,
            () -> checkService.updateCheckImage("%2e%2e%2f%2e%2e%2fetc%2fpasswd", bais));
            
        // Test with null input
        assertThrows(IllegalArgumentException.class,
            () -> checkService.updateCheckImage(null, bais));
    }
    
    @Test
    public void testBulkUpdateWithMaliciousZipEntry() throws Exception {
        // Create a zip stream with a malicious entry
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        
        // Add a valid entry
        zos.putNextEntry(new ZipEntry("valid.jpg"));
        zos.write("valid content".getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
        
        // Add a malicious entry with path traversal
        zos.putNextEntry(new ZipEntry("../../etc/passwd"));
        zos.write("malicious content".getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
        
        zos.close();
        
        // Test the bulk update with the malicious zip
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        
        // This should not throw an exception as malicious entries are skipped
        checkService.updateCheckImagesBulk(TEST_CHECK_NUMBER, bais);
        
        // Verify malicious file doesn't exist
        File maliciousFile = new File("etc/passwd");
        assert !maliciousFile.exists() : "Malicious file should not be created";
        
        // Verify null check
        assertThrows(IllegalArgumentException.class, 
            () -> checkService.updateCheckImagesBulk(null, new ByteArrayInputStream(baos.toByteArray())));
    }
}