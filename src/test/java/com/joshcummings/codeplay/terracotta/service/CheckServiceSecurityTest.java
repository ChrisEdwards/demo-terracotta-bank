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

import static org.testng.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class CheckServiceSecurityTest {
    
    private CheckService checkService;
    
    @BeforeMethod
    public void setup() {
        checkService = new CheckService();
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testFindCheckImageRejectsPathTraversalWithDotDot() {
        // Attempt path traversal with "../"
        checkService.findCheckImage("../etc/passwd", new ByteArrayOutputStream());
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testFindCheckImageRejectsPathTraversalWithForwardSlash() {
        // Attempt path traversal with "/"
        checkService.findCheckImage("/etc/passwd", new ByteArrayOutputStream());
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testFindCheckImageRejectsPathTraversalWithBackslash() {
        // Attempt path traversal with "\"
        checkService.findCheckImage("C:\\windows\\system32", new ByteArrayOutputStream());
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testUpdateCheckImageRejectsPathTraversalWithDotDot() {
        // Attempt path traversal with "../"
        ByteArrayInputStream is = new ByteArrayInputStream("test".getBytes(StandardCharsets.UTF_8));
        checkService.updateCheckImage("../etc/passwd", is);
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testUpdateCheckImagesBulkRejectsPathTraversalWithDotDot() {
        // Attempt path traversal with "../"
        ByteArrayInputStream is = new ByteArrayInputStream("test".getBytes(StandardCharsets.UTF_8));
        checkService.updateCheckImagesBulk("../etc/passwd", is);
    }
    
    @Test
    public void testFindCheckImageWithValidCheckNumber() {
        // Test a valid check number scenario - this should pass without exceptions
        try {
            // Create a test file in the expected location
            new File("images/checks/12345").getParentFile().mkdirs();
            new File("images/checks/12345").createNewFile();
            
            // Should not throw exception for a valid check number
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            checkService.findCheckImage("12345", baos);
        } catch (IOException e) {
            fail("Unexpected exception: " + e.getMessage());
        } finally {
            // Clean up test file
            new File("images/checks/12345").delete();
        }
    }
}