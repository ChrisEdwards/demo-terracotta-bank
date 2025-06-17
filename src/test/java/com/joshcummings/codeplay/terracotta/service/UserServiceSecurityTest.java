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

import com.joshcummings.codeplay.terracotta.model.User;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Security tests for UserService to verify SQL injection vulnerabilities are fixed.
 * 
 * @author Josh Cummings
 */
public class UserServiceSecurityTest {
    
    private UserService userService;
    
    @BeforeMethod
    public void setUp() {
        userService = new UserService();
        // Create a test user to work with
        User testUser = new User("test-id", "John Doe", "john@example.com", "testuser", "password123", false);
        userService.addUser(testUser);
    }
    
    @Test(groups = "security")
    public void testFindByUsername_SqlInjectionAttack_ShouldReturnNull() {
        // Test with classic SQL injection payload based on original HTTP request
        String sqlInjectionPayload = "testuser' OR '1'='1";
        
        User result = userService.findByUsername(sqlInjectionPayload);
        
        // Should return null since the sanitized username won't match any real user
        Assert.assertNull(result, "SQL injection payload should not return any user");
    }
    
    @Test(groups = "security")
    public void testFindByUsername_SqlInjectionWithUnion_ShouldReturnNull() {
        // Test with UNION-based SQL injection
        String sqlInjectionPayload = "testuser' UNION SELECT * FROM users--";
        
        User result = userService.findByUsername(sqlInjectionPayload);
        
        // Should return null since the sanitized username won't match any real user
        Assert.assertNull(result, "UNION-based SQL injection should not return any user");
    }
    
    @Test(groups = "security")
    public void testFindByUsername_SqlInjectionWithComments_ShouldReturnNull() {
        // Test with comment-based SQL injection
        String sqlInjectionPayload = "testuser'--";
        
        User result = userService.findByUsername(sqlInjectionPayload);
        
        // Should return null since the sanitized username won't match any real user
        Assert.assertNull(result, "Comment-based SQL injection should not return any user");
    }
    
    @Test(groups = "security")
    public void testFindByUsername_ValidUsernameAfterSanitization_ShouldWork() {
        // Test with valid username that should work after sanitization
        User result = userService.findByUsername("testuser");
        
        Assert.assertNotNull(result, "Valid username should return the user");
        Assert.assertEquals(result.getUsername(), "testuser");
    }
    
    @Test(groups = "security")
    public void testFindByUsername_NullInput_ShouldReturnNull() {
        // Test with null input
        User result = userService.findByUsername(null);
        
        Assert.assertNull(result, "Null username should return null");
    }
    
    @Test(groups = "security")
    public void testFindByUsername_EmptyInput_ShouldReturnNull() {
        // Test with empty input
        User result = userService.findByUsername("");
        
        Assert.assertNull(result, "Empty username should return null");
    }
    
    @Test(groups = "security")
    public void testFindByUsername_WhitespaceInput_ShouldReturnNull() {
        // Test with whitespace-only input
        User result = userService.findByUsername("   ");
        
        Assert.assertNull(result, "Whitespace-only username should return null");
    }
    
    @Test(groups = "security")
    public void testFindByUsername_LongInput_ShouldBeTruncated() {
        // Test with very long input to verify truncation
        String longUsername = "a".repeat(150); // 150 characters
        
        User result = userService.findByUsername(longUsername);
        
        // Should not throw an exception and return null (since truncated username won't match)
        Assert.assertNull(result, "Very long username should be handled safely");
    }
    
    @Test(groups = "security")
    public void testFindByUsername_SpecialCharacters_ShouldBeSanitized() {
        // Test with special characters that should be removed
        String usernameWithSpecialChars = "test<script>alert('xss')</script>user";
        
        User result = userService.findByUsername(usernameWithSpecialChars);
        
        // Should return null since sanitized username won't match any real user
        Assert.assertNull(result, "Username with special characters should be sanitized");
    }
}