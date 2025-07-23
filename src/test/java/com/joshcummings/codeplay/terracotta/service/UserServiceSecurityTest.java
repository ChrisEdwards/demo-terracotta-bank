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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * This class tests that the UserService is protected against SQL injection attacks.
 */
public class UserServiceSecurityTest {
    private UserService userService;
    private static final String DATABASE_URL = "jdbc:hsqldb:mem:db";
    
    @BeforeMethod
    public void setUp() throws SQLException {
        // Set up the user service
        userService = new UserService();
        
        // Create a test user for our tests
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("CREATE TABLE IF NOT EXISTS users (id VARCHAR(50), name VARCHAR(50), email VARCHAR(50), username VARCHAR(50), password VARCHAR(50), is_employee BOOLEAN)")) {
            ps.executeUpdate();
        }
        
        // Insert test user
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("INSERT INTO users (id, name, email, username, password, is_employee) VALUES (?, ?, ?, ?, ?, ?)")) {
            ps.setString(1, "test-id");
            ps.setString(2, "Test User");
            ps.setString(3, "test@example.com");
            ps.setString(4, "testuser");
            ps.setString(5, "password");
            ps.setBoolean(6, false);
            ps.executeUpdate();
        }
    }
    
    @Test
    public void testFindByUsernameAndPassword_ValidCredentials() {
        // Test a successful login with valid credentials
        User user = userService.findByUsernameAndPassword("testuser", "password");
        
        Assert.assertNotNull(user, "User should be found with valid credentials");
        Assert.assertEquals(user.getUsername(), "testuser");
    }
    
    @Test
    public void testFindByUsernameAndPassword_InvalidCredentials() {
        // Test a failed login with invalid credentials
        User user = userService.findByUsernameAndPassword("testuser", "wrongpassword");
        
        Assert.assertNull(user, "User should not be found with invalid credentials");
    }
    
    @Test
    public void testFindByUsernameAndPassword_SQLInjection() {
        // Test attempt at SQL injection should fail
        // The string "' OR '1'='1" is a common SQL injection attack
        User user = userService.findByUsernameAndPassword("testuser", "' OR '1'='1");
        
        Assert.assertNull(user, "SQL injection attack should not succeed");
    }
    
    @Test
    public void testFindByUsernameAndPassword_SQLInjectionInUsername() {
        // Test attempt at SQL injection in username field should fail
        User user = userService.findByUsernameAndPassword("' OR '1'='1", "password");
        
        Assert.assertNull(user, "SQL injection attack in username should not succeed");
    }
    
    @Test
    public void testAddUser_SQLInjection() {
        // Test that SQL injection in user fields doesn't cause unexpected behavior
        String maliciousId = "malicious-id";
        String maliciousUsername = "') DELETE FROM users; --";
        String maliciousPassword = "password";
        String maliciousName = "Malicious User";
        String maliciousEmail = "malicious@example.com";
        
        User maliciousUser = new User(maliciousId, maliciousUsername, maliciousPassword, maliciousName, maliciousEmail);
        
        try {
            // The operation should succeed without any SQL errors
            userService.addUser(maliciousUser);
            
            // Verify the user was added correctly
            User retrievedUser = userService.findByUsername(maliciousUsername);
            
            Assert.assertNotNull(retrievedUser, "User with malicious data should be retrievable");
            Assert.assertEquals(retrievedUser.getId(), maliciousId, "User ID should match");
            Assert.assertEquals(retrievedUser.getUsername(), maliciousUsername, "Username should match");
            
            // Verify that other users still exist (no deletion occurred)
            User originalUser = userService.findByUsername("testuser");
            Assert.assertNotNull(originalUser, "Original test user should still exist");
        } finally {
            // Clean up the malicious user
            try {
                userService.removeUser(maliciousUsername);
            } catch (Exception e) {
                // Ignore cleanup errors
            }
        }
    }
}