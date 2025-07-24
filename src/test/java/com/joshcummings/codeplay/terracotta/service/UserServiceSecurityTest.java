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
import java.sql.ResultSet;

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
        
        // Delete any existing users
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("DELETE FROM users")) {
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
    public void testAddUser_NoSQLInjection() throws SQLException {
        // Test that addUser method is secure against SQL injection
        String maliciousId = "1'; DELETE FROM users; --";
        User maliciousUser = new User(maliciousId, "hacker", "password", "Hacker", "hacker@example.com");
        
        // This should not cause any error or SQL injection
        userService.addUser(maliciousUser);
        
        // Verify that our original test user still exists (it would be deleted if the injection worked)
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM users WHERE username = ?")) {
            ps.setString(1, "testuser");
            ResultSet rs = ps.executeQuery();
            rs.next();
            int count = rs.getInt(1);
            Assert.assertEquals(count, 1, "Original test user should still exist after SQL injection attempt");
        }
        
        // Verify that the malicious user was added with the malicious ID as-is, not as an injection
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM users WHERE id = ?")) {
            ps.setString(1, maliciousId);
            ResultSet rs = ps.executeQuery();
            rs.next();
            int count = rs.getInt(1);
            Assert.assertEquals(count, 1, "Malicious user ID should be stored as literal string, not executed as SQL");
        }
    }
    
    @Test
    public void testUpdateUser_NoSQLInjection() throws SQLException {
        // Test that updateUser method is secure against SQL injection
        User normalUser = userService.findByUsername("testuser");
        Assert.assertNotNull(normalUser, "Test user should exist");
        
        // Create a user with the same ID but malicious data
        User maliciousUser = new User(
            normalUser.getId(), 
            normalUser.getUsername(), 
            normalUser.getPassword(), 
            "Hacked Name', email='hacked@example.com' WHERE 1=1; --", 
            "hacker@example.com"
        );
        
        // This should not cause SQL injection
        userService.updateUser(maliciousUser);
        
        // Verify that the injection didn't work by checking that only one user's name was updated
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("SELECT name FROM users WHERE id = ?")) {
            ps.setString(1, normalUser.getId());
            ResultSet rs = ps.executeQuery();
            rs.next();
            String name = rs.getString(1);
            Assert.assertEquals(name, "Hacked Name', email='hacked@example.com' WHERE 1=1; --", 
                "The name should be stored exactly as provided, not executed as SQL");
        }
    }
}