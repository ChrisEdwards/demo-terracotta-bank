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
import org.testng.annotations.AfterMethod;
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
    
    @AfterMethod
    public void tearDown() throws SQLException {
        // Clean up the database after each test
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("DROP TABLE users")) {
            ps.executeUpdate();
        } catch (SQLException e) {
            // Ignore errors if table doesn't exist
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
        // The string "\' OR \'1\'=\'1" is a common SQL injection attack
        User user = userService.findByUsernameAndPassword("testuser", "\' OR \'1\'=\'1");
        
        Assert.assertNull(user, "SQL injection attack should not succeed");
    }
    
    @Test
    public void testFindByUsernameAndPassword_SQLInjectionInUsername() {
        // Test attempt at SQL injection in username field should fail
        User user = userService.findByUsernameAndPassword("\' OR \'1\'=\'1", "password");
        
        Assert.assertNull(user, "SQL injection attack in username should not succeed");
    }
    
    @Test
    public void testFindByUsername_ValidUsername() {
        // Test finding a user by valid username
        User user = userService.findByUsername("testuser");
        
        Assert.assertNotNull(user, "User should be found with valid username");
        Assert.assertEquals(user.getUsername(), "testuser");
    }
    
    @Test
    public void testFindByUsername_SQLInjection() {
        // Test attempt at SQL injection should fail
        User user = userService.findByUsername("\' OR \'1\'=\'1");
        
        Assert.assertNull(user, "SQL injection attack should not succeed in findByUsername");
    }
    
    @Test
    public void testUpdateUser_ValidUser() throws SQLException {
        // Create a user to update
        User user = userService.findByUsername("testuser");
        user.setName("Updated Name");
        user.setEmail("updated@example.com");
        
        // Update the user
        userService.updateUser(user);
        
        // Check if the user was updated correctly
        User updatedUser = userService.findByUsername("testuser");
        Assert.assertEquals(updatedUser.getName(), "Updated Name");
        Assert.assertEquals(updatedUser.getEmail(), "updated@example.com");
    }
    
    @Test
    public void testUpdateUserPassword_ValidUser() throws SQLException {
        // Create a user to update
        User user = userService.findByUsername("testuser");
        user.setPassword("newpassword");
        
        // Update the user's password
        userService.updateUserPassword(user);
        
        // Check if the password was updated correctly by trying to log in with new password
        User loggedInUser = userService.findByUsernameAndPassword("testuser", "newpassword");
        Assert.assertNotNull(loggedInUser, "User should be found with updated password");
    }
}