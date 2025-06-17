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

import com.joshcummings.codeplay.terracotta.model.User;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Security test for UserService to verify SQL Injection vulnerability has been fixed.
 */
public class UserServiceSecurityTest {
    private UserService userService;

    @BeforeMethod
    public void setup() {
        userService = new UserService();
    }

    @Test
    public void testAddUserWithSQLInjection() {
        // Attempt to register a user with a SQL injection payload in the username
        String sqlInjectionUsername = "test_user'; DROP TABLE users; --";
        String password = "securePassword123!";
        String name = "Test User";
        String email = "test@example.com";
        
        User user = new User("999", sqlInjectionUsername, password, name, email);
        
        try {
            // This should not cause any SQL error due to our parameterized query
            userService.addUser(user);
            
            // Verify the user was added correctly
            User retrievedUser = userService.findByUsername(sqlInjectionUsername);
            
            // Assert that the user exists and was stored correctly
            Assert.assertNotNull(retrievedUser, "User should be found despite having special SQL characters");
            Assert.assertEquals(retrievedUser.getUsername(), sqlInjectionUsername, "Username should be stored exactly as provided");
            
            // Clean up - remove the test user
            userService.removeUser(sqlInjectionUsername);
            
        } catch (Exception e) {
            Assert.fail("Should not throw exception when using parameterized queries with SQL injection attempt", e);
        }
    }
}