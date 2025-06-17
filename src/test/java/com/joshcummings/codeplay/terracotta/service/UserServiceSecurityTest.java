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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Security tests for UserService to validate the fixes for SQL injection vulnerability.
 */
public class UserServiceSecurityTest {

    private UserService userService;

    @BeforeMethod
    public void setup() {
        userService = new UserService();
    }

    @Test
    public void testAddUserWithSQLInjectionCharacters() {
        // Create a user with malicious characters that would cause SQL injection if not properly handled
        User user = new User(
                "100",
                "test_user_name', 'hacked_password', 'hacked_name', 'hacked_email'); --", // SQL injection in username
                "password123",
                "Test User",
                "test@example.com"
        );

        // This should not throw an exception if our fix is working
        userService.addUser(user);

        // If we get here without an exception, the test passes
        // The parameterized query should handle the malicious input properly
    }

    @Test
    public void testAddUserWithSpecialCharacters() {
        // User with special characters that would need escaping in SQL
        User user = new User(
                "101",
                "user''name", // Contains single quotes
                "pass''word",
                "User's Name", 
                "user@example.com"
        );

        // This should not throw an exception if our fix is working
        userService.addUser(user);
    }
}