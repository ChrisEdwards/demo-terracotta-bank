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

import com.joshcummings.codeplay.terracotta.model.Message;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class MessageServiceSecurityTest {
    private MessageService messageService;
    private static final String DATABASE_URL = "jdbc:hsqldb:mem:db";

    @BeforeClass
    public void setup() throws SQLException {
        // Set up the service
        messageService = new MessageService();
        
        // Ensure we have a test database table
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS messages " +
                    "(id VARCHAR(50), name VARCHAR(50), email VARCHAR(50), subject VARCHAR(100), message VARCHAR(1000))");
        }
    }

    @Test
    public void testAddMessageWithSqlInjectionAttempt() throws SQLException {
        // Prepare data with SQL injection payload
        String sqlInjectionPayload = "test'); DROP TABLE messages; --";
        Message message = new Message("test-id", sqlInjectionPayload, sqlInjectionPayload, sqlInjectionPayload, sqlInjectionPayload);
        
        // Add the message that contains SQL injection attempts
        messageService.addMessage(message);
        
        // Verify the table still exists and contains our data
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM messages WHERE id = 'test-id'")) {
            
            // Table should still exist and contain our entry
            assertTrue(rs.next(), "The message should be inserted and table should exist");
            assertEquals(rs.getString("id"), "test-id");
            assertEquals(rs.getString("name"), sqlInjectionPayload);
        }
        
        // Clean up
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             Statement stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM messages WHERE id = 'test-id'");
        }
    }
}