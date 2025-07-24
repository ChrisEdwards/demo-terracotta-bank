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

import com.joshcummings.codeplay.terracotta.model.Account;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Set;

/**
 * This class tests that the AccountService is protected against SQL injection attacks.
 */
public class AccountServiceSecurityTest {
    private AccountService accountService;
    private static final String DATABASE_URL = "jdbc:hsqldb:mem:db";
    
    @BeforeMethod
    public void setUp() throws SQLException {
        // Set up the account service
        accountService = new AccountService();
        
        // Create tables for our tests
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("CREATE TABLE IF NOT EXISTS users (id VARCHAR(50), name VARCHAR(50), email VARCHAR(50), username VARCHAR(50), password VARCHAR(50), is_employee BOOLEAN)")) {
            ps.executeUpdate();
        }
        
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("CREATE TABLE IF NOT EXISTS accounts (id VARCHAR(50), amount VARCHAR(50), number BIGINT, owner_id VARCHAR(50))")) {
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
        
        // Insert test account
        try (Connection conn = DriverManager.getConnection(DATABASE_URL, "user", "password");
             PreparedStatement ps = conn.prepareStatement("INSERT INTO accounts (id, amount, number, owner_id) VALUES (?, ?, ?, ?)")) {
            ps.setString(1, "acct-id");
            ps.setString(2, "1000.00");
            ps.setLong(3, 123456789L);
            ps.setString(4, "test-id");
            ps.executeUpdate();
        }
    }
    
    @Test
    public void testFindByUsername_Normal() {
        // Test normal account lookup
        Set<Account> accounts = accountService.findByUsername("testuser");
        
        Assert.assertEquals(accounts.size(), 1, "Should find one account for test user");
        Account account = accounts.iterator().next();
        Assert.assertEquals(account.getId(), "acct-id");
        Assert.assertEquals(account.getAmount(), new BigDecimal("1000.00"));
    }
    
    @Test
    public void testFindByUsername_SQLInjection() {
        // Test SQL injection attempt fails
        Set<Account> accounts = accountService.findByUsername("' OR '1'='1");
        
        Assert.assertEquals(accounts.size(), 0, "SQL injection attack in findByUsername should not succeed");
    }
}