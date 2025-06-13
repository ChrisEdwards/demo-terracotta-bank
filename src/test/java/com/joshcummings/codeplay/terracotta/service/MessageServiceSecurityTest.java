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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.sql.SQLException;
import java.util.Set;

public class MessageServiceSecurityTest {
    
    private MessageService messageService;
    
    @BeforeMethod
    public void setup() {
        messageService = new MessageService();
    }
    
    @Test
    public void testSqlInjectionAttempt() {
        // Test with SQL injection payloads
        String maliciousId = "1'; DROP TABLE messages; --";
        String maliciousName = "name'; DELETE FROM messages; --";
        String maliciousEmail = "email@test.com'; UPDATE messages SET message='hacked'; --";
        String maliciousSubject = "subject'; TRUNCATE TABLE messages; --";
        String maliciousMessage = "message'; INSERT INTO messages VALUES ('999','hacker','hacker@evil.com','pwned','system compromised'); --";
        
        // This should execute without SQL errors because prepared statements handle the malicious input properly
        Message message = new Message(
            maliciousId, 
            maliciousName,
            maliciousEmail,
            maliciousSubject,
            maliciousMessage
        );
        
        // The addMessage method should handle the malicious input safely
        messageService.addMessage(message);
        
        // Verify we can still query the database after the attempted attack
        Set<Message> messages = messageService.findAll();
        // No assertions here - the test passes if no SQLException is thrown
    }
}