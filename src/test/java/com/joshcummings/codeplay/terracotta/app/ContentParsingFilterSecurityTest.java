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
package com.joshcummings.codeplay.terracotta.app;

import com.joshcummings.codeplay.terracotta.AbstractEmbeddedTomcatTest;

import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;

/**
 * Security test for ContentParsingFilter to verify protection against XXE attacks
 */
public class ContentParsingFilterSecurityTest extends AbstractEmbeddedTomcatTest {
    
    /**
     * Test that the XML parser is configured to prevent XXE attacks
     * This test attempts to use an XML External Entity to access the file system
     */
    @Test(groups="security")
    public void testXxeProtection() throws IOException {
        // This is a malicious XML payload that attempts to exploit XXE
        String xxePayload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n" +
                "<transfer>\n" +
                "   <fromAccount>&xxe;</fromAccount>\n" +
                "   <toAccount>987654321</toAccount>\n" +
                "   <amount>100.00</amount>\n" +
                "</transfer>";
        
        HttpPost request = new HttpPost("http://localhost:8080/transferMoney?c=finance");
        request.setEntity(new StringEntity(xxePayload, ContentType.APPLICATION_XML));
        
        // Execute the request
        try (CloseableHttpResponse response = http.getForEntity(request)) {
            // If the XXE protection is working, the request should be rejected or fail to include
            // the contents of /etc/passwd in the response
            
            // Success means:
            // 1. Either the request is rejected (e.g. 400 Bad Request) 
            // 2. Or the response does not contain contents of /etc/passwd
            String responseContent = "";
            if (response.getEntity() != null) {
                responseContent = new String(response.getEntity().getContent().readAllBytes());
            }
            
            // If the response contains "root:" it likely means XXE succeeded in reading /etc/passwd
            Assert.assertFalse(responseContent.contains("root:"), 
                    "XXE attack succeeded! Response contains file system content");
        }
    }
}