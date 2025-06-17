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
package com.joshcummings.codeplay.terracotta.metrics;

import com.joshcummings.codeplay.terracotta.AbstractEmbeddedTomcatTest;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.RequestBuilder;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;

/**
 * Security test for the RequestClassificationFilter to verify
 * header injection vulnerability is fixed.
 */
public class RequestClassificationFilterSecurityTest extends AbstractEmbeddedTomcatTest {

    /**
     * Test that the RequestClassificationFilter properly sanitizes header values
     * to prevent header injection attacks.
     */
    @Test(groups="security")
    public void testHeaderInjectionPrevention() throws IOException {
        // Test with a malicious header injection attempt using CRLF
        String maliciousValue = "finance\r\nX-Malicious-Header: evil";
        
        // Send a request to transferMoney with the malicious value in the c parameter
        try (CloseableHttpResponse response = http.getForEntity(
                RequestBuilder.get("/transferMoney").addParameter("c", maliciousValue))) {
            
            // Get all headers in the response
            Header[] headers = response.getHeaders("X-Terracotta-Classification");
            
            // Verify that we have a header but it's sanitized (only contains "finance")
            Assert.assertTrue(headers.length > 0, "X-Terracotta-Classification header should exist");
            Assert.assertEquals(headers[0].getValue(), "finance", "Header value should be sanitized to 'finance'");
            
            // Make sure the malicious header was not injected
            Header[] maliciousHeaders = response.getHeaders("X-Malicious-Header");
            Assert.assertEquals(maliciousHeaders.length, 0, "No malicious headers should be present");
        }
        
        // Test with a valid classification value
        String validValue = "finance-related";
        
        try (CloseableHttpResponse response = http.getForEntity(
                RequestBuilder.get("/transferMoney").addParameter("c", validValue))) {
            
            Header[] headers = response.getHeaders("X-Terracotta-Classification");
            
            // Verify the header is set with the safe value
            Assert.assertTrue(headers.length > 0, "X-Terracotta-Classification header should exist");
            Assert.assertEquals(headers[0].getValue(), "finance", 
                    "Header value should be sanitized to 'finance' since it contains non-allowed chars");
        }
    }
    
    /**
     * Test that the filter allows expected valid values.
     */
    @Test(groups="security")
    public void testAllowsValidValues() throws IOException {
        // Test with a safe value
        String safeValue = "finance";
        
        try (CloseableHttpResponse response = http.getForEntity(
                RequestBuilder.get("/transferMoney").addParameter("c", safeValue))) {
            
            Header[] headers = response.getHeaders("X-Terracotta-Classification");
            
            // Verify the header is set with the original value
            Assert.assertTrue(headers.length > 0, "X-Terracotta-Classification header should exist");
            Assert.assertEquals(headers[0].getValue(), safeValue, 
                    "Header should contain original value when it's safe");
        }
    }
}