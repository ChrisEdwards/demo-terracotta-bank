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
package com.joshcummings.codeplay.terracotta.metrics;

import com.joshcummings.codeplay.terracotta.AbstractEmbeddedTomcatTest;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.RequestBuilder;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;

/**
 * Security test for {@link RequestClassificationFilter} to verify that it
 * properly sanitizes header values to prevent header injection.
 */
public class RequestClassificationFilterSecurityTest extends AbstractEmbeddedTomcatTest {

    /**
     * Test that the RequestClassificationFilter properly sanitizes the 'c' parameter
     * to prevent header injection attacks.
     * 
     * This test attempts to inject a new header using CRLF characters in the 'c' parameter
     * and verifies that the injection does not succeed.
     */
    @Test(groups = "web")
    public void testHeaderInjectionPrevention() throws IOException {
        // Test payload with CRLF to attempt header injection
        String maliciousClassification = "account\r\nX-Injected-Header: Malicious-Value";
        
        try (CloseableHttpResponse response = http.getForEntity(
                RequestBuilder.get("/changePassword")
                .addParameter("c", maliciousClassification))) {
            
            // Check that the classification header is sanitized correctly
            Header classificationHeader = response.getFirstHeader("X-Terracotta-Classification");
            
            if (classificationHeader != null) {
                // The header value should just contain "account" with CRLF characters removed
                Assert.assertEquals(classificationHeader.getValue(), "account");
                
                // Ensure no injected header is present
                Header injectedHeader = response.getFirstHeader("X-Injected-Header");
                Assert.assertNull(injectedHeader, "Injected header should not be present");
            }
        }
    }
}