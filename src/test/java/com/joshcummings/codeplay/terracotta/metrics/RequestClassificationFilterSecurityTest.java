package com.joshcummings.codeplay.terracotta.metrics;

import com.joshcummings.codeplay.terracotta.AbstractEmbeddedTomcatTest;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;

import static org.apache.http.client.methods.RequestBuilder.post;

/**
 * Security test for the RequestClassificationFilter to verify protection against Header Injection vulnerability.
 */
public class RequestClassificationFilterSecurityTest extends AbstractEmbeddedTomcatTest {

    @Test(groups = "security")
    public void testHeaderInjectionMitigation() throws IOException {
        // Attempt to inject a new header using CR/LF characters in the "c" parameter
        String maliciousValue = "account\r\nX-Injected-Header: Malicious";
        
        try (CloseableHttpResponse response = http.post("/forgotPassword", 
                new org.apache.http.message.BasicNameValuePair("c", maliciousValue))) {
            
            // Find the X-Terracotta-Classification header
            Header[] headers = response.getHeaders("X-Terracotta-Classification");
            
            // Verify the header exists
            Assert.assertTrue(headers.length > 0, "X-Terracotta-Classification header should exist");
            
            // Verify the header value was sanitized (no CR/LF characters)
            String headerValue = headers[0].getValue();
            Assert.assertFalse(headerValue.contains("\r") || headerValue.contains("\n"), 
                    "Header value should not contain CR or LF characters");
            
            // Verify no injected header was created
            Header[] injectedHeaders = response.getHeaders("X-Injected-Header");
            Assert.assertEquals(injectedHeaders.length, 0, "No injected headers should be present");
        }
    }
}