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

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.testng.annotations.Test;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.testng.Assert.*;

public class RequestClassificationFilterSecurityTest {

    private RequestClassificationFilter filter = new RequestClassificationFilter();
    
    @Test
    public void testNormalHeaderValue() throws IOException, ServletException {
        // Test with normal value
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/checkLookup");
        request.setParameter("c", "finance");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals("finance", response.getHeader("X-Terracotta-Classification"));
    }
    
    @Test
    public void testHeaderInjectionWithCRLF() throws IOException, ServletException {
        // Manually create CRLF characters
        String maliciousInput = "finance" + (char)13 + (char)10 + "Set-Cookie: hacked=true";
        
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/checkLookup");
        request.setParameter("c", maliciousInput);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        // Check that CRLF was removed
        assertEquals("finance", response.getHeader("X-Terracotta-Classification"));
        assertNull(response.getHeader("Set-Cookie"));
    }
    
    @Test
    public void testNullParameter() throws IOException, ServletException {
        // Test with null value
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/checkLookup");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        // Header should not be set when parameter is null
        assertNull(response.getHeader("X-Terracotta-Classification"));
    }
    
    @Test
    public void testHeaderInjectionWithControlCharacters() throws IOException, ServletException {
        // Test with CR
        verifyControlCharSanitized("test" + (char)13 + "Set-Cookie: session=hacked");
        
        // Test with LF
        verifyControlCharSanitized("test" + (char)10 + "Set-Cookie: session=hacked");
        
        // Test with CRLF and tab
        verifyControlCharSanitized("test" + (char)13 + (char)10 + (char)9 + "Set-Cookie: session=hacked");
        
        // Test with null byte
        verifyControlCharSanitized("test" + (char)0 + "Set-Cookie: session=hacked");
    }
    
    private void verifyControlCharSanitized(String input) throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/checkLookup");
        request.setParameter("c", input);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        // Get sanitized header value
        String headerValue = response.getHeader("X-Terracotta-Classification");
        
        // Check that control characters were removed
        assertTrue(headerValue.indexOf((char)13) == -1, "CR should be removed");
        assertTrue(headerValue.indexOf((char)10) == -1, "LF should be removed");
        assertTrue(headerValue.indexOf((char)9) == -1, "TAB should be removed");
        assertTrue(headerValue.indexOf((char)0) == -1, "NULL byte should be removed");
        
        // Should be sanitized to "testSet-Cookie: session=hacked"
        assertEquals("testSet-Cookie: session=hacked", headerValue);
    }
}