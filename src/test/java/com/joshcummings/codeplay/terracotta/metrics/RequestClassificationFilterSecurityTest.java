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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class RequestClassificationFilterSecurityTest {

    private RequestClassificationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    @BeforeMethod
    public void setup() {
        filter = new RequestClassificationFilter();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
    }

    @Test
    public void testHeaderWithNormalValue() throws ServletException, IOException {
        // Set up normal parameter
        request.setParameter("c", "account");
        
        // Execute filter
        filter.doFilter(request, response, chain);
        
        // Verify header is set correctly
        assertEquals("account", response.getHeader("X-Terracotta-Classification"));
    }
    
    @Test
    public void testHeaderWithNullValue() throws ServletException, IOException {
        // Do not set parameter 'c'
        
        // Execute filter
        filter.doFilter(request, response, chain);
        
        // Verify header is null or empty
        assertNull(response.getHeader("X-Terracotta-Classification"));
    }
    
    @Test
    public void testHeaderWithInjectionAttempt() throws ServletException, IOException {
        // Set up parameter with CRLF injection attempt
        request.setParameter("c", "malicious\r\nSet-Cookie: hacked=true");
        
        // Execute filter
        filter.doFilter(request, response, chain);
        
        // Verify header does not contain CRLF and is sanitized
        assertEquals("maliciousSet-Cookie: hacked=true", response.getHeader("X-Terracotta-Classification"));
    }
    
    @Test
    public void testHeaderWithControlCharacters() throws ServletException, IOException {
        // Set up parameter with various control characters
        request.setParameter("c", "test\r\n\t\f\u0000\u007F value");
        
        // Execute filter
        filter.doFilter(request, response, chain);
        
        // Verify header is sanitized
        assertEquals("test value", response.getHeader("X-Terracotta-Classification"));
    }
}