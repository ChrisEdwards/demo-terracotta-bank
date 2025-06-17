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

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

import static org.testng.Assert.*;

public class RequestClassificationFilterSecurityTest {

    private RequestClassificationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain filterChain;

    @BeforeMethod
    public void setUp() {
        filter = new RequestClassificationFilter();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
    }

    @Test
    public void doFilterWhenValidClassificationThenSetsHeader() throws IOException, ServletException {
        request.setParameter("c", "finance");
        
        filter.doFilter(request, response, filterChain);
        
        assertEquals("finance", response.getHeader("X-Terracotta-Classification"));
    }

    @Test
    public void doFilterWhenNullClassificationThenNoHeader() throws IOException, ServletException {
        // No parameter set (null)
        
        filter.doFilter(request, response, filterChain);
        
        assertNull(response.getHeader("X-Terracotta-Classification"));
    }

    @Test
    public void doFilterWhenHeaderInjectionAttemptThenSanitized() throws IOException, ServletException {
        // Based on the original HTTP request - simulating header injection attempt
        String maliciousInput = "finance\r\nX-Injected-Header: malicious-value\r\nAnother-Header: evil";
        request.setParameter("c", maliciousInput);
        
        filter.doFilter(request, response, filterChain);
        
        String headerValue = response.getHeader("X-Terracotta-Classification");
        assertNotNull(headerValue);
        assertEquals("financeX-Injected-Header: malicious-valueAnother-Header: evil", headerValue);
        // Verify no additional headers were injected
        assertNull(response.getHeader("X-Injected-Header"));
        assertNull(response.getHeader("Another-Header"));
    }

    @Test
    public void doFilterWhenControlCharactersThenRemoved() throws IOException, ServletException {
        String inputWithControlChars = "finance\u0000\u0001\u0002\u007f\u0080";
        request.setParameter("c", inputWithControlChars);
        
        filter.doFilter(request, response, filterChain);
        
        assertEquals("finance", response.getHeader("X-Terracotta-Classification"));
    }

    @Test
    public void doFilterWhenEmptyAfterSanitizationThenNoHeader() throws IOException, ServletException {
        String onlyControlChars = "\r\n\u0000\u0001\u0002";
        request.setParameter("c", onlyControlChars);
        
        filter.doFilter(request, response, filterChain);
        
        assertNull(response.getHeader("X-Terracotta-Classification"));
    }

    @Test
    public void doFilterWhenWhitespaceOnlyThenNoHeader() throws IOException, ServletException {
        request.setParameter("c", "   \t   ");
        
        filter.doFilter(request, response, filterChain);
        
        assertNull(response.getHeader("X-Terracotta-Classification"));
    }

    // Mock FilterChain for testing
    private static class MockFilterChain implements FilterChain {
        @Override
        public void doFilter(ServletRequest request, ServletResponse response) 
                throws IOException, ServletException {
            // Mock implementation - no action needed for our tests
        }
    }
}