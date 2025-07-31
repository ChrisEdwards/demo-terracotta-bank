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

public class RequestClassificationFilterTests {

    private RequestClassificationFilter filter = new RequestClassificationFilter();

    @Test
    public void doFilterWhenValidClassificationThenSetsHeaderCorrectly() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        request.setParameter("c", "helpdesk");
        
        filter.doFilter(request, response, chain);
        
        assertEquals("helpdesk", response.getHeader("X-Terracotta-Classification"));
    }

    @Test
    public void doFilterWhenNoClassificationThenSetsNullHeader() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertNull(response.getHeader("X-Terracotta-Classification"));
    }

    @Test
    public void doFilterWhenCRLFInjectionAttemptThenSanitizesHeader() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        // Attempt CRLF injection
        request.setParameter("c", "helpdesk\r\nSet-Cookie: evil=true");
        
        filter.doFilter(request, response, chain);
        
        String classification = response.getHeader("X-Terracotta-Classification");
        // After fix, should not contain CRLF characters
        assertNotNull(classification);
        assertFalse(classification.contains("\r"));
        assertFalse(classification.contains("\n"));
        assertEquals("helpdeskSet-Cookie: evil=true", classification);
        // Should not have created additional headers
        assertNull(response.getHeader("Set-Cookie"));
    }
}