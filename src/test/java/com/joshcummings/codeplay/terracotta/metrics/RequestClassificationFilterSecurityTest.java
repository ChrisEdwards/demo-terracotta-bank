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

import org.mockito.Mockito;
import org.testng.annotations.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.anyString;

public class RequestClassificationFilterSecurityTest {

    @Test
    public void testHeaderInjectionAttackPrevention() throws IOException, ServletException {
        // Setup
        RequestClassificationFilter filter = new RequestClassificationFilter();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        
        // Simulate header injection attack with CRLF characters
        when(request.getParameter("c")).thenReturn("finance\r\nSet-Cookie: malicious=cookie");
        
        // Execute
        filter.doFilter(request, response, chain);
        
        // Verify that setHeader was not called (because we filter out CRLF)
        verify(response, never()).setHeader(eq("X-Terracotta-Classification"), anyString());
        
        // Verify filter chain was called
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testNormalHeaderSetting() throws IOException, ServletException {
        // Setup
        RequestClassificationFilter filter = new RequestClassificationFilter();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        
        // Simulate normal parameter
        when(request.getParameter("c")).thenReturn("finance");
        
        // Execute
        filter.doFilter(request, response, chain);
        
        // Verify header was set correctly
        verify(response).setHeader("X-Terracotta-Classification", "finance");
        
        // Verify filter chain was called
        verify(chain).doFilter(request, response);
    }
    
    @Test
    public void testNullClassificationParameter() throws IOException, ServletException {
        // Setup
        RequestClassificationFilter filter = new RequestClassificationFilter();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        
        // Simulate null parameter
        when(request.getParameter("c")).thenReturn(null);
        
        // Execute
        filter.doFilter(request, response, chain);
        
        // Verify header was not set
        verify(response, never()).setHeader(eq("X-Terracotta-Classification"), anyString());
        
        // Verify filter chain was called
        verify(chain).doFilter(request, response);
    }
}