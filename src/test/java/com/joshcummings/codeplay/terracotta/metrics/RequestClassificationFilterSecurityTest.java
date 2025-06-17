package com.joshcummings.codeplay.terracotta.metrics;

import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.mockito.Mockito.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public class RequestClassificationFilterSecurityTest {

    @Test
    public void testHeaderInjectionIsBlocked() throws Exception {
        // Setup
        RequestClassificationFilter filter = new RequestClassificationFilter();
        ServletRequest request = mock(ServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // Simulate a malicious header injection attempt with CRLF 
        when(request.getParameter("c")).thenReturn("finance\r\nSet-Cookie: malicious=cookie");

        // Execute
        filter.doFilter(request, response, chain);

        // Verify that the sanitized value (without CRLF) is set in the header
        verify(response).setHeader(eq("X-Terracotta-Classification"), eq("financeSet-Cookie: malicious=cookie"));
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testHeaderInjectionWithEncodedNewLinesIsBlocked() throws Exception {
        // Setup
        RequestClassificationFilter filter = new RequestClassificationFilter();
        ServletRequest request = mock(ServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // Simulate a malicious header injection attempt with encoded newlines
        when(request.getParameter("c")).thenReturn("finance\\r\\nSet-Cookie: malicious=cookie");

        // Execute
        filter.doFilter(request, response, chain);

        // Verify that the sanitized value (without the encoded newlines) is set in the header
        verify(response).setHeader(eq("X-Terracotta-Classification"), eq("financeSet-Cookie: malicious=cookie"));
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testNullParameterHandling() throws Exception {
        // Setup
        RequestClassificationFilter filter = new RequestClassificationFilter();
        ServletRequest request = mock(ServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // Simulate null parameter
        when(request.getParameter("c")).thenReturn(null);

        // Execute
        filter.doFilter(request, response, chain);

        // Verify that the header is not set when parameter is null
        verify(response, never()).setHeader(eq("X-Terracotta-Classification"), any());
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testValidHeaderPassesThrough() throws Exception {
        // Setup
        RequestClassificationFilter filter = new RequestClassificationFilter();
        ServletRequest request = mock(ServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // Simulate valid parameter
        when(request.getParameter("c")).thenReturn("finance");

        // Execute
        filter.doFilter(request, response, chain);

        // Verify that the header is set correctly for valid input
        verify(response).setHeader(eq("X-Terracotta-Classification"), eq("finance"));
        verify(chain).doFilter(request, response);
    }
}