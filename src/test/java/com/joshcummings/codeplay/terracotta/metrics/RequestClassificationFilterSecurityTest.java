package com.joshcummings.codeplay.terracotta.metrics;

import org.testng.annotations.Test;
import org.testng.annotations.BeforeMethod;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.*;

/**
 * Security test for the RequestClassificationFilter to validate the fixed header injection vulnerability.
 */
public class RequestClassificationFilterSecurityTest {

    private RequestClassificationFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;

    @BeforeMethod
    public void setup() {
        filter = new RequestClassificationFilter();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
    }

    @Test
    public void testValidClassificationIsSet() throws Exception {
        // Test with a valid classification from the whitelist
        when(request.getParameter("c")).thenReturn("helpdesk");
        
        filter.doFilter(request, response, chain);
        
        // Verify that the header is set with the valid classification
        verify(response).setHeader("X-Terracotta-Classification", "helpdesk");
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testInvalidClassificationIsNotSet() throws Exception {
        // Test with an invalid classification (not in the whitelist)
        when(request.getParameter("c")).thenReturn("malicious\r\nX-Malicious-Header: injected");
        
        filter.doFilter(request, response, chain);
        
        // Verify that the header is NOT set with the invalid classification
        verify(response, never()).setHeader(eq("X-Terracotta-Classification"), eq("malicious\r\nX-Malicious-Header: injected"));
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testNullClassificationIsHandledSafely() throws Exception {
        // Test with null classification
        when(request.getParameter("c")).thenReturn(null);
        
        filter.doFilter(request, response, chain);
        
        // Verify that the header is not set when the classification is null
        verify(response, never()).setHeader(eq("X-Terracotta-Classification"), any());
        verify(chain).doFilter(request, response);
    }
}