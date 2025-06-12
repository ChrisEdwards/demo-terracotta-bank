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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This filter adds the 'X-Terracotta-Classification' header to responses
 * based on the 'c' request parameter. It sanitizes the header value to
 * prevent CRLF injection attacks by removing control characters.
 *
 * @author Josh Cummings
 */
//@WebFilter(value="/*", dispatcherTypes={ DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.ERROR })
public class RequestClassificationFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) { }

	@Override
	public void doFilter(
				ServletRequest req,
				ServletResponse resp,
				FilterChain chain)
			throws IOException, ServletException {

		String classification = req.getParameter("c");
		if ( resp instanceof HttpServletResponse && classification != null ) {
			HttpServletResponse response = (HttpServletResponse) resp;
			// Sanitize header value to prevent CRLF injection
			String sanitizedValue = sanitizeHeaderValue(classification);
			response.setHeader("X-Terracotta-Classification", sanitizedValue);
		}

		chain.doFilter(req, resp);
	}

	@Override
	public void destroy() { }
	
	/**
	 * Sanitizes a value to be used in an HTTP header by removing CR, LF, and other control characters
	 * that could lead to header injection attacks.
	 * 
	 * @param value The value to sanitize
	 * @return A sanitized version of the value safe for use in HTTP headers
	 */
	private String sanitizeHeaderValue(String value) {
		if (value == null) {
			return null;
		}
		// Remove CR, LF, and other control characters that can be used for header injection
		return value.replaceAll("[\\r\\n\\t\\f\\u000B]|\\x00", "");
	}
}