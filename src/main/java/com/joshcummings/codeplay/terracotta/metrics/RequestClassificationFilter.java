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
import java.util.regex.Pattern;

/**
 * This filter makes Terracotta Bank vulnerable to CLRF injection because
 * it doesn't validate and encode {@code classification} before including
 * it as a header.
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
			response.setHeader("X-Terracotta-Classification", validateHeaderValue(classification));
		}

		chain.doFilter(req, resp);
	}
	
	/**
	 * Validates and sanitizes a header value to prevent header injection attacks.
	 * Removes CR, LF, and other control characters that could be used for CRLF injection.
	 * 
	 * @param value The header value to sanitize
	 * @return A sanitized header value safe to use in HTTP headers
	 */
	private String validateHeaderValue(String value) {
		if (value == null) {
			return "";
		}
		// Remove CR, LF, and other control characters
		return value.replaceAll("[\r\n\f\t]|[\u0000-\u001F\u007F-\u009F]", "");
	}

	@Override
	public void destroy() { }
}
