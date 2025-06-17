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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * This filter makes Terracotta Bank vulnerable to CLRF injection because
 * it doesn't validate and encode {@code classification} before including
 * it as a header.
 *
 * @author Josh Cummings
 */
//@WebFilter(value="/*", dispatcherTypes={ DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.ERROR })
public class RequestClassificationFilter implements Filter {
	
	// Define allowed classifications
	private static final Set<String> ALLOWED_CLASSIFICATIONS = new HashSet<>(Arrays.asList(
		"account", "admin", "transfer", "message", "public"
	));
	
	/**
	 * Validates that the classification parameter contains only allowed values.
	 * 
	 * @param classification The user-provided classification string
	 * @return The validated classification or a default value if invalid
	 */
	private String validateClassification(String classification) {
		if (classification != null && ALLOWED_CLASSIFICATIONS.contains(classification)) {
			return classification;
		}
		return "unclassified"; // Default value if invalid or null
	}

	@Override
	public void init(FilterConfig filterConfig) { }

	@Override
	public void doFilter(
					ServletRequest req,
					ServletResponse resp,
					FilterChain chain)
			throws IOException, ServletException {

		String classification = req.getParameter("c");
		if ( resp instanceof HttpServletResponse ) {
			HttpServletResponse response = (HttpServletResponse) resp;
			response.setHeader("X-Terracotta-Classification", validateClassification(classification));
		}

		chain.doFilter(req, resp);
	}

	@Override
	public void destroy() { }
}
