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
package com.joshcummings.codeplay.terracotta;

import com.joshcummings.codeplay.terracotta.model.User;
import com.joshcummings.codeplay.terracotta.service.UserService;
import org.testng.Assert;
import org.testng.annotations.Test;

import static org.apache.http.client.methods.RequestBuilder.post;

public class UserServiceSecurityTest extends AbstractEmbeddedTomcatTest {

	@Test(groups="security")
	public void testSqlInjectionInUsername() {
		// Test SQL injection attempt in username parameter
		String maliciousUsername = "admin' OR '1'='1";
		String password = "anypassword";
		
		String content = http.postForContent(post("/login")
				.addParameter("username", maliciousUsername)
				.addParameter("password", password));

		// SQL injection should not succeed - should get error message
		Assert.assertTrue(content.contains("provided is incorrect"), 
				"SQL injection in username should fail authentication");
	}

	@Test(groups="security")
	public void testSqlInjectionInPassword() {
		// Test SQL injection attempt in password parameter
		String username = "admin";
		String maliciousPassword = "anypassword' OR '1'='1";
		
		String content = http.postForContent(post("/login")
				.addParameter("username", username)
				.addParameter("password", maliciousPassword));

		// SQL injection should not succeed - should get error message
		Assert.assertTrue(content.contains("provided is incorrect"), 
				"SQL injection in password should fail authentication");
	}

	@Test(groups="security")
	public void testSqlInjectionBothParameters() {
		// Test SQL injection in both username and password parameters
		String maliciousUsername = "admin' OR '1'='1' --";
		String maliciousPassword = "' OR '1'='1";
		
		String content = http.postForContent(post("/login")
				.addParameter("username", maliciousUsername)
				.addParameter("password", maliciousPassword));

		// SQL injection should not succeed - should get error message
		Assert.assertTrue(content.contains("provided is incorrect"), 
				"SQL injection in both parameters should fail authentication");
	}

	@Test(groups="security")
	public void testValidLoginStillWorks() {
		// Ensure valid login still works after security fix
		String content = http.postForContent(post("/login")
				.addParameter("username", "admin")
				.addParameter("password", "admin"));

		Assert.assertTrue(content.contains("Welcome, Admin Admin!"), 
				"Valid login should still work after security fix");
	}
}