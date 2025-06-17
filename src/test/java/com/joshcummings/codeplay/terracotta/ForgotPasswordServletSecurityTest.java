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

import org.testng.Assert;
import org.testng.annotations.Test;

import static org.apache.http.client.methods.RequestBuilder.post;

/**
 * Security tests for ForgotPasswordServlet to verify SQL injection vulnerabilities are fixed.
 * 
 * @author Josh Cummings
 */
public class ForgotPasswordServletSecurityTest extends AbstractEmbeddedTomcatSeleniumTest {
    
    @Test(groups = "security")
    public void testForgotPassword_SqlInjectionAttack_ShouldNotAllowBypass() {
        // Test with classic SQL injection payload (based on the original HTTP request)
        String response = http.postForContent(post("/forgotPassword")
                .addParameter("forgotPasswordAccount", "admin' OR '1'='1'--")
                .addParameter("csrfToken", ""));

        // Should not return any password information for SQL injection attempt
        Assert.assertFalse(response.contains("Your password is"), 
            "SQL injection should not return password information");
        Assert.assertTrue(response.contains("does not exist") || response.contains("error"), 
            "Should return error message for invalid/malicious input");
    }
    
    @Test(groups = "security")
    public void testForgotPassword_SqlInjectionUnionAttack_ShouldNotAllowBypass() {
        // Test with UNION-based SQL injection
        String response = http.postForContent(post("/forgotPassword")
                .addParameter("forgotPasswordAccount", "admin' UNION SELECT * FROM users--")
                .addParameter("csrfToken", ""));

        // Should not return any password information for SQL injection attempt
        Assert.assertFalse(response.contains("Your password is"), 
            "UNION-based SQL injection should not return password information");
        Assert.assertTrue(response.contains("does not exist") || response.contains("error"), 
            "Should return error message for invalid/malicious input");
    }
    
    @Test(groups = "security")
    public void testForgotPassword_SqlInjectionCommentAttack_ShouldNotAllowBypass() {
        // Test with comment-based SQL injection
        String response = http.postForContent(post("/forgotPassword")
                .addParameter("forgotPasswordAccount", "admin'--")
                .addParameter("csrfToken", ""));

        // Should not return any password information for SQL injection attempt
        Assert.assertFalse(response.contains("Your password is"), 
            "Comment-based SQL injection should not return password information");
        Assert.assertTrue(response.contains("does not exist") || response.contains("error"), 
            "Should return error message for invalid/malicious input");
    }
    
    @Test(groups = "security")
    public void testForgotPassword_ValidUser_ShouldStillWork() {
        // Test that valid users still work after the security fix
        String response = http.postForContent(post("/forgotPassword")
                .addParameter("forgotPasswordAccount", "admin")
                .addParameter("csrfToken", ""));

        // Valid user should still work
        Assert.assertTrue(response.contains("Your password is"), 
            "Valid user should still receive password information");
    }
    
    @Test(groups = "security")
    public void testForgotPassword_EmptyInput_ShouldReturnError() {
        // Test with empty input
        String response = http.postForContent(post("/forgotPassword")
                .addParameter("forgotPasswordAccount", "")
                .addParameter("csrfToken", ""));

        // Should return error for empty input
        Assert.assertTrue(response.contains("does not exist") || response.contains("error"), 
            "Empty input should return error message");
    }
    
    @Test(groups = "security")
    public void testForgotPassword_SpecialCharacters_ShouldBeSanitized() {
        // Test with special characters that should be sanitized
        String response = http.postForContent(post("/forgotPassword")
                .addParameter("forgotPasswordAccount", "admin<script>alert('xss')</script>")
                .addParameter("csrfToken", ""));

        // Should not contain any script tags in response
        Assert.assertFalse(response.contains("<script>"), 
            "Response should not contain unsanitized script tags");
        Assert.assertTrue(response.contains("does not exist") || response.contains("error"), 
            "Should return error message for invalid input with special characters");
    }
}