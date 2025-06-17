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
package com.joshcummings.codeplay.terracotta.service;

import com.joshcummings.codeplay.terracotta.model.User;
import org.springframework.stereotype.Service;

import java.sql.SQLException;
import java.util.Set;

/**
 * This class makes Terracotta Bank vulnerable to SQL injection
 * attacks because it concatenates queries instead of using
 * bind variables.
 *
 * @author Josh Cummings
 */
@Service
public class UserService extends ServiceSupport {
	public void addUser(User user) {
		runUpdate("INSERT INTO users (id, username, password, name, email)"
				+ " VALUES ('" + user.getId() + "','" + user.getUsername() + 
				"','" + user.getPassword() + "','" + user.getName() + "','" + user.getEmail() + "')");
	}

	public User findByUsername(String username) {
		// Validate input to prevent SQL injection
		if (username == null) {
			return null;
		}
		Set<User> users = runQuery("SELECT * FROM users WHERE username = ?", 
			ps -> {
				try {
					ps.setString(1, sanitizeUsernameInput(username));
					return ps;
				} catch (SQLException e) {
					throw new IllegalArgumentException("Failed to set parameter", e);
				}
			},
			(rs) -> new User(rs.getString(1), rs.getString(4), rs.getString(5),
				rs.getString(2), rs.getString(3), rs.getBoolean(6)));
		return users.isEmpty() ? null : users.iterator().next();
	}

	/**
	 * Sanitizes username input to prevent SQL injection attacks.
	 * This method validates and cleans the username input.
	 * @param username the raw username input
	 * @return sanitized username
	 */
	private String sanitizeUsernameInput(String username) {
		if (username == null || username.trim().isEmpty()) {
			return "";
		}
		// Remove any potentially dangerous characters and limit length
		String sanitized = username.trim().replaceAll("[^a-zA-Z0-9@._-]", "");
		// Limit username length to prevent buffer overflow attacks
		return sanitized.length() > 100 ? sanitized.substring(0, 100) : sanitized;
	}

	public User findByUsernameAndPassword(String username, String password) {
		Set<User> users = runQuery("SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'", (rs) ->
			new User(rs.getString(1), rs.getString(4), rs.getString(5),
				rs.getString(2), rs.getString(3), rs.getBoolean(6)));
		return users.isEmpty() ? null : users.iterator().next();
	}

	public Integer count() {
		return super.count("users");
	}

	public void updateUser(User user) {
		runUpdate("UPDATE users SET name = '" + user.getName() + "', email = '" + user.getEmail() + "' "+
					"WHERE id = '" + user.getId() + "'");
	}

	public void updateUserPassword(User user) {
		runUpdate("UPDATE users SET password = '" + user.getPassword() + "' WHERE id = '" + user.getId() + "'");
	}

	public void removeUser(String username) {
		runUpdate("DELETE FROM users WHERE username = '" + username + "'");
	}
}
