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

import java.util.Set;

/**
 * @author Josh Cummings
 */
@Service
public class UserService extends ServiceSupport {
	public void addUser(User user) {
		String query = "INSERT INTO users (id, username, password, name, email) VALUES (?, ?, ?, ?, ?)";
		runUpdate(query, ps -> {
			ps.setString(1, user.getId());
			ps.setString(2, user.getUsername());
			ps.setString(3, user.getPassword());
			ps.setString(4, user.getName());
			ps.setString(5, user.getEmail());
			return ps;
		});
	}

	public User findByUsername(String username) {
		String query = "SELECT * FROM users WHERE username = ?";
		Set<User> users = runQuery(query, ps -> {
			ps.setString(1, username);
			return ps;
		}, (rs) ->
			new User(rs.getString(1), rs.getString(4), rs.getString(5),
				rs.getString(2), rs.getString(3), rs.getBoolean(6)));
		return users.isEmpty() ? null : users.iterator().next();
	}

	public User findByUsernameAndPassword(String username, String password) {
		String query = "SELECT * FROM users WHERE username = ? AND password = ?";
		Set<User> users = runQuery(query, ps -> {
			ps.setString(1, username);
			ps.setString(2, password);
			return ps;
		}, (rs) ->
			new User(rs.getString(1), rs.getString(4), rs.getString(5),
				rs.getString(2), rs.getString(3), rs.getBoolean(6)));
		return users.isEmpty() ? null : users.iterator().next();
	}

	public Integer count() {
		return super.count("users");
	}

	public void updateUser(User user) {
		String query = "UPDATE users SET name = ?, email = ? WHERE id = ?";
		runUpdate(query, ps -> {
			ps.setString(1, user.getName());
			ps.setString(2, user.getEmail());
			ps.setString(3, user.getId());
			return ps;
		});
	}

	public void updateUserPassword(User user) {
		String query = "UPDATE users SET password = ? WHERE id = ?";
		runUpdate(query, ps -> {
			ps.setString(1, user.getPassword());
			ps.setString(2, user.getId());
			return ps;
		});
	}

	public void removeUser(String username) {
		String query = "DELETE FROM users WHERE username = ?";
		runUpdate(query, ps -> {
			ps.setString(1, username);
			return ps;
		});
	}
}
