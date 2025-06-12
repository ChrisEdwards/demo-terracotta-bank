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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.joshcummings.codeplay.terracotta.model.Check;
import org.springframework.stereotype.Service;

/**
 * This class makes Terracotta Bank vulnerable to SQL injection
 * attacks because it concatenates queries instead of using
 * bind variables.
 *
 * This class also makes the site vulnerable to Directory
 * Traversal attacks because it concatenates user input to
 * compose file system paths.
 *
 * @author Josh Cummings
 */
@Service
public class CheckService extends ServiceSupport {
	private static final String CHECK_IMAGE_LOCATION = "images/checks";
	static {
		new File(CHECK_IMAGE_LOCATION).mkdirs();
	}
	
	public void addCheck(Check check) {
		runUpdate("INSERT INTO checks (id, number, amount, account_id)"
				+ " VALUES ('" + check.getId() + "','" + check.getNumber() + 
				"','" + check.getAmount() + "','" + check.getAccountId() + "')");
	}

	public void updateCheckImagesBulk(String checkNumber, InputStream is) {
		if (checkNumber == null) {
			throw new IllegalArgumentException("Check number cannot be null");
		}
		
		try (ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry ze;
			while ( (ze = zis.getNextEntry()) != null ) {
				try {
					// Verify the zip entry name is safe
					String entryName = ze.getName();
					if (entryName == null || entryName.contains("..") || entryName.startsWith("/")) {
						continue; // Skip potentially malicious entries
					}
					updateCheckImage(checkNumber + "/" + entryName, zis);
				} catch ( Exception e ) {
					e.printStackTrace(); // try to upload the other ones
				}
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public void updateCheckImage(String checkNumber, InputStream is) {
		if (checkNumber == null) {
			throw new IllegalArgumentException("Check number cannot be null");
		}
		
		try {
			Path basePath = Paths.get(CHECK_IMAGE_LOCATION).toAbsolutePath();
			Path targetPath = basePath.resolve(checkNumber).normalize();
			
			// Verify the path is still within the base directory
			if (!targetPath.startsWith(basePath)) {
				throw new IllegalArgumentException("Invalid check number path");
			}
			
			try (FileOutputStream fos = new FileOutputStream(targetPath.toFile())) {
				byte[] b = new byte[1024];
				int read;
				while ((read = is.read(b)) != -1) {
					fos.write(b, 0, read);
				}
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	public void findCheckImage(String checkNumber, OutputStream os) {
		if (checkNumber == null) {
			throw new IllegalArgumentException("Check number cannot be null");
		}
		
		Path basePath = Paths.get(CHECK_IMAGE_LOCATION).toAbsolutePath();
		Path targetPath = basePath.resolve(checkNumber).normalize();
		
		// Verify the path is still within the base directory
		if (!targetPath.startsWith(basePath)) {
			throw new IllegalArgumentException("Invalid check number path");
		}
		
		try (FileInputStream fis = new FileInputStream(targetPath.toFile())) {
			byte[] b = new byte[1024];
			int read;
			while ((read = fis.read(b)) != -1) {
				os.write(b, 0, read);
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}
}
