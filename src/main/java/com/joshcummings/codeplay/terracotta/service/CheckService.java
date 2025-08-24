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
		// Validate the check number to prevent path traversal
		if (!isValidCheckNumber(checkNumber)) {
			throw new IllegalArgumentException("Invalid check number format");
		}
		
		try (ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry ze;
			while ( (ze = zis.getNextEntry()) != null ) {
				try {
					// Make sure the ZIP entry name is safe
					String entryName = ze.getName();
					if (entryName.contains("../") || entryName.contains("..\\") || 
						entryName.startsWith("/") || entryName.startsWith("\\")) {
						throw new IllegalArgumentException("Invalid ZIP entry path");
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
		// Extract just the filename portion for validation if path includes a directory
		String filenameToCheck = checkNumber;
		if (checkNumber.contains("/")) {
			String[] parts = checkNumber.split("/");
			filenameToCheck = parts[0]; // Validate the first part which is the check number
		}
		
		// Validate input to prevent path traversal
		if (!isValidCheckNumber(filenameToCheck)) {
			throw new IllegalArgumentException("Invalid check number format");
		}
		
		try {
			String location = new URI(CHECK_IMAGE_LOCATION + "/" + checkNumber).normalize().toString();
			
			// Additional safety check - ensure the normalized path is still within the intended directory
			File targetFile = new File(location);
			File baseDir = new File(CHECK_IMAGE_LOCATION).getCanonicalFile();
			if (!targetFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
				throw new IllegalArgumentException("Path traversal attempt detected");
			}
			
			try ( FileOutputStream fos = new FileOutputStream(location) ) {
				byte[] b = new byte[1024];
				int read;
				while ( ( read = is.read(b) ) != -1 ) {
					fos.write(b, 0, read);
				}
			} catch ( IOException e ) {
				throw new IllegalArgumentException(e);
			}
		} catch ( URISyntaxException | IOException e ) {
			throw new IllegalArgumentException(e);
		}
	}
	
	/**
	 * Validates that the given check number is safe to use in file paths
	 * 
	 * @param checkNumber the check number to validate
	 * @return true if the check number is valid, false otherwise
	 */
	public boolean isValidCheckNumber(String checkNumber) {
		// Allow only alphanumeric characters and basic symbols - no path traversal
		return checkNumber != null && checkNumber.matches("^[a-zA-Z0-9-_]+$");
	}

	public void findCheckImage(String checkNumber, OutputStream os) {
		// Validate input to prevent path traversal
		if (!isValidCheckNumber(checkNumber)) {
			throw new IllegalArgumentException("Invalid check number format");
		}
		
		try ( FileInputStream fis = new FileInputStream(CHECK_IMAGE_LOCATION + "/" + checkNumber) ) {
			byte[] b = new byte[1024];
			int read;
			while ( ( read = fis.read(b) ) != -1 ) {
				os.write(b, 0, read);
			}
		} catch ( IOException e ) {
			throw new IllegalArgumentException(e);
		}
	}
}
