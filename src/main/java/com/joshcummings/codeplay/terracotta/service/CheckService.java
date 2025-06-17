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
		// Validate the check number first
		if (!isValidCheckNumber(checkNumber)) {
			throw new IllegalArgumentException("Invalid check number format");
		}
		
		try (ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry ze;
			while ((ze = zis.getNextEntry()) != null) {
				try {
					// Extract just the filename from the ZIP entry to avoid path traversal
					String entryName = new File(ze.getName()).getName();
					
					// Validate the entry name
					if (entryName.isEmpty() || entryName.contains("/") || 
					    entryName.contains("\\") || entryName.contains("..")) {
						continue; // Skip invalid entries
					}
					
					updateCheckImage(checkNumber + "/" + entryName, zis);
				} catch (Exception e) {
					e.printStackTrace(); // try to upload the other ones
				}
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public void updateCheckImage(String checkNumber, InputStream is) {
		try {
			// Validate the check number first
			if (!isValidCheckNumber(checkNumber)) {
				throw new IllegalArgumentException("Invalid check number format");
			}
			
			File checkImageFile = new File(CHECK_IMAGE_LOCATION, checkNumber);
			
			// Ensure the target directory exists
			File parentDir = checkImageFile.getParentFile();
			if (!parentDir.exists()) {
				parentDir.mkdirs();
			}
			
			// Validate the canonical path to ensure it's within the expected directory
			File checkImageDir = new File(CHECK_IMAGE_LOCATION).getCanonicalFile();
			File requestedFile = checkImageFile.getCanonicalFile();
			
			if (!requestedFile.getPath().startsWith(checkImageDir.getPath())) {
				throw new IllegalArgumentException("Access to the requested file is not allowed");
			}
			
			try (FileOutputStream fos = new FileOutputStream(requestedFile)) {
				byte[] b = new byte[1024];
				int read;
				while ((read = is.read(b)) != -1) {
					fos.write(b, 0, read);
				}
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	/**
	 * Validates if a check number contains path traversal attempts
	 * 
	 * @param checkNumber the check number to validate
	 * @return true if the check number is valid, false otherwise
	 */
	private boolean isValidCheckNumber(String checkNumber) {
		// Check for null or empty
		if (checkNumber == null || checkNumber.isEmpty()) {
			return false;
		}
		
		// Check for path traversal characters
		if (checkNumber.contains("/") || checkNumber.contains("\\") || 
		    checkNumber.contains("..") || checkNumber.contains(":")) {
			return false;
		}
		
		// Additional validation could be added here such as limiting to 
		// alphanumeric characters, size limits, etc.
		return true;
	}
	
	public void findCheckImage(String checkNumber, OutputStream os) {
		if (!isValidCheckNumber(checkNumber)) {
			throw new IllegalArgumentException("Invalid check number format");
		}

		try {
			File checkImageFile = new File(CHECK_IMAGE_LOCATION, checkNumber);
			
			// Validate the canonical path to ensure it's within the expected directory
			File checkImageDir = new File(CHECK_IMAGE_LOCATION).getCanonicalFile();
			File requestedFile = checkImageFile.getCanonicalFile();
			
			if (!requestedFile.getPath().startsWith(checkImageDir.getPath())) {
				throw new IllegalArgumentException("Access to the requested file is not allowed");
			}
			
			try (FileInputStream fis = new FileInputStream(requestedFile)) {
				byte[] b = new byte[1024];
				int read;
				while ((read = fis.read(b)) != -1) {
					os.write(b, 0, read);
				}
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}
}
