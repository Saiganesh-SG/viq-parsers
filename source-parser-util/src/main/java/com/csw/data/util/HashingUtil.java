package com.csw.data.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashingUtil {

	public static String getShaChecksum(File file) throws IOException, NoSuchAlgorithmException {

		MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");

		FileInputStream fis = new FileInputStream(file);

		byte[] byteArray = new byte[1024];
		int bytesCount = 0;

		while ((bytesCount = fis.read(byteArray)) != -1) {
			shaDigest.update(byteArray, 0, bytesCount);
		}
		;

		fis.close();

		byte[] bytes = shaDigest.digest();

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
		}

		return sb.toString();
	}

}
