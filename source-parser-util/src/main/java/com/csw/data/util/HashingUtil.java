package com.csw.data.util;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * The Class HashingUtil.
 */
public class HashingUtil {

	/**
	 * Instantiates a new hashing util.
	 */
	private HashingUtil() {
	}

	/**
	 * Gets the sha checksum.
	 *
	 * @param content the content
	 * @return the sha checksum
	 */
	public static String getShaChecksum(byte[] content) {
		return DigestUtils.sha256Hex(content);
	}

}
