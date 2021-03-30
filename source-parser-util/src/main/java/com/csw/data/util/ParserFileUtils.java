package com.csw.data.util;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.FileHeader;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class ParserFileUtils {
	
	private ParserFileUtils() {
	}
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ParserFileUtils.class);

	public static String getDownloadedDirectoryPath(String filePath, List<String> downloadUrls, String type)
			throws IOException {
		String path = filePath;
		if (downloadUrls != null) {
			for (String urls : downloadUrls) {
				LOGGER.info("cve source url :: {}", urls);
				String zipFilePath = path + "_" + type + "_" + System.currentTimeMillis()
						+ ParserConstants.ZIP_FILE_EXTENSION;
				URL url = new URL(urls);
				FileUtils.copyURLToFile(url, new File(zipFilePath));
				List<FileHeader> fileHeaders = new ZipFile(zipFilePath).getFileHeaders();
				fileHeaders.stream().forEach(fileHeader -> {
					String fileName = fileHeader.getFileName();
					try {
						new ZipFile(zipFilePath).extractFile(fileName, path);
						FileUtils.deleteQuietly(new File(zipFilePath));
					} catch (ZipException e) {
						LOGGER.error(e.getMessage());
						e.printStackTrace();
					}
				});
			}
		}
		return path;
	}

	public static void createOrCleanDirectory(String path) throws IOException {
		File directory = new File(path);
		if (directory.exists()) {
			FileUtils.cleanDirectory(directory);
		} else {
			Files.createDirectories(Paths.get(path));
		}
	}
}
