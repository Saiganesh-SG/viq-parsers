package com.csw.data.mitre.utils;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.FileHeader;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.csw.data.util.ParserConstants;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ParserFileUtils {
	
	private ParserFileUtils() {
	}
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ParserFileUtils.class);
	
	/**
	 * Processs files in directory with selected extension.
	 *
	 * @param sourceBaseDirectoryPath the directory path
	 * @param downloadUrls 
	 * @param fileExtension the file extension
	 * @return the list
	 */
	public static List<String> extractSourceFilesWithExtension(String sourceBaseDirectoryPath, List<String> downloadUrls, String topic, String fileExtension) {
		downloadedFileToSourceDirectory(sourceBaseDirectoryPath, downloadUrls, topic);
		List<String> sourceFiles = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(Paths.get(sourceBaseDirectoryPath))) {
            sourceFiles = walk
                    .filter(p -> !Files.isDirectory(p))
                    .map(p -> p.toString().toLowerCase())
                    .filter(f -> f.endsWith(fileExtension))
                    .collect(Collectors.toList());
        } catch (IOException e) {
        	LOGGER.error("Error in reading source file from the directory: {}", e.getMessage(), e);
		}
        return sourceFiles;
	}

	private static String downloadedFileToSourceDirectory(String filePath, List<String> downloadUrls, String type) {
		String path = filePath;
		for (String urls : downloadUrls) {
			String zipFilePath = path + "_" + type + "_" + System.currentTimeMillis() + ParserConstants.ZIP_FILE_EXTENSION;
			try {
				URL url = new URL(urls);
				FileUtils.copyURLToFile(url, new File(zipFilePath));
				List<FileHeader> fileHeaders = new ZipFile(zipFilePath).getFileHeaders();
				fileHeaders.stream().forEach(fileHeader -> {
					String fileName = fileHeader.getFileName();
					try {
						new ZipFile(zipFilePath).extractFile(fileName, path);
					} catch (ZipException e) {
						LOGGER.error("ZipException while extracting source file : {}", e.getMessage(), e);
					}
					FileUtils.deleteQuietly(new File(zipFilePath));
				});
			} catch (IOException e) {
				LOGGER.error("IOException while extracting source file : {}", e.getMessage(), e);
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
