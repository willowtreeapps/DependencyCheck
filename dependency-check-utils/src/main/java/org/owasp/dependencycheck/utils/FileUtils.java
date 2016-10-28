/*
 * This file is part of dependency-check-core.
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
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.UUID;
import org.apache.commons.lang3.SystemUtils;

/**
 * A collection of utilities for processing information about files.
 *
 * @author Jeremy Long
 */
public final class FileUtils {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(FileUtils.class);
    /**
     * Bit bucket for non-Windows systems
     */
    private static final String BIT_BUCKET_UNIX = "/dev/null";

    /**
     * Bit bucket for Windows systems (yes, only one 'L')
     */
    private static final String BIT_BUCKET_WIN = "NUL";

    /**
     * Private constructor for a utility class.
     */
    private FileUtils() {
    }

    /**
     * Returns the (lowercase) file extension for a specified file.
     *
     * @param fileName the file name to retrieve the file extension from.
     * @return the file extension.
     */
    public static String getFileExtension(String fileName) {
        final String fileExt = FilenameUtils.getExtension(fileName);
        return null == fileExt || fileExt.isEmpty() ? null : fileExt.toLowerCase();
    }

    /**
     * Deletes a file. If the File is a directory it will recursively delete the
     * contents.
     *
     * @param file the File to delete
     * @return true if the file was deleted successfully, otherwise false
     */
    public static boolean delete(File file) {
        final boolean success = org.apache.commons.io.FileUtils.deleteQuietly(file);
        if (!success) {
            LOGGER.debug("Failed to delete file: {}; attempting to delete on exit.", file.getPath());
            file.deleteOnExit();
        }
        return success;
    }

    /**
     * Creates a unique temporary directory in the given directory.
     *
     * @param base the base directory to create a temporary directory within
     * @return the temporary directory
     * @throws IOException thrown when a directory cannot be created within the
     * base directory
     */
    public static File createTempDirectory(File base) throws IOException {
        final File tempDir = new File(base, "dctemp" + UUID.randomUUID().toString());
        if (tempDir.exists()) {
            return createTempDirectory(base);
        }
        if (!tempDir.mkdirs()) {
            throw new IOException("Could not create temp directory `" + tempDir.getAbsolutePath() + "`");
        }
        return tempDir;
    }

    /**
     * Generates a new temporary file name that is guaranteed to be unique.
     *
     * @param prefix the prefix for the file name to generate
     * @param extension the extension of the generated file name
     * @return a temporary File
     * @throws java.io.IOException thrown if the temporary folder could not be
     * created
     */
    public static File getTempFile(String prefix, String extension) throws IOException {
        final File dir = Settings.getTempDirectory();
        final String tempFileName = String.format("%s%s.%s", prefix, UUID.randomUUID().toString(), extension);
        final File tempFile = new File(dir, tempFileName);
        if (tempFile.exists()) {
            return getTempFile(prefix, extension);
        }
        return tempFile;
    }

    /**
     * Return the bit bucket for the OS. '/dev/null' for Unix and 'NUL' for
     * Windows
     *
     * @return a String containing the bit bucket
     */
    public static String getBitBucket() {
        if (SystemUtils.IS_OS_WINDOWS) {
            return BIT_BUCKET_WIN;
        } else {
            return BIT_BUCKET_UNIX;
        }
    }
}
