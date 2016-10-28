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
 * Copyright (c) 2015 Institute for Defense Analyses. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.io.filefilter.NameFileFilter;
import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.ExtractionException;
import org.owasp.dependencycheck.utils.ExtractionUtil;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.UrlStringUtils;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Used to analyze a Wheel or egg distribution files, or their contents in
 * unzipped form, and collect information that can be used to determine the
 * associated CPE.
 *
 * @author Dale Visser
 */
@Experimental
public class PythonDistributionAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * Name of egg metadata files to analyze.
     */
    private static final String PKG_INFO = "PKG-INFO";

    /**
     * Name of wheel metadata files to analyze.
     */
    private static final String METADATA = "METADATA";

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory
            .getLogger(PythonDistributionAnalyzer.class);

    /**
     * The count of directories created during analysis. This is used for
     * creating temporary directories.
     */
    private static final AtomicInteger DIR_COUNT = new AtomicInteger(0);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Python Distribution Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final String[] EXTENSIONS = {"whl", "egg", "zip"};

    /**
     * Used to match on egg archive candidate extensions.
     */
    private static final FileFilter EGG_OR_ZIP = FileFilterBuilder.newInstance().addExtensions("egg", "zip").build();

    /**
     * Used to detect files with a .whl extension.
     */
    private static final FileFilter WHL_FILTER = FileFilterBuilder.newInstance().addExtensions("whl").build();

    /**
     * The parent directory for the individual directories per archive.
     */
    private File tempFileLocation;

    /**
     * Filter that detects *.dist-info files (but doesn't verify they are
     * directories.
     */
    private static final FilenameFilter DIST_INFO_FILTER = new SuffixFileFilter(
            ".dist-info");

    /**
     * Filter that detects files named "METADATA".
     */
    private static final FilenameFilter EGG_INFO_FILTER = new NameFileFilter(
            "EGG-INFO");

    /**
     * Filter that detects files named "METADATA".
     */
    private static final NameFileFilter METADATA_FILTER = new NameFileFilter(
            METADATA);

    /**
     * Filter that detects files named "PKG-INFO".
     */
    private static final NameFileFilter PKG_INFO_FILTER = new NameFileFilter(
            PKG_INFO);

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFileFilters(
            METADATA_FILTER, PKG_INFO_FILTER).addExtensions(EXTENSIONS).build();

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED;
    }

    @Override
    protected void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
        final File actualFile = dependency.getActualFile();
        if (WHL_FILTER.accept(actualFile)) {
            collectMetadataFromArchiveFormat(dependency, DIST_INFO_FILTER,
                    METADATA_FILTER);
        } else if (EGG_OR_ZIP.accept(actualFile)) {
            collectMetadataFromArchiveFormat(dependency, EGG_INFO_FILTER,
                    PKG_INFO_FILTER);
        } else {
            final String name = actualFile.getName();
            final boolean metadata = METADATA.equals(name);
            if (metadata || PKG_INFO.equals(name)) {
                final File parent = actualFile.getParentFile();
                final String parentName = parent.getName();
                dependency.setDisplayFileName(parentName + "/" + name);
                if (parent.isDirectory()
                        && (metadata && parentName.endsWith(".dist-info")
                        || parentName.endsWith(".egg-info") || "EGG-INFO"
                        .equals(parentName))) {
                    collectWheelMetadata(dependency, actualFile);
                }
            }
        }
    }

    /**
     * Collects the meta data from an archive.
     *
     * @param dependency the archive being scanned
     * @param folderFilter the filter to apply to the folder
     * @param metadataFilter the filter to apply to the meta data
     * @throws AnalysisException thrown when there is a problem analyzing the
     * dependency
     */
    private void collectMetadataFromArchiveFormat(Dependency dependency,
            FilenameFilter folderFilter, FilenameFilter metadataFilter)
            throws AnalysisException {
        final File temp = getNextTempDirectory();
        LOGGER.debug("{} exists? {}", temp, temp.exists());
        try {
            ExtractionUtil.extractFilesUsingFilter(
                    new File(dependency.getActualFilePath()), temp,
                    metadataFilter);
        } catch (ExtractionException ex) {
            throw new AnalysisException(ex);
        }

        File matchingFile = getMatchingFile(temp, folderFilter);
        if (matchingFile != null) {
            matchingFile = getMatchingFile(matchingFile, metadataFilter);
            if (matchingFile != null) {
                collectWheelMetadata(dependency, matchingFile);
            }
        }
    }

    /**
     * Makes sure a usable temporary directory is available.
     *
     * @throws InitializationException an AnalyzeException is thrown when the
     * temp directory cannot be created
     */
    @Override
    protected void initializeFileTypeAnalyzer() throws InitializationException {
        try {
            final File baseDir = Settings.getTempDirectory();
            tempFileLocation = File.createTempFile("check", "tmp", baseDir);
            if (!tempFileLocation.delete()) {
                setEnabled(false);
                final String msg = String.format(
                        "Unable to delete temporary file '%s'.",
                        tempFileLocation.getAbsolutePath());
                throw new InitializationException(msg);
            }
            if (!tempFileLocation.mkdirs()) {
                setEnabled(false);
                final String msg = String.format(
                        "Unable to create directory '%s'.",
                        tempFileLocation.getAbsolutePath());
                throw new InitializationException(msg);
            }
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create a temporary file", ex);
        }
    }

    /**
     * Deletes any files extracted from the Wheel during analysis.
     */
    @Override
    public void close() {
        if (tempFileLocation != null && tempFileLocation.exists()) {
            LOGGER.debug("Attempting to delete temporary files");
            final boolean success = FileUtils.delete(tempFileLocation);
            if (!success && tempFileLocation.exists()) {
                final String[] l = tempFileLocation.list();
                if (l != null && l.length > 0) {
                    LOGGER.warn("Failed to delete some temporary files, see the log for more details");
                }
            }
        }
    }

    /**
     * Gathers evidence from the METADATA file.
     *
     * @param dependency the dependency being analyzed
     * @param file a reference to the manifest/properties file
     */
    private static void collectWheelMetadata(Dependency dependency, File file) {
        final InternetHeaders headers = getManifestProperties(file);
        addPropertyToEvidence(headers, dependency.getVersionEvidence(),
                "Version", Confidence.HIGHEST);
        addPropertyToEvidence(headers, dependency.getProductEvidence(), "Name",
                Confidence.HIGHEST);
        final String url = headers.getHeader("Home-page", null);
        final EvidenceCollection vendorEvidence = dependency
                .getVendorEvidence();
        if (StringUtils.isNotBlank(url)) {
            if (UrlStringUtils.isUrl(url)) {
                vendorEvidence.addEvidence(METADATA, "vendor", url,
                        Confidence.MEDIUM);
            }
        }
        addPropertyToEvidence(headers, vendorEvidence, "Author", Confidence.LOW);
        final String summary = headers.getHeader("Summary", null);
        if (StringUtils.isNotBlank(summary)) {
            JarAnalyzer
                    .addDescription(dependency, summary, METADATA, "summary");
        }
    }

    /**
     * Adds a value to the evidence collection.
     *
     * @param headers the properties collection
     * @param evidence the evidence collection to add the value
     * @param property the property name
     * @param confidence the confidence of the evidence
     */
    private static void addPropertyToEvidence(InternetHeaders headers,
            EvidenceCollection evidence, String property, Confidence confidence) {
        final String value = headers.getHeader(property, null);
        LOGGER.debug("Property: {}, Value: {}", property, value);
        if (StringUtils.isNotBlank(value)) {
            evidence.addEvidence(METADATA, property, value, confidence);
        }
    }

    /**
     * Returns a list of files that match the given filter, this does not
     * recursively scan the directory.
     *
     * @param folder the folder to filter
     * @param filter the filter to apply to the files in the directory
     * @return the list of Files in the directory that match the provided filter
     */
    private static File getMatchingFile(File folder, FilenameFilter filter) {
        File result = null;
        final File[] matches = folder.listFiles(filter);
        if (null != matches && 1 == matches.length) {
            result = matches[0];
        }
        return result;
    }

    /**
     * Reads the manifest entries from the provided file.
     *
     * @param manifest the manifest
     * @return the manifest entries
     */
    private static InternetHeaders getManifestProperties(File manifest) {
        final InternetHeaders result = new InternetHeaders();
        if (null == manifest) {
            LOGGER.debug("Manifest file not found.");
        } else {
            InputStream in = null;
            try {
                in = new BufferedInputStream(new FileInputStream(manifest));
                result.load(in);
            } catch (MessagingException e) {
                LOGGER.warn(e.getMessage(), e);
            } catch (FileNotFoundException e) {
                LOGGER.warn(e.getMessage(), e);
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException ex) {
                        LOGGER.debug("failed to close input stream", ex);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Retrieves the next temporary destination directory for extracting an
     * archive.
     *
     * @return a directory
     * @throws AnalysisException thrown if unable to create temporary directory
     */
    private File getNextTempDirectory() throws AnalysisException {
        File directory;

        // getting an exception for some directories not being able to be
        // created; might be because the directory already exists?
        do {
            final int dirCount = DIR_COUNT.incrementAndGet();
            directory = new File(tempFileLocation, String.valueOf(dirCount));
        } while (directory.exists());
        if (!directory.mkdirs()) {
            throw new AnalysisException(String.format(
                    "Unable to create temp directory '%s'.",
                    directory.getAbsolutePath()));
        }
        return directory;
    }
}
