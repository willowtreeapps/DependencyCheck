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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Used to analyze Ruby Bundler Gemspec.lock files utilizing the 3rd party
 * bundle-audit tool.
 *
 * @author Dale Visser
 */
@Experimental
public class RubyBundleAuditAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RubyBundleAuditAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Ruby Bundle Audit Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.PRE_INFORMATION_COLLECTION;
    /**
     * The filter defining which files will be analyzed.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames("Gemfile.lock").build();
    /**
     * Name.
     */
    public static final String NAME = "Name: ";
    /**
     * Version.
     */
    public static final String VERSION = "Version: ";
    /**
     * Advisory.
     */
    public static final String ADVISORY = "Advisory: ";
    /**
     * Criticality.
     */
    public static final String CRITICALITY = "Criticality: ";

    /**
     * The DAL.
     */
    private CveDB cvedb;

    /**
     * @return a filter that accepts files named Gemfile.lock
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Launch bundle-audit.
     *
     * @param folder directory that contains bundle audit
     * @return a handle to the process
     * @throws AnalysisException thrown when there is an issue launching bundle
     * audit
     */
    private Process launchBundleAudit(File folder) throws AnalysisException {
        if (!folder.isDirectory()) {
            throw new AnalysisException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }
        final List<String> args = new ArrayList<String>();
        final String bundleAuditPath = Settings.getString(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH);
        args.add(null == bundleAuditPath ? "bundle-audit" : bundleAuditPath);
        args.add("check");
        args.add("--verbose");
        final ProcessBuilder builder = new ProcessBuilder(args);
        builder.directory(folder);
        try {
            LOGGER.info("Launching: " + args + " from " + folder);
            return builder.start();
        } catch (IOException ioe) {
            throw new AnalysisException("bundle-audit failure", ioe);
        }
    }

    /**
     * Initialize the analyzer. In this case, extract GrokAssembly.exe to a
     * temporary location.
     *
     * @throws InitializationException if anything goes wrong
     */
    @Override
    public void initializeFileTypeAnalyzer() throws InitializationException {
        try {
            cvedb = new CveDB();
            cvedb.open();
        } catch (DatabaseException ex) {
            LOGGER.warn("Exception opening the database");
            LOGGER.debug("error", ex);
            setEnabled(false);
            throw new InitializationException("Error connecting to the database", ex);
        }
        // Now, need to see if bundle-audit actually runs from this location.
        Process process = null;
        try {
            process = launchBundleAudit(Settings.getTempDirectory());
        } catch (AnalysisException ae) {

            setEnabled(false);
            cvedb.close();
            cvedb = null;
            final String msg = String.format("Exception from bundle-audit process: %s. Disabling %s", ae.getCause(), ANALYZER_NAME);
            throw new InitializationException(msg, ae);
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create temporary file, the Ruby Bundle Audit Analyzer will be disabled", ex);
        }

        final int exitValue;
        try {
            exitValue = process.waitFor();
        } catch (InterruptedException ex) {
            setEnabled(false);
            final String msg = String.format("Bundle-audit process was interupted. Disabling %s", ANALYZER_NAME);
            throw new InitializationException(msg);
        }
        if (0 == exitValue) {
            setEnabled(false);
            final String msg = String.format("Unexpected exit code from bundle-audit process. Disabling %s: %s", ANALYZER_NAME, exitValue);
            throw new InitializationException(msg);
        } else {
            BufferedReader reader = null;
            try {
                reader = new BufferedReader(new InputStreamReader(process.getErrorStream(), "UTF-8"));
                if (!reader.ready()) {
                    LOGGER.warn("Bundle-audit error stream unexpectedly not ready. Disabling " + ANALYZER_NAME);
                    setEnabled(false);
                    throw new InitializationException("Bundle-audit error stream unexpectedly not ready.");
                } else {
                    final String line = reader.readLine();
                    if (line == null || !line.contains("Errno::ENOENT")) {
                        LOGGER.warn("Unexpected bundle-audit output. Disabling {}: {}", ANALYZER_NAME, line);
                        setEnabled(false);
                        throw new InitializationException("Unexpected bundle-audit output.");
                    }
                }
            } catch (UnsupportedEncodingException ex) {
                setEnabled(false);
                throw new InitializationException("Unexpected bundle-audit encoding.", ex);
            } catch (IOException ex) {
                setEnabled(false);
                throw new InitializationException("Unable to read bundle-audit output.", ex);
            } finally {
                if (null != reader) {
                    try {
                        reader.close();
                    } catch (IOException ex) {
                        LOGGER.debug("Error closing reader", ex);
                    }
                }
            }
        }

        if (isEnabled()) {
            LOGGER.info(ANALYZER_NAME + " is enabled. It is necessary to manually run \"bundle-audit update\" "
                    + "occasionally to keep its database up to date.");
        }
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
        return Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED;
    }

    /**
     * If {@link #analyzeFileType(Dependency, Engine)} is called, then we have
     * successfully initialized, and it will be necessary to disable
     * {@link RubyGemspecAnalyzer}.
     */
    private boolean needToDisableGemspecAnalyzer = true;

    /**
     * Determines if the analyzer can analyze the given file type.
     *
     * @param dependency the dependency to determine if it can analyze
     * @param engine the dependency-check engine
     * @throws AnalysisException thrown if there is an analysis exception.
     */
    @Override
    protected void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
        if (needToDisableGemspecAnalyzer) {
            boolean failed = true;
            final String className = RubyGemspecAnalyzer.class.getName();
            for (FileTypeAnalyzer analyzer : engine.getFileTypeAnalyzers()) {
                if (analyzer instanceof RubyBundlerAnalyzer) {
                    ((RubyBundlerAnalyzer) analyzer).setEnabled(false);
                    LOGGER.info("Disabled " + RubyBundlerAnalyzer.class.getName() + " to avoid noisy duplicate results.");
                } else if (analyzer instanceof RubyGemspecAnalyzer) {
                    ((RubyGemspecAnalyzer) analyzer).setEnabled(false);
                    LOGGER.info("Disabled " + className + " to avoid noisy duplicate results.");
                    failed = false;
                }
            }
            if (failed) {
                LOGGER.warn("Did not find " + className + '.');
            }
            needToDisableGemspecAnalyzer = false;
        }
        final File parentFile = dependency.getActualFile().getParentFile();
        final Process process = launchBundleAudit(parentFile);
        final int exitValue;
        try {
            exitValue = process.waitFor();
        } catch (InterruptedException ie) {
            throw new AnalysisException("bundle-audit process interrupted", ie);
        }
        if (exitValue < 0 || exitValue > 1) {
            final String msg = String.format("Unexpected exit code from bundle-audit process; exit code: %s", exitValue);
            throw new AnalysisException(msg);
        }
        BufferedReader rdr = null;
        BufferedReader errReader = null;
        try {
            errReader = new BufferedReader(new InputStreamReader(process.getErrorStream(), "UTF-8"));
            while (errReader.ready()) {
                final String error = errReader.readLine();
                LOGGER.warn(error);
            }
            rdr = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8"));
            processBundlerAuditOutput(dependency, engine, rdr);
        } catch (IOException ioe) {
            LOGGER.warn("bundle-audit failure", ioe);
        } finally {
            if (errReader != null) {
                try {
                    errReader.close();
                } catch (IOException ioe) {
                    LOGGER.warn("bundle-audit close failure", ioe);
                }
            }
            if (null != rdr) {
                try {
                    rdr.close();
                } catch (IOException ioe) {
                    LOGGER.warn("bundle-audit close failure", ioe);
                }
            }
        }

    }

    /**
     * Processes the bundler audit output.
     *
     * @param original the dependency
     * @param engine the dependency-check engine
     * @param rdr the reader of the report
     * @throws IOException thrown if the report cannot be read.
     */
    private void processBundlerAuditOutput(Dependency original, Engine engine, BufferedReader rdr) throws IOException {
        final String parentName = original.getActualFile().getParentFile().getName();
        final String fileName = original.getFileName();
        final String filePath = original.getFilePath();
        Dependency dependency = null;
        Vulnerability vulnerability = null;
        String gem = null;
        final Map<String, Dependency> map = new HashMap<String, Dependency>();
        boolean appendToDescription = false;
        while (rdr.ready()) {
            final String nextLine = rdr.readLine();
            if (null == nextLine) {
                break;
            } else if (nextLine.startsWith(NAME)) {
                appendToDescription = false;
                gem = nextLine.substring(NAME.length());
                if (!map.containsKey(gem)) {
                    map.put(gem, createDependencyForGem(engine, parentName, fileName, filePath, gem));
                }
                dependency = map.get(gem);
                LOGGER.debug(String.format("bundle-audit (%s): %s", parentName, nextLine));
            } else if (nextLine.startsWith(VERSION)) {
                vulnerability = createVulnerability(parentName, dependency, gem, nextLine);
            } else if (nextLine.startsWith(ADVISORY)) {
                setVulnerabilityName(parentName, dependency, vulnerability, nextLine);
            } else if (nextLine.startsWith(CRITICALITY)) {
                addCriticalityToVulnerability(parentName, vulnerability, nextLine);
            } else if (nextLine.startsWith("URL: ")) {
                addReferenceToVulnerability(parentName, vulnerability, nextLine);
            } else if (nextLine.startsWith("Description:")) {
                appendToDescription = true;
                if (null != vulnerability) {
                    vulnerability.setDescription("*** Vulnerability obtained from bundle-audit verbose report. "
                            + "Title link may not work. CPE below is guessed. CVSS score is estimated (-1.0 "
                            + " indicates unknown). See link below for full details. *** ");
                }
            } else if (appendToDescription) {
                if (null != vulnerability) {
                    vulnerability.setDescription(vulnerability.getDescription() + nextLine + "\n");
                }
            }
        }
    }

    /**
     * Sets the vulnerability name.
     *
     * @param parentName the parent name
     * @param dependency the dependency
     * @param vulnerability the vulnerability
     * @param nextLine the line to parse
     */
    private void setVulnerabilityName(String parentName, Dependency dependency, Vulnerability vulnerability, String nextLine) {
        final String advisory = nextLine.substring((ADVISORY.length()));
        if (null != vulnerability) {
            vulnerability.setName(advisory);
        }
        if (null != dependency) {
            dependency.getVulnerabilities().add(vulnerability); // needed to wait for vulnerability name to avoid NPE
        }
        LOGGER.debug(String.format("bundle-audit (%s): %s", parentName, nextLine));
    }

    /**
     * Adds a reference to the vulnerability.
     *
     * @param parentName the parent name
     * @param vulnerability the vulnerability
     * @param nextLine the line to parse
     */
    private void addReferenceToVulnerability(String parentName, Vulnerability vulnerability, String nextLine) {
        final String url = nextLine.substring(("URL: ").length());
        if (null != vulnerability) {
            final Reference ref = new Reference();
            ref.setName(vulnerability.getName());
            ref.setSource("bundle-audit");
            ref.setUrl(url);
            vulnerability.getReferences().add(ref);
        }
        LOGGER.debug(String.format("bundle-audit (%s): %s", parentName, nextLine));
    }

    /**
     * Adds the criticality to the vulnerability
     *
     * @param parentName the parent name
     * @param vulnerability the vulnerability
     * @param nextLine the line to parse
     */
    private void addCriticalityToVulnerability(String parentName, Vulnerability vulnerability, String nextLine) {
        if (null != vulnerability) {
            final String criticality = nextLine.substring(CRITICALITY.length()).trim();
            float score = -1.0f;
            Vulnerability v = null;
            try {
                v = cvedb.getVulnerability(vulnerability.getName());
            } catch (DatabaseException ex) {
                LOGGER.debug("Unable to look up vulnerability {}", vulnerability.getName());
            }
            if (v != null) {
                score = v.getCvssScore();
            } else if ("High".equalsIgnoreCase(criticality)) {
                score = 8.5f;
            } else if ("Medium".equalsIgnoreCase(criticality)) {
                score = 5.5f;
            } else if ("Low".equalsIgnoreCase(criticality)) {
                score = 2.0f;
            }
            vulnerability.setCvssScore(score);
        }
        LOGGER.debug(String.format("bundle-audit (%s): %s", parentName, nextLine));
    }

    /**
     * Creates a vulnerability.
     *
     * @param parentName the parent name
     * @param dependency the dependency
     * @param gem the gem name
     * @param nextLine the line to parse
     * @return the vulnerability
     */
    private Vulnerability createVulnerability(String parentName, Dependency dependency, String gem, String nextLine) {
        Vulnerability vulnerability = null;
        if (null != dependency) {
            final String version = nextLine.substring(VERSION.length());
            dependency.getVersionEvidence().addEvidence(
                    "bundler-audit",
                    "Version",
                    version,
                    Confidence.HIGHEST);
            vulnerability = new Vulnerability(); // don't add to dependency until we have name set later
            vulnerability.setMatchedCPE(
                    String.format("cpe:/a:%1$s_project:%1$s:%2$s::~~~ruby~~", gem, version),
                    null);
            vulnerability.setCvssAccessVector("-");
            vulnerability.setCvssAccessComplexity("-");
            vulnerability.setCvssAuthentication("-");
            vulnerability.setCvssAvailabilityImpact("-");
            vulnerability.setCvssConfidentialityImpact("-");
            vulnerability.setCvssIntegrityImpact("-");
        }
        LOGGER.debug(String.format("bundle-audit (%s): %s", parentName, nextLine));
        return vulnerability;
    }

    /**
     * Creates the dependency based off of the gem.
     *
     * @param engine the engine used for scanning
     * @param parentName the gem parent
     * @param fileName the file name
     * @param filePath the file path
     * @param gem the gem name
     * @return the dependency to add
     * @throws IOException thrown if a temporary gem file could not be written
     */
    private Dependency createDependencyForGem(Engine engine, String parentName, String fileName, String filePath, String gem) throws IOException {
        final File gemFile = new File(Settings.getTempDirectory(), gem + "_Gemfile.lock");
        if (!gemFile.createNewFile()) {
            throw new IOException("Unable to create temporary gem file");
        }
        final String displayFileName = String.format("%s%c%s:%s", parentName, File.separatorChar, fileName, gem);

        FileUtils.write(gemFile, displayFileName, Charset.defaultCharset()); // unique contents to avoid dependency bundling
        final Dependency dependency = new Dependency(gemFile);
        dependency.getProductEvidence().addEvidence("bundler-audit", "Name", gem, Confidence.HIGHEST);
        dependency.setDisplayFileName(displayFileName);
        dependency.setFileName(fileName);
        dependency.setFilePath(filePath);
        engine.getDependencies().add(dependency);
        return dependency;
    }
}
