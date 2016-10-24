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
 * Copyright (c) 2016 IBM Corporation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This analyzer is used to analyze carthage files
 *
 * @author Erik LaManna
 */
public class CarthageAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CarthageAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Carthage Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file name to scan.
     */
    public static final String Cartfile = "Cartfile";

    /**
     * Filter that detects files named "Cartfile".
     */
    private static final FileFilter CARTFILE_FILTER = FileFilterBuilder.newInstance().addFilenames(Cartfile).build();

    /**
     * The capture group #1 is the dependency, capture group #2 is the version
     * Note that this only gets the actual dependencies and not the subdependencies because the actual version of
     * those should be in the main dependency list. Note that this ignores github dependencies for now
     */
    public static final Pattern GITHUB_LINE_PATTERN = Pattern.compile("^github \\\"(.*)\\\" .+ (.*)\\s*");
    public static final Pattern GIT_TAG_COMMIT_PATTERN = Pattern.compile("^git\\S* \\\"(.*)\\\" \\\"(.*)\\\"\\s*");

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return CARTFILE_FILTER;
    }

    @Override
    protected void initializeFileTypeAnalyzer() {
        // NO-OP
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
        return Settings.KEYS.ANALYZER_CARTHAGE_ENABLED;
    }

    @Override
    protected void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {

        try {
            BufferedReader br = new BufferedReader(new FileReader(dependency.getActualFile()));
            boolean inDependencies = false;
            boolean inHashes = false;
            Map<String, Dependency> dependencies = new HashMap<String, Dependency>();


            for (String line; (line = br.readLine()) != null; ) {
                if (line.isEmpty()) {
                    continue;
                }

                extractDependencyLine(line, dependencies);
            }

            //Now that we have all of the dependencies, add them to get scanned
            for(Dependency dep : dependencies.values()) {
                LOGGER.debug("Adding dep="+dep.getDisplayFileName());
                engine.getDependencies().add(dep);
            }

        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }

        setPackagePath(dependency);
    }

    private void extractDependencyLine(String line, Map<String, Dependency> dependencies) throws IOException {
        LOGGER.debug("LINE = "+line);
        String vendor = "", version = "";
        boolean found = false;
        boolean isCommit = false;
        boolean isTag = false;
        boolean isVersion = false;
        final Matcher githubMatcher = GITHUB_LINE_PATTERN.matcher(line);
        final Matcher gitMatcher = GIT_TAG_COMMIT_PATTERN.matcher(line);

        if (githubMatcher.find()) {
            String[] pathComponents = githubMatcher.group(1).split("/");

            LOGGER.debug("Path is " + pathComponents);

            if (pathComponents.length > 0) {
                vendor = pathComponents[pathComponents.length - 1];
                version = githubMatcher.group(2);
                isVersion = true;
            }

            found = true;
        } else if (gitMatcher.find()) {
            String[] pathComponents = gitMatcher.group(1).split("/");

            LOGGER.debug("Path is " + pathComponents);

            if (pathComponents.length > 0) {
                vendor = pathComponents[pathComponents.length - 1];
                version = gitMatcher.group(2);
                isTag = true;
            }

            found = true;
        }

        //If we've found it with the version then add as much information about it as we can
        if (found) {
            LOGGER.debug("Found a dependency");
            Dependency dependency1 = new Dependency();
            String dependencyString = vendor;
            dependency1.setFileName(dependencyString);

            //For some reason we need an actual unique file path for this library. So make a fake one
            File tmpFile = File.createTempFile("dep", "pod");
            PrintWriter writer = new PrintWriter(tmpFile);
            writer.write(dependencyString);
            writer.close();
            dependency1.setFilePath(tmpFile.getPath());
            dependency1.setActualFilePath(tmpFile.getAbsolutePath());
            dependency1.setDisplayFileName(dependencyString);
            dependencyString = dependencyString.toLowerCase();
            //Since we're not sure how CVD will contain non version libraries,
            // just add them all as a version but change the confidence down a step if it's not a verbatim "version"
            if (version.length() > 0) {
                dependency1.getVersionEvidence().addEvidence("cartfile", "version", version, isVersion ? Confidence.HIGHEST : Confidence.HIGH);
            }

            if (isTag) {
                dependency1.getVersionEvidence().addEvidence("cartfile", "tag", version, Confidence.HIGHEST);
            }

            dependency1.getProductEvidence().addEvidence("cartfile", "name", dependencyString, Confidence.HIGHEST);
            dependency1.getVendorEvidence().addEvidence("cartfile", "vendor", dependencyString, Confidence.HIGH);
            dependency1.getVendorEvidence().addEvidence("cartfile", "vendor", dependencyString + "_project", Confidence.HIGH);
            dependency1.getProductEvidence().addEvidence("cartfile", "name_project", dependencyString, Confidence.HIGH);


            LOGGER.debug("Saving dep vendor = " + vendor + " dep = " + dependency1.getDisplayFileName());

            dependencies.put(vendor, dependency1);
        }
    }

    /**
     * Sets the package path on the given dependency.
     *
     * @param dep the dependency to update
     */
    private void setPackagePath(Dependency dep) {
        final File file = new File(dep.getFilePath());
        final String parent = file.getParent();
        if (parent != null) {
            dep.setPackagePath(parent);
        }
    }
}
