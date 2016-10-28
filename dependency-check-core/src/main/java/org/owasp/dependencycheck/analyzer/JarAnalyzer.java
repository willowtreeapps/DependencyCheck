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
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.FileFilter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.io.FilenameUtils;
import org.jsoup.Jsoup;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.xml.pom.License;
import org.owasp.dependencycheck.xml.pom.PomUtils;
import org.owasp.dependencycheck.xml.pom.Model;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Used to load a JAR file and collect information that can be used to determine
 * the associated CPE.
 *
 * @author Jeremy Long
 */
public class JarAnalyzer extends AbstractFileTypeAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="Constants and Member Variables">
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(JarAnalyzer.class);
    /**
     * The count of directories created during analysis. This is used for
     * creating temporary directories.
     */
    private static final AtomicInteger DIR_COUNT = new AtomicInteger(0);
    /**
     * The system independent newline character.
     */
    private static final String NEWLINE = System.getProperty("line.separator");
    /**
     * A list of values in the manifest to ignore as they only result in false
     * positives.
     */
    private static final Set<String> IGNORE_VALUES = newHashSet(
            "Sun Java System Application Server");
    /**
     * A list of elements in the manifest to ignore.
     */
    private static final Set<String> IGNORE_KEYS = newHashSet(
            "built-by",
            "created-by",
            "builtby",
            "createdby",
            "build-jdk",
            "buildjdk",
            "ant-version",
            "antversion",
            "dynamicimportpackage",
            "dynamicimport-package",
            "dynamic-importpackage",
            "dynamic-import-package",
            "import-package",
            "ignore-package",
            "export-package",
            "importpackage",
            "ignorepackage",
            "exportpackage",
            "sealed",
            "manifest-version",
            "archiver-version",
            "manifestversion",
            "archiverversion",
            "classpath",
            "class-path",
            "tool",
            "bundle-manifestversion",
            "bundlemanifestversion",
            "bundle-vendor",
            "include-resource",
            "embed-dependency",
            "ipojo-components",
            "ipojo-extension",
            "eclipse-sourcereferences");
    /**
     * Deprecated Jar manifest attribute, that is, nonetheless, useful for
     * analysis.
     */
    @SuppressWarnings("deprecation")
    private static final String IMPLEMENTATION_VENDOR_ID = Attributes.Name.IMPLEMENTATION_VENDOR_ID
            .toString();
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_VERSION = "Bundle-Version"; //: 2.1.2
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_DESCRIPTION = "Bundle-Description"; //: Apache Struts 2
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_NAME = "Bundle-Name"; //: Struts 2 Core
    /**
     * A pattern to detect HTML within text.
     */
    private static final Pattern HTML_DETECTION_PATTERN = Pattern.compile("\\<[a-z]+.*/?\\>", Pattern.CASE_INSENSITIVE);

    //</editor-fold>
    /**
     * Constructs a new JarAnalyzer.
     */
    public JarAnalyzer() {
    }

    //<editor-fold defaultstate="collapsed" desc="All standard implmentation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Jar Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final String[] EXTENSIONS = {"jar", "war"};

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(EXTENSIONS).build();

    /**
     * Returns the FileFilter.
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
    //</editor-fold>

    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_JAR_ENABLED;
    }

    /**
     * Loads a specified JAR file and collects information from the manifest and
     * checksums to identify the correct CPE information.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    @Override
    public void analyzeFileType(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            final List<ClassNameInformation> classNames = collectClassNames(dependency);
            final String fileName = dependency.getFileName().toLowerCase();
            if (classNames.isEmpty()
                    && (fileName.endsWith("-sources.jar")
                    || fileName.endsWith("-javadoc.jar")
                    || fileName.endsWith("-src.jar")
                    || fileName.endsWith("-doc.jar"))) {
                engine.getDependencies().remove(dependency);
            }
            final boolean hasManifest = parseManifest(dependency, classNames);
            final boolean hasPOM = analyzePOM(dependency, classNames, engine);
            final boolean addPackagesAsEvidence = !(hasManifest && hasPOM);
            analyzePackageNames(classNames, dependency, addPackagesAsEvidence);
        } catch (IOException ex) {
            throw new AnalysisException("Exception occurred reading the JAR file.", ex);
        }
    }

    /**
     * Attempts to find a pom.xml within the JAR file. If found it extracts
     * information and adds it to the evidence. This will attempt to interpolate
     * the strings contained within the pom.properties if one exists.
     *
     * @param dependency the dependency being analyzed
     * @param classes a collection of class name information
     * @param engine the analysis engine, used to add additional dependencies
     * @throws AnalysisException is thrown if there is an exception parsing the
     * pom
     * @return whether or not evidence was added to the dependency
     */
    protected boolean analyzePOM(Dependency dependency, List<ClassNameInformation> classes, Engine engine) throws AnalysisException {
        boolean foundSomething = false;
        final JarFile jar;
        try {
            jar = new JarFile(dependency.getActualFilePath());
        } catch (IOException ex) {
            LOGGER.warn("Unable to read JarFile '{}'.", dependency.getActualFilePath());
            LOGGER.trace("", ex);
            return false;
        }
        List<String> pomEntries;
        try {
            pomEntries = retrievePomListing(jar);
        } catch (IOException ex) {
            LOGGER.warn("Unable to read Jar file entries in '{}'.", dependency.getActualFilePath());
            LOGGER.trace("", ex);
            return false;
        }
        File externalPom = null;
        if (pomEntries.isEmpty()) {
            final String pomPath = FilenameUtils.removeExtension(dependency.getActualFilePath()) + ".pom";
            externalPom = new File(pomPath);
            if (externalPom.isFile()) {
                pomEntries.add(pomPath);
            } else {
                return false;
            }
        }
        for (String path : pomEntries) {
            LOGGER.debug("Reading pom entry: {}", path);
            Properties pomProperties = null;
            try {
                if (externalPom == null) {
                    pomProperties = retrievePomProperties(path, jar);
                }
            } catch (IOException ex) {
                LOGGER.trace("ignore this, failed reading a non-existent pom.properties", ex);
            }
            Model pom = null;
            try {
                if (pomEntries.size() > 1) {
                    //extract POM to its own directory and add it as its own dependency
                    final Dependency newDependency = new Dependency();
                    pom = extractPom(path, jar, newDependency);

                    final String displayPath = String.format("%s%s%s",
                            dependency.getFilePath(),
                            File.separator,
                            path);
                    final String displayName = String.format("%s%s%s",
                            dependency.getFileName(),
                            File.separator,
                            path);

                    newDependency.setFileName(displayName);
                    newDependency.setFilePath(displayPath);
                    pom.processProperties(pomProperties);
                    setPomEvidence(newDependency, pom, null);
                    engine.getDependencies().add(newDependency);
                } else {
                    if (externalPom == null) {
                        pom = PomUtils.readPom(path, jar);
                    } else {
                        pom = PomUtils.readPom(externalPom);
                    }
                    if (pom != null) {
                        pom.processProperties(pomProperties);
                        foundSomething |= setPomEvidence(dependency, pom, classes);
                    }
                }
            } catch (AnalysisException ex) {
                LOGGER.warn("An error occurred while analyzing '{}'.", dependency.getActualFilePath());
                LOGGER.trace("", ex);
            }
        }
        return foundSomething;
    }

    /**
     * Given a path to a pom.xml within a JarFile, this method attempts to load
     * a sibling pom.properties if one exists.
     *
     * @param path the path to the pom.xml within the JarFile
     * @param jar the JarFile to load the pom.properties from
     * @return a Properties object or null if no pom.properties was found
     * @throws IOException thrown if there is an exception reading the
     * pom.properties
     */
    private Properties retrievePomProperties(String path, final JarFile jar) throws IOException {
        Properties pomProperties = null;
        final String propPath = path.substring(0, path.length() - 7) + "pom.properies";
        final ZipEntry propEntry = jar.getEntry(propPath);
        if (propEntry != null) {
            Reader reader = null;
            try {
                reader = new InputStreamReader(jar.getInputStream(propEntry), "UTF-8");
                pomProperties = new Properties();
                pomProperties.load(reader);
                LOGGER.debug("Read pom.properties: {}", propPath);
            } finally {
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException ex) {
                        LOGGER.trace("close error", ex);
                    }
                }
            }
        }
        return pomProperties;
    }

    /**
     * Searches a JarFile for pom.xml entries and returns a listing of these
     * entries.
     *
     * @param jar the JarFile to search
     * @return a list of pom.xml entries
     * @throws IOException thrown if there is an exception reading a JarEntry
     */
    private List<String> retrievePomListing(final JarFile jar) throws IOException {
        final List<String> pomEntries = new ArrayList<String>();
        final Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            final JarEntry entry = entries.nextElement();
            final String entryName = (new File(entry.getName())).getName().toLowerCase();
            if (!entry.isDirectory() && "pom.xml".equals(entryName)) {
                LOGGER.trace("POM Entry found: {}", entry.getName());
                pomEntries.add(entry.getName());
            }
        }
        return pomEntries;
    }

    /**
     * Retrieves the specified POM from a jar file and converts it to a Model.
     *
     * @param path the path to the pom.xml file within the jar file
     * @param jar the jar file to extract the pom from
     * @param dependency the dependency being analyzed
     * @return returns the POM object
     * @throws AnalysisException is thrown if there is an exception extracting
     * or parsing the POM {@link org.owasp.dependencycheck.xml.pom.Model} object
     */
    private Model extractPom(String path, JarFile jar, Dependency dependency) throws AnalysisException {
        InputStream input = null;
        FileOutputStream fos = null;
        final File tmpDir = getNextTempDirectory();
        final File file = new File(tmpDir, "pom.xml");
        try {
            final ZipEntry entry = jar.getEntry(path);
            if (entry == null) {
                throw new AnalysisException(String.format("Pom (%s)does not exist in %s", path, jar.getName()));
            }
            input = jar.getInputStream(entry);
            fos = new FileOutputStream(file);
            IOUtils.copy(input, fos);
            dependency.setActualFilePath(file.getAbsolutePath());
        } catch (IOException ex) {
            LOGGER.warn("An error occurred reading '{}' from '{}'.", path, dependency.getFilePath());
            LOGGER.error("", ex);
        } finally {
            closeStream(fos);
            closeStream(input);
        }
        return PomUtils.readPom(file);
    }

    /**
     * Silently closes an input stream ignoring errors.
     *
     * @param stream an input stream to close
     */
    private void closeStream(InputStream stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException ex) {
                LOGGER.trace("", ex);
            }
        }
    }

    /**
     * Silently closes an output stream ignoring errors.
     *
     * @param stream an output stream to close
     */
    private void closeStream(OutputStream stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException ex) {
                LOGGER.trace("", ex);
            }
        }
    }

    /**
     * Sets evidence from the pom on the supplied dependency.
     *
     * @param dependency the dependency to set data on
     * @param pom the information from the pom
     * @param classes a collection of ClassNameInformation - containing data
     * about the fully qualified class names within the JAR file being analyzed
     * @return true if there was evidence within the pom that we could use;
     * otherwise false
     */
    public static boolean setPomEvidence(Dependency dependency, Model pom, List<ClassNameInformation> classes) {
        boolean foundSomething = false;
        boolean addAsIdentifier = true;
        if (pom == null) {
            return foundSomething;
        }
        String groupid = pom.getGroupId();
        String parentGroupId = pom.getParentGroupId();
        String artifactid = pom.getArtifactId();
        String parentArtifactId = pom.getParentArtifactId();
        String version = pom.getVersion();
        String parentVersion = pom.getParentVersion();

        if ("org.sonatype.oss".equals(parentGroupId) && "oss-parent".equals(parentArtifactId)) {
            parentGroupId = null;
            parentArtifactId = null;
            parentVersion = null;
        }

        if ((groupid == null || groupid.isEmpty()) && parentGroupId != null && !parentGroupId.isEmpty()) {
            groupid = parentGroupId;
        }

        final String originalGroupID = groupid;
        if (groupid != null && (groupid.startsWith("org.") || groupid.startsWith("com."))) {
            groupid = groupid.substring(4);
        }

        if ((artifactid == null || artifactid.isEmpty()) && parentArtifactId != null && !parentArtifactId.isEmpty()) {
            artifactid = parentArtifactId;
        }

        final String originalArtifactID = artifactid;
        if (artifactid != null && (artifactid.startsWith("org.") || artifactid.startsWith("com."))) {
            artifactid = artifactid.substring(4);
        }

        if ((version == null || version.isEmpty()) && parentVersion != null && !parentVersion.isEmpty()) {
            version = parentVersion;
        }

        if (groupid != null && !groupid.isEmpty()) {
            foundSomething = true;
            dependency.getVendorEvidence().addEvidence("pom", "groupid", groupid, Confidence.HIGHEST);
            dependency.getProductEvidence().addEvidence("pom", "groupid", groupid, Confidence.LOW);
            addMatchingValues(classes, groupid, dependency.getVendorEvidence());
            addMatchingValues(classes, groupid, dependency.getProductEvidence());
            if (parentGroupId != null && !parentGroupId.isEmpty() && !parentGroupId.equals(groupid)) {
                dependency.getVendorEvidence().addEvidence("pom", "parent-groupid", parentGroupId, Confidence.MEDIUM);
                dependency.getProductEvidence().addEvidence("pom", "parent-groupid", parentGroupId, Confidence.LOW);
                addMatchingValues(classes, parentGroupId, dependency.getVendorEvidence());
                addMatchingValues(classes, parentGroupId, dependency.getProductEvidence());
            }
        } else {
            addAsIdentifier = false;
        }

        if (artifactid != null && !artifactid.isEmpty()) {
            foundSomething = true;
            dependency.getProductEvidence().addEvidence("pom", "artifactid", artifactid, Confidence.HIGHEST);
            dependency.getVendorEvidence().addEvidence("pom", "artifactid", artifactid, Confidence.LOW);
            addMatchingValues(classes, artifactid, dependency.getVendorEvidence());
            addMatchingValues(classes, artifactid, dependency.getProductEvidence());
            if (parentArtifactId != null && !parentArtifactId.isEmpty() && !parentArtifactId.equals(artifactid)) {
                dependency.getProductEvidence().addEvidence("pom", "parent-artifactid", parentArtifactId, Confidence.MEDIUM);
                dependency.getVendorEvidence().addEvidence("pom", "parent-artifactid", parentArtifactId, Confidence.LOW);
                addMatchingValues(classes, parentArtifactId, dependency.getVendorEvidence());
                addMatchingValues(classes, parentArtifactId, dependency.getProductEvidence());
            }
        } else {
            addAsIdentifier = false;
        }

        if (version != null && !version.isEmpty()) {
            foundSomething = true;
            dependency.getVersionEvidence().addEvidence("pom", "version", version, Confidence.HIGHEST);
            if (parentVersion != null && !parentVersion.isEmpty() && !parentVersion.equals(version)) {
                dependency.getVersionEvidence().addEvidence("pom", "parent-version", version, Confidence.LOW);
            }
        } else {
            addAsIdentifier = false;
        }

        if (addAsIdentifier) {
            dependency.addIdentifier("maven", String.format("%s:%s:%s", originalGroupID, originalArtifactID, version), null, Confidence.HIGH);
        }

        // org name
        final String org = pom.getOrganization();
        if (org != null && !org.isEmpty()) {
            dependency.getVendorEvidence().addEvidence("pom", "organization name", org, Confidence.HIGH);
            dependency.getProductEvidence().addEvidence("pom", "organization name", org, Confidence.LOW);
            addMatchingValues(classes, org, dependency.getVendorEvidence());
            addMatchingValues(classes, org, dependency.getProductEvidence());
        }
        //pom name
        final String pomName = pom.getName();
        if (pomName
                != null && !pomName.isEmpty()) {
            foundSomething = true;
            dependency.getProductEvidence().addEvidence("pom", "name", pomName, Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("pom", "name", pomName, Confidence.HIGH);
            addMatchingValues(classes, pomName, dependency.getVendorEvidence());
            addMatchingValues(classes, pomName, dependency.getProductEvidence());
        }

        //Description
        final String description = pom.getDescription();
        if (description != null && !description.isEmpty() && !description.startsWith("POM was created by")) {
            foundSomething = true;
            final String trimmedDescription = addDescription(dependency, description, "pom", "description");
            addMatchingValues(classes, trimmedDescription, dependency.getVendorEvidence());
            addMatchingValues(classes, trimmedDescription, dependency.getProductEvidence());
        }

        final String projectURL = pom.getProjectURL();
        if (projectURL != null && !projectURL.trim().isEmpty()) {
            dependency.getVendorEvidence().addEvidence("pom", "url", projectURL, Confidence.HIGHEST);
        }

        extractLicense(pom, dependency);
        return foundSomething;
    }

    /**
     * Analyzes the path information of the classes contained within the
     * JarAnalyzer to try and determine possible vendor or product names. If any
     * are found they are stored in the packageVendor and packageProduct
     * hashSets.
     *
     * @param classNames a list of class names
     * @param dependency a dependency to analyze
     * @param addPackagesAsEvidence a flag indicating whether or not package
     * names should be added as evidence.
     */
    protected void analyzePackageNames(List<ClassNameInformation> classNames,
            Dependency dependency, boolean addPackagesAsEvidence) {
        final Map<String, Integer> vendorIdentifiers = new HashMap<String, Integer>();
        final Map<String, Integer> productIdentifiers = new HashMap<String, Integer>();
        analyzeFullyQualifiedClassNames(classNames, vendorIdentifiers, productIdentifiers);

        final int classCount = classNames.size();
        final EvidenceCollection vendor = dependency.getVendorEvidence();
        final EvidenceCollection product = dependency.getProductEvidence();

        for (Map.Entry<String, Integer> entry : vendorIdentifiers.entrySet()) {
            final float ratio = entry.getValue() / (float) classCount;
            if (ratio > 0.5) {
                //TODO remove weighting
                vendor.addWeighting(entry.getKey());
                if (addPackagesAsEvidence && entry.getKey().length() > 1) {
                    vendor.addEvidence("jar", "package name", entry.getKey(), Confidence.LOW);
                }
            }
        }
        for (Map.Entry<String, Integer> entry : productIdentifiers.entrySet()) {
            final float ratio = entry.getValue() / (float) classCount;
            if (ratio > 0.5) {
                product.addWeighting(entry.getKey());
                if (addPackagesAsEvidence && entry.getKey().length() > 1) {
                    product.addEvidence("jar", "package name", entry.getKey(), Confidence.LOW);
                }
            }
        }
    }

    /**
     * <p>
     * Reads the manifest from the JAR file and collects the entries. Some
     * vendorKey entries are:</p>
     * <ul><li>Implementation Title</li>
     * <li>Implementation Version</li> <li>Implementation Vendor</li>
     * <li>Implementation VendorId</li> <li>Bundle Name</li> <li>Bundle
     * Version</li> <li>Bundle Vendor</li> <li>Bundle Description</li> <li>Main
     * Class</li> </ul>
     * However, all but a handful of specific entries are read in.
     *
     * @param dependency A reference to the dependency
     * @param classInformation a collection of class information
     * @return whether evidence was identified parsing the manifest
     * @throws IOException if there is an issue reading the JAR file
     */
    protected boolean parseManifest(Dependency dependency, List<ClassNameInformation> classInformation) throws IOException {
        boolean foundSomething = false;
        JarFile jar = null;
        try {
            jar = new JarFile(dependency.getActualFilePath());
            final Manifest manifest = jar.getManifest();
            if (manifest == null) {
                if (!dependency.getFileName().toLowerCase().endsWith("-sources.jar")
                        && !dependency.getFileName().toLowerCase().endsWith("-javadoc.jar")
                        && !dependency.getFileName().toLowerCase().endsWith("-src.jar")
                        && !dependency.getFileName().toLowerCase().endsWith("-doc.jar")) {
                    LOGGER.debug("Jar file '{}' does not contain a manifest.",
                            dependency.getFileName());
                }
                return false;
            }
            final EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
            final EvidenceCollection productEvidence = dependency.getProductEvidence();
            final EvidenceCollection versionEvidence = dependency.getVersionEvidence();
            String source = "Manifest";
            String specificationVersion = null;
            boolean hasImplementationVersion = false;
            Attributes atts = manifest.getMainAttributes();
            for (Entry<Object, Object> entry : atts.entrySet()) {
                String key = entry.getKey().toString();
                String value = atts.getValue(key);
                if (HTML_DETECTION_PATTERN.matcher(value).find()) {
                    value = Jsoup.parse(value).text();
                }
                if (IGNORE_VALUES.contains(value)) {
                    continue;
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_TITLE.toString())) {
                    foundSomething = true;
                    productEvidence.addEvidence(source, key, value, Confidence.HIGH);
                    addMatchingValues(classInformation, value, productEvidence);
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VERSION.toString())) {
                    hasImplementationVersion = true;
                    foundSomething = true;
                    versionEvidence.addEvidence(source, key, value, Confidence.HIGH);
                } else if ("specification-version".equalsIgnoreCase(key)) {
                    specificationVersion = value;
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VENDOR.toString())) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Confidence.HIGH);
                    addMatchingValues(classInformation, value, vendorEvidence);
                } else if (key.equalsIgnoreCase(IMPLEMENTATION_VENDOR_ID)) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, vendorEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_DESCRIPTION)) {
                    foundSomething = true;
                    addDescription(dependency, value, "manifest", key);
                    addMatchingValues(classInformation, value, productEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_NAME)) {
                    foundSomething = true;
                    productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, productEvidence);
//                //the following caused false positives.
//                } else if (key.equalsIgnoreCase(BUNDLE_VENDOR)) {
                } else if (key.equalsIgnoreCase(BUNDLE_VERSION)) {
                    foundSomething = true;
                    versionEvidence.addEvidence(source, key, value, Confidence.HIGH);
                } else if (key.equalsIgnoreCase(Attributes.Name.MAIN_CLASS.toString())) {
                    continue;
                    //skipping main class as if this has important information to add it will be added during class name analysis...
                } else {
                    key = key.toLowerCase();
                    if (!IGNORE_KEYS.contains(key)
                            && !key.endsWith("jdk")
                            && !key.contains("lastmodified")
                            && !key.endsWith("package")
                            && !key.endsWith("classpath")
                            && !key.endsWith("class-path")
                            && !key.endsWith("-scm") //todo change this to a regex?
                            && !key.startsWith("scm-")
                            && !value.trim().startsWith("scm:")
                            && !isImportPackage(key, value)
                            && !isPackage(key, value)) {
                        foundSomething = true;
                        if (key.contains("version")) {
                            if (!key.contains("specification")) {
                                versionEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                            }
                        } else if ("build-id".equals(key)) {
                            int pos = value.indexOf('(');
                            if (pos >= 0) {
                                value = value.substring(0, pos - 1);
                            }
                            pos = value.indexOf('[');
                            if (pos >= 0) {
                                value = value.substring(0, pos - 1);
                            }
                            versionEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                        } else if (key.contains("title")) {
                            productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                            addMatchingValues(classInformation, value, productEvidence);
                        } else if (key.contains("vendor")) {
                            if (key.contains("specification")) {
                                vendorEvidence.addEvidence(source, key, value, Confidence.LOW);
                            } else {
                                vendorEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                                addMatchingValues(classInformation, value, vendorEvidence);
                            }
                        } else if (key.contains("name")) {
                            productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                            vendorEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                            addMatchingValues(classInformation, value, vendorEvidence);
                            addMatchingValues(classInformation, value, productEvidence);
                        } else if (key.contains("license")) {
                            addLicense(dependency, value);
                        } else if (key.contains("description")) {
                            addDescription(dependency, value, "manifest", key);
                        } else {
                            productEvidence.addEvidence(source, key, value, Confidence.LOW);
                            vendorEvidence.addEvidence(source, key, value, Confidence.LOW);
                            addMatchingValues(classInformation, value, vendorEvidence);
                            addMatchingValues(classInformation, value, productEvidence);
                            if (value.matches(".*\\d.*")) {
                                final StringTokenizer tokenizer = new StringTokenizer(value, " ");
                                while (tokenizer.hasMoreElements()) {
                                    final String s = tokenizer.nextToken();
                                    if (s.matches("^[0-9.]+$")) {
                                        versionEvidence.addEvidence(source, key, s, Confidence.LOW);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for (Map.Entry<String, Attributes> item : manifest.getEntries().entrySet()) {
                final String name = item.getKey();
                source = "manifest: " + name;
                atts = item.getValue();
                for (Entry<Object, Object> entry : atts.entrySet()) {
                    final String key = entry.getKey().toString();
                    final String value = atts.getValue(key);
                    if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_TITLE.toString())) {
                        foundSomething = true;
                        productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                        addMatchingValues(classInformation, value, productEvidence);
                    } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VERSION.toString())) {
                        foundSomething = true;
                        versionEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                    } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VENDOR.toString())) {
                        foundSomething = true;
                        vendorEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                        addMatchingValues(classInformation, value, vendorEvidence);
                    } else if (key.equalsIgnoreCase(Attributes.Name.SPECIFICATION_TITLE.toString())) {
                        foundSomething = true;
                        productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                        addMatchingValues(classInformation, value, productEvidence);
                    }
                }
            }
            if (specificationVersion != null && !hasImplementationVersion) {
                foundSomething = true;
                versionEvidence.addEvidence(source, "specification-version", specificationVersion, Confidence.HIGH);
            }
        } finally {
            if (jar != null) {
                jar.close();
            }
        }
        return foundSomething;
    }

    /**
     * Adds a description to the given dependency. If the description contains
     * one of the following strings beyond 100 characters, then the description
     * used will be trimmed to that position:
     * <ul><li>"such as"</li><li>"like "</li><li>"will use "</li><li>"* uses
     * "</li></ul>
     *
     * @param dependency a dependency
     * @param description the description
     * @param source the source of the evidence
     * @param key the "name" of the evidence
     * @return if the description is trimmed, the trimmed version is returned;
     * otherwise the original description is returned
     */
    public static String addDescription(Dependency dependency, String description, String source, String key) {
        if (dependency.getDescription() == null) {
            dependency.setDescription(description);
        }
        String desc;
        if (HTML_DETECTION_PATTERN.matcher(description).find()) {
            desc = Jsoup.parse(description).text();
        } else {
            desc = description;
        }
        dependency.setDescription(desc);
        if (desc.length() > 100) {
            desc = desc.replaceAll("\\s\\s+", " ");
            final int posSuchAs = desc.toLowerCase().indexOf("such as ", 100);
            final int posLike = desc.toLowerCase().indexOf("like ", 100);
            final int posWillUse = desc.toLowerCase().indexOf("will use ", 100);
            final int posUses = desc.toLowerCase().indexOf(" uses ", 100);
            int pos = -1;
            pos = Math.max(pos, posSuchAs);
            if (pos >= 0 && posLike >= 0) {
                pos = Math.min(pos, posLike);
            } else {
                pos = Math.max(pos, posLike);
            }
            if (pos >= 0 && posWillUse >= 0) {
                pos = Math.min(pos, posWillUse);
            } else {
                pos = Math.max(pos, posWillUse);
            }
            if (pos >= 0 && posUses >= 0) {
                pos = Math.min(pos, posUses);
            } else {
                pos = Math.max(pos, posUses);
            }

            if (pos > 0) {
                desc = desc.substring(0, pos) + "...";
            }
            dependency.getProductEvidence().addEvidence(source, key, desc, Confidence.LOW);
            dependency.getVendorEvidence().addEvidence(source, key, desc, Confidence.LOW);
        } else {
            dependency.getProductEvidence().addEvidence(source, key, desc, Confidence.MEDIUM);
            dependency.getVendorEvidence().addEvidence(source, key, desc, Confidence.MEDIUM);
        }
        return desc;
    }

    /**
     * Adds a license to the given dependency.
     *
     * @param d a dependency
     * @param license the license
     */
    private void addLicense(Dependency d, String license) {
        if (d.getLicense() == null) {
            d.setLicense(license);
        } else if (!d.getLicense().contains(license)) {
            d.setLicense(d.getLicense() + NEWLINE + license);
        }
    }

    /**
     * The parent directory for the individual directories per archive.
     */
    private File tempFileLocation = null;

    /**
     * Initializes the JarAnalyzer.
     *
     * @throws InitializationException is thrown if there is an exception
     * creating a temporary directory
     */
    @Override
    public void initializeFileTypeAnalyzer() throws InitializationException {
        try {
            final File baseDir = Settings.getTempDirectory();
            tempFileLocation = File.createTempFile("check", "tmp", baseDir);
            if (!tempFileLocation.delete()) {
                final String msg = String.format("Unable to delete temporary file '%s'.", tempFileLocation.getAbsolutePath());
                setEnabled(false);
                throw new InitializationException(msg);
            }
            if (!tempFileLocation.mkdirs()) {
                final String msg = String.format("Unable to create directory '%s'.", tempFileLocation.getAbsolutePath());
                setEnabled(false);
                throw new InitializationException(msg);
            }
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create a temporary file", ex);
        }
    }

    /**
     * Deletes any files extracted from the JAR during analysis.
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
     * Determines if the key value pair from the manifest is for an "import"
     * type entry for package names.
     *
     * @param key the key from the manifest
     * @param value the value from the manifest
     * @return true or false depending on if it is believed the entry is an
     * "import" entry
     */
    private boolean isImportPackage(String key, String value) {
        final Pattern packageRx = Pattern.compile("^([a-zA-Z0-9_#\\$\\*\\.]+\\s*[,;]\\s*)+([a-zA-Z0-9_#\\$\\*\\.]+\\s*)?$");
        final boolean matches = packageRx.matcher(value).matches();
        return matches && (key.contains("import") || key.contains("include") || value.length() > 10);
    }

    /**
     * Cycles through an enumeration of JarEntries, contained within the
     * dependency, and returns a list of the class names. This does not include
     * core Java package names (i.e. java.* or javax.*).
     *
     * @param dependency the dependency being analyzed
     * @return an list of fully qualified class names
     */
    private List<ClassNameInformation> collectClassNames(Dependency dependency) {
        final List<ClassNameInformation> classNames = new ArrayList<ClassNameInformation>();
        JarFile jar = null;
        try {
            jar = new JarFile(dependency.getActualFilePath());
            final Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                final JarEntry entry = entries.nextElement();
                final String name = entry.getName().toLowerCase();
                //no longer stripping "|com\\.sun" - there are some com.sun jar files with CVEs.
                if (name.endsWith(".class") && !name.matches("^javax?\\..*$")) {
                    final ClassNameInformation className = new ClassNameInformation(name.substring(0, name.length() - 6));
                    classNames.add(className);
                }
            }
        } catch (IOException ex) {
            LOGGER.warn("Unable to open jar file '{}'.", dependency.getFileName());
            LOGGER.debug("", ex);
        } finally {
            if (jar != null) {
                try {
                    jar.close();
                } catch (IOException ex) {
                    LOGGER.trace("", ex);
                }
            }
        }
        return classNames;
    }

    /**
     * Cycles through the list of class names and places the package levels 0-3
     * into the provided maps for vendor and product. This is helpful when
     * analyzing vendor/product as many times this is included in the package
     * name.
     *
     * @param classNames a list of class names
     * @param vendor HashMap of possible vendor names from package names (e.g.
     * owasp)
     * @param product HashMap of possible product names from package names (e.g.
     * dependencycheck)
     */
    private void analyzeFullyQualifiedClassNames(List<ClassNameInformation> classNames,
            Map<String, Integer> vendor, Map<String, Integer> product) {
        for (ClassNameInformation entry : classNames) {
            final List<String> list = entry.getPackageStructure();
            addEntry(vendor, list.get(0));

            if (list.size() == 2) {
                addEntry(product, list.get(1));
            }
            if (list.size() == 3) {
                addEntry(vendor, list.get(1));
                addEntry(product, list.get(1));
                addEntry(product, list.get(2));
            }
            if (list.size() >= 4) {
                addEntry(vendor, list.get(1));
                addEntry(vendor, list.get(2));
                addEntry(product, list.get(1));
                addEntry(product, list.get(2));
                addEntry(product, list.get(3));
            }
        }
    }

    /**
     * Adds an entry to the specified collection and sets the Integer (e.g. the
     * count) to 1. If the entry already exists in the collection then the
     * Integer is incremented by 1.
     *
     * @param collection a collection of strings and their occurrence count
     * @param key the key to add to the collection
     */
    private void addEntry(Map<String, Integer> collection, String key) {
        if (collection.containsKey(key)) {
            collection.put(key, collection.get(key) + 1);
        } else {
            collection.put(key, 1);
        }
    }

    /**
     * Cycles through the collection of class name information to see if parts
     * of the package names are contained in the provided value. If found, it
     * will be added as the HIGHEST confidence evidence because we have more
     * then one source corroborating the value.
     *
     * @param classes a collection of class name information
     * @param value the value to check to see if it contains a package name
     * @param evidence the evidence collection to add new entries too
     */
    private static void addMatchingValues(List<ClassNameInformation> classes, String value, EvidenceCollection evidence) {
        if (value == null || value.isEmpty() || classes == null || classes.isEmpty()) {
            return;
        }
        final String text = value.toLowerCase();
        for (ClassNameInformation cni : classes) {
            for (String key : cni.getPackageStructure()) {
                final Pattern p = Pattern.compile("\b" + key + "\b");
                if (p.matcher(text).find()) {
                    //if (text.contains(key)) { //note, package structure elements are already lowercase.
                    evidence.addEvidence("jar", "package name", key, Confidence.HIGHEST);
                }
            }
        }
    }

    /**
     * Simple check to see if the attribute from a manifest is just a package
     * name.
     *
     * @param key the key of the value to check
     * @param value the value to check
     * @return true if the value looks like a java package name, otherwise false
     */
    private boolean isPackage(String key, String value) {

        return !key.matches(".*(version|title|vendor|name|license|description).*")
                && value.matches("^([a-zA-Z_][a-zA-Z0-9_\\$]*(\\.[a-zA-Z_][a-zA-Z0-9_\\$]*)*)?$");

    }

    /**
     * Extracts the license information from the pom and adds it to the
     * dependency.
     *
     * @param pom the pom object
     * @param dependency the dependency to add license information too
     */
    public static void extractLicense(Model pom, Dependency dependency) {
        //license
        if (pom.getLicenses() != null) {
            String license = null;
            for (License lic : pom.getLicenses()) {
                String tmp = null;
                if (lic.getName() != null) {
                    tmp = lic.getName();
                }
                if (lic.getUrl() != null) {
                    if (tmp == null) {
                        tmp = lic.getUrl();
                    } else {
                        tmp += ": " + lic.getUrl();
                    }
                }
                if (tmp == null) {
                    continue;
                }
                if (HTML_DETECTION_PATTERN.matcher(tmp).find()) {
                    tmp = Jsoup.parse(tmp).text();
                }
                if (license == null) {
                    license = tmp;
                } else {
                    license += "\n" + tmp;
                }
            }
            if (license != null) {
                dependency.setLicense(license);

            }
        }
    }

    /**
     * Stores information about a class name.
     */
    protected static class ClassNameInformation {

        /**
         * <p>
         * Stores information about a given class name. This class will keep the
         * fully qualified class name and a list of the important parts of the
         * package structure. Up to the first four levels of the package
         * structure are stored, excluding a leading "org" or "com".
         * Example:</p>
         * <code>ClassNameInformation obj = new ClassNameInformation("org.owasp.dependencycheck.analyzer.JarAnalyzer");
         * System.out.println(obj.getName());
         * for (String p : obj.getPackageStructure())
         *     System.out.println(p);
         * </code>
         * <p>
         * Would result in:</p>
         * <code>org.owasp.dependencycheck.analyzer.JarAnalyzer
         * owasp
         * dependencycheck
         * analyzer
         * jaranalyzer</code>
         *
         * @param className a fully qualified class name
         */
        ClassNameInformation(String className) {
            name = className;
            if (name.contains("/")) {
                final String[] tmp = className.toLowerCase().split("/");
                int start = 0;
                int end = 3;
                if ("com".equals(tmp[0]) || "org".equals(tmp[0])) {
                    start = 1;
                    end = 4;
                }
                if (tmp.length <= end) {
                    end = tmp.length - 1;
                }
                for (int i = start; i <= end; i++) {
                    packageStructure.add(tmp[i]);
                }
            } else {
                packageStructure.add(name);
            }
        }
        /**
         * The fully qualified class name.
         */
        private String name;

        /**
         * Get the value of name
         *
         * @return the value of name
         */
        public String getName() {
            return name;
        }

        /**
         * Set the value of name
         *
         * @param name new value of name
         */
        public void setName(String name) {
            this.name = name;
        }
        /**
         * Up to the first four levels of the package structure, excluding a
         * leading "org" or "com".
         */
        private final ArrayList<String> packageStructure = new ArrayList<String>();

        /**
         * Get the value of packageStructure
         *
         * @return the value of packageStructure
         */
        public ArrayList<String> getPackageStructure() {
            return packageStructure;
        }
    }

    /**
     * Retrieves the next temporary directory to extract an archive too.
     *
     * @return a directory
     * @throws AnalysisException thrown if unable to create temporary directory
     */
    private File getNextTempDirectory() throws AnalysisException {
        final int dirCount = DIR_COUNT.incrementAndGet();
        final File directory = new File(tempFileLocation, String.valueOf(dirCount));
        //getting an exception for some directories not being able to be created; might be because the directory already exists?
        if (directory.exists()) {
            return getNextTempDirectory();
        }
        if (!directory.mkdirs()) {
            final String msg = String.format("Unable to create temp directory '%s'.", directory.getAbsolutePath());
            throw new AnalysisException(msg);
        }
        return directory;
    }
}
