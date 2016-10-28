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
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.ParserConfigurationException;
import org.owasp.dependencycheck.exception.InitializationException;
import org.apache.commons.lang3.SystemUtils;

/**
 * Analyzer for getting company, product, and version information from a .NET
 * assembly.
 *
 * @author colezlaw
 *
 */
public class AssemblyAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The analyzer name
     */
    private static final String ANALYZER_NAME = "Assembly Analyzer";
    /**
     * The analysis phase
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The list of supported extensions
     */
    private static final String[] SUPPORTED_EXTENSIONS = {"dll", "exe"};
    /**
     * The temp value for GrokAssembly.exe
     */
    private File grokAssemblyExe = null;
    /**
     * Logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AssemblyAnalyzer.class);

    /**
     * Builds the beginnings of a List for ProcessBuilder
     *
     * @return the list of arguments to begin populating the ProcessBuilder
     */
    protected List<String> buildArgumentList() {
        // Use file.separator as a wild guess as to whether this is Windows
        final List<String> args = new ArrayList<String>();
        if (!SystemUtils.IS_OS_WINDOWS) {
            if (Settings.getString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH) != null) {
                args.add(Settings.getString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH));
            } else if (isInPath("mono")) {
                args.add("mono");
            } else {
                return null;
            }
        }
        args.add(grokAssemblyExe.getPath());
        return args;
    }

    /**
     * Performs the analysis on a single Dependency.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine to perform the analysis under
     * @throws AnalysisException if anything goes sideways
     */
    @Override
    public void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
        if (grokAssemblyExe == null) {
            LOGGER.warn("GrokAssembly didn't get deployed");
            return;
        }

        final List<String> args = buildArgumentList();
        if (args == null) {
            LOGGER.warn("Assembly Analyzer was unable to execute");
            return;
        }
        args.add(dependency.getActualFilePath());
        final ProcessBuilder pb = new ProcessBuilder(args);
        Document doc = null;
        try {
            final Process proc = pb.start();

            final DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            doc = builder.parse(proc.getInputStream());

            // Try evacuating the error stream
            final String errorStream = IOUtils.toString(proc.getErrorStream(), "UTF-8");
            if (null != errorStream && !errorStream.isEmpty()) {
                LOGGER.warn("Error from GrokAssembly: {}", errorStream);
            }

            int rc = 0;
            try {
                rc = proc.waitFor();
            } catch (InterruptedException ie) {
                return;
            }
            if (rc == 3) {
                LOGGER.debug("{} is not a .NET assembly or executable and as such cannot be analyzed by dependency-check",
                        dependency.getActualFilePath());
                return;
            } else if (rc != 0) {
                LOGGER.warn("Return code {} from GrokAssembly", rc);
            }

            final XPath xpath = XPathFactory.newInstance().newXPath();

            // First, see if there was an error
            final String error = xpath.evaluate("/assembly/error", doc);
            if (error != null && !error.isEmpty()) {
                throw new AnalysisException(error);
            }

            final String version = xpath.evaluate("/assembly/version", doc);
            if (version != null) {
                dependency.getVersionEvidence().addEvidence(new Evidence("grokassembly", "version",
                        version, Confidence.HIGHEST));
            }

            final String vendor = xpath.evaluate("/assembly/company", doc);
            if (vendor != null) {
                dependency.getVendorEvidence().addEvidence(new Evidence("grokassembly", "vendor",
                        vendor, Confidence.HIGH));
            }

            final String product = xpath.evaluate("/assembly/product", doc);
            if (product != null) {
                dependency.getProductEvidence().addEvidence(new Evidence("grokassembly", "product",
                        product, Confidence.HIGH));
            }

        } catch (ParserConfigurationException pce) {
            throw new AnalysisException("Error initializing the assembly analyzer", pce);
        } catch (IOException ioe) {
            throw new AnalysisException(ioe);
        } catch (SAXException saxe) {
            throw new AnalysisException("Couldn't parse GrokAssembly result", saxe);
        } catch (XPathExpressionException xpe) {
            // This shouldn't happen
            throw new AnalysisException(xpe);
        }
    }

    /**
     * Initialize the analyzer. In this case, extract GrokAssembly.exe to a
     * temporary location.
     *
     * @throws InitializationException thrown if anything goes wrong
     */
    @Override
    public void initializeFileTypeAnalyzer() throws InitializationException {
        final File tempFile;
        try {
            tempFile = File.createTempFile("GKA", ".exe", Settings.getTempDirectory());
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create temporary file for the assembly analyzerr", ex);
        }
        FileOutputStream fos = null;
        InputStream is = null;
        try {
            fos = new FileOutputStream(tempFile);
            is = AssemblyAnalyzer.class.getClassLoader().getResourceAsStream("GrokAssembly.exe");
            IOUtils.copy(is, fos);

            grokAssemblyExe = tempFile;
            LOGGER.debug("Extracted GrokAssembly.exe to {}", grokAssemblyExe.getPath());
        } catch (IOException ioe) {
            this.setEnabled(false);
            LOGGER.warn("Could not extract GrokAssembly.exe: {}", ioe.getMessage());
            throw new InitializationException("Could not extract GrokAssembly.exe", ioe);
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (Throwable e) {
                    LOGGER.debug("Error closing output stream");
                }
            }
            if (is != null) {
                try {
                    is.close();
                } catch (Throwable e) {
                    LOGGER.debug("Error closing input stream");
                }
            }
        }

        // Now, need to see if GrokAssembly actually runs from this location.
        final List<String> args = buildArgumentList();
        //TODO this creates an "unreported" error - if someone doesn't look
        // at the command output this could easily be missed (especially in an
        // Ant or Maven build.
        //
        // We need to create a non-fatal warning error type that will
        // get added to the report.
        //TOOD this idea needs to get replicated to the bundle audit analyzer.
        if (args == null) {
            setEnabled(false);
            LOGGER.error("----------------------------------------------------");
            LOGGER.error(".NET Assembly Analyzer could not be initialized and at least one "
                    + "'exe' or 'dll' was scanned. The 'mono' executable could not be found on "
                    + "the path; either disable the Assembly Analyzer or configure the path mono.");
            LOGGER.error("----------------------------------------------------");
            return;
        }
        try {
            final ProcessBuilder pb = new ProcessBuilder(args);
            final Process p = pb.start();
            // Try evacuating the error stream
            IOUtils.copy(p.getErrorStream(), NullOutputStream.NULL_OUTPUT_STREAM);

            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            final DocumentBuilder builder = factory.newDocumentBuilder();
            final Document doc = builder.parse(p.getInputStream());
            final XPath xpath = XPathFactory.newInstance().newXPath();
            final String error = xpath.evaluate("/assembly/error", doc);
            if (p.waitFor() != 1 || error == null || error.isEmpty()) {
                LOGGER.warn("An error occurred with the .NET AssemblyAnalyzer, please see the log for more details.");
                LOGGER.debug("GrokAssembly.exe is not working properly");
                grokAssemblyExe = null;
                setEnabled(false);
                throw new InitializationException("Could not execute .NET AssemblyAnalyzer");
            }
        } catch (InitializationException e) {
            setEnabled(false);
            throw e;
        } catch (Throwable e) {
            LOGGER.warn("An error occurred with the .NET AssemblyAnalyzer;\n"
                    + "this can be ignored unless you are scanning .NET DLLs. Please see the log for more details.");
            LOGGER.debug("Could not execute GrokAssembly {}", e.getMessage());
            setEnabled(false);
            throw new InitializationException("An error occurred with the .NET AssemblyAnalyzer", e);
        }
    }

    /**
     * Removes resources used from the local file system.
     *
     * @throws Exception thrown if there is a problem closing the analyzer
     */
    @Override
    public void close() throws Exception {
        super.close();
        try {
            if (grokAssemblyExe != null && !grokAssemblyExe.delete()) {
                LOGGER.debug("Unable to delete temporary GrokAssembly.exe; attempting delete on exit");
                grokAssemblyExe.deleteOnExit();
            }
        } catch (SecurityException se) {
            LOGGER.debug("Can't delete temporary GrokAssembly.exe");
            grokAssemblyExe.deleteOnExit();
        }
    }

    /**
     * The File Filter used to filter supported extensions.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(
            SUPPORTED_EXTENSIONS).build();

    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Gets this analyzer's name.
     *
     * @return the analyzer name
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase this analyzer runs under.
     *
     * @return the phase this runs under
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
        return Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED;
    }

    /**
     * Tests to see if a file is in the system path. <b>Note</b> - the current
     * implementation only works on non-windows platforms. For purposes of the
     * AssemblyAnalyzer this is okay as this is only needed on Mac/*nix.
     *
     * @param file the executable to look for
     * @return <code>true</code> if the file exists; otherwise
     * <code>false</code>
     */
    private boolean isInPath(String file) {
        final ProcessBuilder pb = new ProcessBuilder("which", file);
        try {
            final Process proc = pb.start();
            final int retCode = proc.waitFor();
            if (retCode == 0) {
                return true;
            }
        } catch (IOException ex) {
            LOGGER.debug("Path seach failed for " + file);
        } catch (InterruptedException ex) {
            LOGGER.debug("Path seach failed for " + file);
        }
        return false;
    }
}
