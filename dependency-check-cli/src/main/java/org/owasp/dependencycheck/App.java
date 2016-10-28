/*
 * This file is part of dependency-check-cli.
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
package org.owasp.dependencycheck;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.cli.ParseException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.dependency.Dependency;
import org.apache.tools.ant.DirectoryScanner;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ch.qos.logback.core.FileAppender;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.slf4j.impl.StaticLoggerBinder;

/**
 * The command line interface for the DependencyCheck application.
 *
 * @author Jeremy Long
 */
public class App {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(App.class);

    /**
     * The main method for the application.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        int exitCode = 0;
        try {
            Settings.initialize();
            final App app = new App();
            exitCode = app.run(args);
            LOGGER.debug("Exit code: " + exitCode);
        } finally {
            Settings.cleanup(true);
        }
        System.exit(exitCode);
    }

    /**
     * Main CLI entry-point into the application.
     *
     * @param args the command line arguments
     * @return the exit code to return
     */
    public int run(String[] args) {
        int exitCode = 0;
        final CliParser cli = new CliParser();

        try {
            cli.parse(args);
        } catch (FileNotFoundException ex) {
            System.err.println(ex.getMessage());
            cli.printHelp();
            return -1;
        } catch (ParseException ex) {
            System.err.println(ex.getMessage());
            cli.printHelp();
            return -2;
        }

        if (cli.getVerboseLog() != null) {
            prepareLogger(cli.getVerboseLog());
        }

        if (cli.isPurge()) {
            if (cli.getConnectionString() != null) {
                LOGGER.error("Unable to purge the database when using a non-default connection string");
                exitCode = -3;
            } else {
                try {
                    populateSettings(cli);
                } catch (InvalidSettingException ex) {
                    LOGGER.error(ex.getMessage());
                    LOGGER.debug("Error loading properties file", ex);
                    exitCode = -4;
                }
                File db;
                try {
                    db = new File(Settings.getDataDirectory(), "dc.h2.db");
                    if (db.exists()) {
                        if (db.delete()) {
                            LOGGER.info("Database file purged; local copy of the NVD has been removed");
                        } else {
                            LOGGER.error("Unable to delete '{}'; please delete the file manually", db.getAbsolutePath());
                            exitCode = -5;
                        }
                    } else {
                        LOGGER.error("Unable to purge database; the database file does not exists: {}", db.getAbsolutePath());
                        exitCode = -6;
                    }
                } catch (IOException ex) {
                    LOGGER.error("Unable to delete the database");
                    exitCode = -7;
                }
            }
        } else if (cli.isGetVersion()) {
            cli.printVersionInfo();
        } else if (cli.isUpdateOnly()) {
            try {
                populateSettings(cli);
            } catch (InvalidSettingException ex) {
                LOGGER.error(ex.getMessage());
                LOGGER.debug("Error loading properties file", ex);
                exitCode = -4;
            }
            try {
                runUpdateOnly();
            } catch (UpdateException ex) {
                LOGGER.error(ex.getMessage());
                exitCode = -8;
            } catch (DatabaseException ex) {
                LOGGER.error(ex.getMessage());
                exitCode = -9;
            }
        } else if (cli.isRunScan()) {
            try {
                populateSettings(cli);
            } catch (InvalidSettingException ex) {
                LOGGER.error(ex.getMessage());
                LOGGER.debug("Error loading properties file", ex);
                exitCode = -4;
            }
            try {
                final String[] scanFiles = cli.getScanFiles();
                if (scanFiles != null) {
                    runScan(cli.getReportDirectory(), cli.getReportFormat(), cli.getProjectName(), scanFiles,
                            cli.getExcludeList(), cli.getSymLinkDepth());
                } else {
                    LOGGER.error("No scan files configured");
                }
            } catch (InvalidScanPathException ex) {
                LOGGER.error("An invalid scan path was detected; unable to scan '//*' paths");
                exitCode = -10;
            } catch (DatabaseException ex) {
                LOGGER.error(ex.getMessage());
                exitCode = -11;
            } catch (ReportException ex) {
                LOGGER.error(ex.getMessage());
                exitCode = -12;
            } catch (ExceptionCollection ex) {
                if (ex.isFatal()) {
                    exitCode = -13;
                    LOGGER.error("One or more fatal errors occurred");
                } else {
                    exitCode = -14;
                }
                for (Throwable e : ex.getExceptions()) {
                    LOGGER.error(e.getMessage());
                }
            }
        } else {
            cli.printHelp();
        }
        return exitCode;
    }

    /**
     * Scans the specified directories and writes the dependency reports to the
     * reportDirectory.
     *
     * @param reportDirectory the path to the directory where the reports will
     * be written
     * @param outputFormat the output format of the report
     * @param applicationName the application name for the report
     * @param files the files/directories to scan
     * @param excludes the patterns for files/directories to exclude
     * @param symLinkDepth the depth that symbolic links will be followed
     *
     * @throws InvalidScanPathException thrown if the path to scan starts with
     * "//"
     * @throws ReportException thrown when the report cannot be generated
     * @throws DatabaseException thrown when there is an error connecting to the
     * database
     * @throws ExceptionCollection thrown when an exception occurs during
     * analysis; there may be multiple exceptions contained within the
     * collection.
     */
    private void runScan(String reportDirectory, String outputFormat, String applicationName, String[] files,
            String[] excludes, int symLinkDepth) throws InvalidScanPathException, DatabaseException, ExceptionCollection, ReportException {
        Engine engine = null;
        try {
            engine = new Engine();
            final List<String> antStylePaths = new ArrayList<String>();
            for (String file : files) {
                final String antPath = ensureCanonicalPath(file);
                antStylePaths.add(antPath);
            }

            final Set<File> paths = new HashSet<File>();
            for (String file : antStylePaths) {
                LOGGER.debug("Scanning {}", file);
                final DirectoryScanner scanner = new DirectoryScanner();
                String include = file.replace('\\', '/');
                File baseDir;

                if (include.startsWith("//")) {
                    throw new InvalidScanPathException("Unable to scan paths specified by //");
                } else {
                    final int pos = getLastFileSeparator(include);
                    final String tmpBase = include.substring(0, pos);
                    final String tmpInclude = include.substring(pos + 1);
                    if (tmpInclude.indexOf('*') >= 0 || tmpInclude.indexOf('?') >= 0
                            || (new File(include)).isFile()) {
                        baseDir = new File(tmpBase);
                        include = tmpInclude;
                    } else {
                        baseDir = new File(tmpBase, tmpInclude);
                        include = "**/*";
                    }
                }
                scanner.setBasedir(baseDir);
                final String[] includes = {include};
                scanner.setIncludes(includes);
                scanner.setMaxLevelsOfSymlinks(symLinkDepth);
                if (symLinkDepth <= 0) {
                    scanner.setFollowSymlinks(false);
                }
                if (excludes != null && excludes.length > 0) {
                    scanner.addExcludes(excludes);
                }
                scanner.scan();
                if (scanner.getIncludedFilesCount() > 0) {
                    for (String s : scanner.getIncludedFiles()) {
                        final File f = new File(baseDir, s);
                        LOGGER.debug("Found file {}", f.toString());
                        paths.add(f);
                    }
                }
            }
            engine.scan(paths);

            ExceptionCollection exCol = null;
            try {
                engine.analyzeDependencies();
            } catch (ExceptionCollection ex) {
                if (ex.isFatal()) {
                    throw ex;
                }
                exCol = ex;
            }
            final List<Dependency> dependencies = engine.getDependencies();
            DatabaseProperties prop = null;
            CveDB cve = null;
            try {
                cve = new CveDB();
                cve.open();
                prop = cve.getDatabaseProperties();
            } finally {
                if (cve != null) {
                    cve.close();
                }
            }
            final ReportGenerator report = new ReportGenerator(applicationName, dependencies, engine.getAnalyzers(), prop);
            try {
                report.generateReports(reportDirectory, outputFormat);
            } catch (ReportException ex) {
                if (exCol != null) {
                    exCol.addException(ex);
                    throw exCol;
                } else {
                    throw ex;
                }
            }
            if (exCol != null && exCol.getExceptions().size() > 0) {
                throw exCol;
            }
        } finally {
            if (engine != null) {
                engine.cleanup();
            }
        }

    }

    /**
     * Only executes the update phase of dependency-check.
     *
     * @throws UpdateException thrown if there is an error updating
     * @throws DatabaseException thrown if a fatal error occurred and a
     * connection to the database could not be established
     */
    private void runUpdateOnly() throws UpdateException, DatabaseException {
        Engine engine = null;
        try {
            engine = new Engine();
            engine.doUpdates();
        } finally {
            if (engine != null) {
                engine.cleanup();
            }
        }
    }

    /**
     * Updates the global Settings.
     *
     * @param cli a reference to the CLI Parser that contains the command line
     * arguments used to set the corresponding settings in the core engine.
     *
     * @throws InvalidSettingException thrown when a user defined properties
     * file is unable to be loaded.
     */
    private void populateSettings(CliParser cli) throws InvalidSettingException {
        final boolean autoUpdate = cli.isAutoUpdate();
        final String connectionTimeout = cli.getConnectionTimeout();
        final String proxyServer = cli.getProxyServer();
        final String proxyPort = cli.getProxyPort();
        final String proxyUser = cli.getProxyUsername();
        final String proxyPass = cli.getProxyPassword();
        final String dataDirectory = cli.getDataDirectory();
        final File propertiesFile = cli.getPropertiesFile();
        final String suppressionFile = cli.getSuppressionFile();
        final String hintsFile = cli.getHintsFile();
        final String nexusUrl = cli.getNexusUrl();
        final String databaseDriverName = cli.getDatabaseDriverName();
        final String databaseDriverPath = cli.getDatabaseDriverPath();
        final String connectionString = cli.getConnectionString();
        final String databaseUser = cli.getDatabaseUser();
        final String databasePassword = cli.getDatabasePassword();
        final String additionalZipExtensions = cli.getAdditionalZipExtensions();
        final String pathToMono = cli.getPathToMono();
        final String cveMod12 = cli.getModifiedCve12Url();
        final String cveMod20 = cli.getModifiedCve20Url();
        final String cveBase12 = cli.getBaseCve12Url();
        final String cveBase20 = cli.getBaseCve20Url();
        final Integer cveValidForHours = cli.getCveValidForHours();
        final boolean experimentalEnabled = cli.isExperimentalEnabled();

        if (propertiesFile != null) {
            try {
                Settings.mergeProperties(propertiesFile);
            } catch (FileNotFoundException ex) {
                throw new InvalidSettingException("Unable to find properties file '" + propertiesFile.getPath() + "'", ex);
            } catch (IOException ex) {
                throw new InvalidSettingException("Error reading properties file '" + propertiesFile.getPath() + "'", ex);
            }
        }
        // We have to wait until we've merged the properties before attempting to set whether we use
        // the proxy for Nexus since it could be disabled in the properties, but not explicitly stated
        // on the command line
        final boolean nexusUsesProxy = cli.isNexusUsesProxy();
        if (dataDirectory != null) {
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        } else if (System.getProperty("basedir") != null) {
            final File dataDir = new File(System.getProperty("basedir"), "data");
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDir.getAbsolutePath());
        } else {
            final File jarPath = new File(App.class.getProtectionDomain().getCodeSource().getLocation().getPath());
            final File base = jarPath.getParentFile();
            final String sub = Settings.getString(Settings.KEYS.DATA_DIRECTORY);
            final File dataDir = new File(base, sub);
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDir.getAbsolutePath());
        }
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);
        Settings.setStringIfNotEmpty(Settings.KEYS.PROXY_SERVER, proxyServer);
        Settings.setStringIfNotEmpty(Settings.KEYS.PROXY_PORT, proxyPort);
        Settings.setStringIfNotEmpty(Settings.KEYS.PROXY_USERNAME, proxyUser);
        Settings.setStringIfNotEmpty(Settings.KEYS.PROXY_PASSWORD, proxyPass);
        Settings.setStringIfNotEmpty(Settings.KEYS.CONNECTION_TIMEOUT, connectionTimeout);
        Settings.setStringIfNotEmpty(Settings.KEYS.SUPPRESSION_FILE, suppressionFile);
        Settings.setStringIfNotEmpty(Settings.KEYS.HINTS_FILE, hintsFile);
        Settings.setIntIfNotNull(Settings.KEYS.CVE_CHECK_VALID_FOR_HOURS, cveValidForHours);

        //File Type Analyzer Settings
        Settings.setBoolean(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, experimentalEnabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_JAR_ENABLED, !cli.isJarDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, !cli.isArchiveDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED, !cli.isPythonDistributionDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED, !cli.isPythonPackageDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_AUTOCONF_ENABLED, !cli.isAutoconfDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_CMAKE_ENABLED, !cli.isCmakeDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_NUSPEC_ENABLED, !cli.isNuspecDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, !cli.isAssemblyDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED, !cli.isBundleAuditDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_OPENSSL_ENABLED, !cli.isOpenSSLDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED, !cli.isComposerDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, !cli.isNodeJsDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED, !cli.isRubyGemspecDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, !cli.isCentralDisabled());
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, !cli.isNexusDisabled());

        Settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH, cli.getPathToBundleAudit());
        Settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_NEXUS_URL, nexusUrl);
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_USES_PROXY, nexusUsesProxy);
        Settings.setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_NAME, databaseDriverName);
        Settings.setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_PATH, databaseDriverPath);
        Settings.setStringIfNotEmpty(Settings.KEYS.DB_CONNECTION_STRING, connectionString);
        Settings.setStringIfNotEmpty(Settings.KEYS.DB_USER, databaseUser);
        Settings.setStringIfNotEmpty(Settings.KEYS.DB_PASSWORD, databasePassword);
        Settings.setStringIfNotEmpty(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS, additionalZipExtensions);
        Settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, pathToMono);
        if (cveBase12 != null && !cveBase12.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_SCHEMA_1_2, cveBase12);
            Settings.setString(Settings.KEYS.CVE_SCHEMA_2_0, cveBase20);
            Settings.setString(Settings.KEYS.CVE_MODIFIED_12_URL, cveMod12);
            Settings.setString(Settings.KEYS.CVE_MODIFIED_20_URL, cveMod20);
        }
    }

    /**
     * Creates a file appender and adds it to logback.
     *
     * @param verboseLog the path to the verbose log file
     */
    private void prepareLogger(String verboseLog) {
        final StaticLoggerBinder loggerBinder = StaticLoggerBinder.getSingleton();
        final LoggerContext context = (LoggerContext) loggerBinder.getLoggerFactory();

        final PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setPattern("%d %C:%L%n%-5level - %msg%n");
        encoder.setContext(context);
        encoder.start();
        final FileAppender<ILoggingEvent> fa = new FileAppender<ILoggingEvent>();
        fa.setAppend(true);
        fa.setEncoder(encoder);
        fa.setContext(context);
        fa.setFile(verboseLog);
        final File f = new File(verboseLog);
        String name = f.getName();
        final int i = name.lastIndexOf('.');
        if (i > 1) {
            name = name.substring(0, i);
        }
        fa.setName(name);
        fa.start();
        final ch.qos.logback.classic.Logger rootLogger = context.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
        rootLogger.addAppender(fa);
    }

    /**
     * Takes a path and resolves it to be a canonical &amp; absolute path. The
     * caveats are that this method will take an Ant style file selector path
     * (../someDir/**\/*.jar) and convert it to an absolute/canonical path (at
     * least to the left of the first * or ?).
     *
     * @param path the path to canonicalize
     * @return the canonical path
     */
    protected String ensureCanonicalPath(String path) {
        String basePath;
        String wildCards = null;
        final String file = path.replace('\\', '/');
        if (file.contains("*") || file.contains("?")) {

            int pos = getLastFileSeparator(file);
            if (pos < 0) {
                return file;
            }
            pos += 1;
            basePath = file.substring(0, pos);
            wildCards = file.substring(pos);
        } else {
            basePath = file;
        }

        File f = new File(basePath);
        try {
            f = f.getCanonicalFile();
            if (wildCards != null) {
                f = new File(f, wildCards);
            }
        } catch (IOException ex) {
            LOGGER.warn("Invalid path '{}' was provided.", path);
            LOGGER.debug("Invalid path provided", ex);
        }
        return f.getAbsolutePath().replace('\\', '/');
    }

    /**
     * Returns the position of the last file separator.
     *
     * @param file a file path
     * @return the position of the last file separator
     */
    private int getLastFileSeparator(String file) {
        if (file.contains("*") || file.contains("?")) {
            int p1 = file.indexOf('*');
            int p2 = file.indexOf('?');
            p1 = p1 > 0 ? p1 : file.length();
            p2 = p2 > 0 ? p2 : file.length();
            int pos = p1 < p2 ? p1 : p2;
            pos = file.lastIndexOf('/', pos);
            return pos;
        } else {
            return file.lastIndexOf('/');
        }
    }
}
