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

import java.io.File;
import java.io.FileNotFoundException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.owasp.dependencycheck.reporting.ReportGenerator.Format;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A utility to parse command line arguments for the DependencyCheck.
 *
 * @author Jeremy Long
 */
public final class CliParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CliParser.class);
    /**
     * The command line.
     */
    private CommandLine line;
    /**
     * Indicates whether the arguments are valid.
     */
    private boolean isValid = true;

    /**
     * Parses the arguments passed in and captures the results for later use.
     *
     * @param args the command line arguments
     * @throws FileNotFoundException is thrown when a 'file' argument does not
     * point to a file that exists.
     * @throws ParseException is thrown when a Parse Exception occurs.
     */
    public void parse(String[] args) throws FileNotFoundException, ParseException {
        line = parseArgs(args);

        if (line != null) {
            validateArgs();
        }
    }

    /**
     * Parses the command line arguments.
     *
     * @param args the command line arguments
     * @return the results of parsing the command line arguments
     * @throws ParseException if the arguments are invalid
     */
    private CommandLine parseArgs(String[] args) throws ParseException {
        final CommandLineParser parser = new DefaultParser();
        final Options options = createCommandLineOptions();
        return parser.parse(options, args);
    }

    /**
     * Validates that the command line arguments are valid.
     *
     * @throws FileNotFoundException if there is a file specified by either the
     * SCAN or CPE command line arguments that does not exist.
     * @throws ParseException is thrown if there is an exception parsing the
     * command line.
     */
    private void validateArgs() throws FileNotFoundException, ParseException {
        if (isUpdateOnly() || isRunScan()) {
            final String value = line.getOptionValue(ARGUMENT.CVE_VALID_FOR_HOURS);
            if (value != null) {
                try {
                    final int i = Integer.parseInt(value);
                    if (i < 0) {
                        throw new ParseException("Invalid Setting: cveValidForHours must be a number greater than or equal to 0.");
                    }
                } catch (NumberFormatException ex) {
                    throw new ParseException("Invalid Setting: cveValidForHours must be a number greater than or equal to 0.");
                }
            }
        }
        if (isRunScan()) {
            validatePathExists(getScanFiles(), ARGUMENT.SCAN);
            validatePathExists(getReportDirectory(), ARGUMENT.OUT);
            if (getPathToMono() != null) {
                validatePathExists(getPathToMono(), ARGUMENT.PATH_TO_MONO);
            }
            if (!line.hasOption(ARGUMENT.APP_NAME) && !line.hasOption(ARGUMENT.PROJECT)) {
                throw new ParseException("Missing '" + ARGUMENT.PROJECT + "' argument; the scan cannot be run without the an project name.");
            }
            if (line.hasOption(ARGUMENT.OUTPUT_FORMAT)) {
                final String format = line.getOptionValue(ARGUMENT.OUTPUT_FORMAT);
                try {
                    Format.valueOf(format);
                } catch (IllegalArgumentException ex) {
                    final String msg = String.format("An invalid 'format' of '%s' was specified. "
                            + "Supported output formats are XML, HTML, VULN, or ALL", format);
                    throw new ParseException(msg);
                }
            }
            if ((getBaseCve12Url() != null || getBaseCve20Url() != null || getModifiedCve12Url() != null || getModifiedCve20Url() != null)
                    && (getBaseCve12Url() == null || getBaseCve20Url() == null || getModifiedCve12Url() == null || getModifiedCve20Url() == null)) {
                final String msg = "If one of the CVE URLs is specified they must all be specified; please add the missing CVE URL.";
                throw new ParseException(msg);
            }
            if (line.hasOption((ARGUMENT.SYM_LINK_DEPTH))) {
                try {
                    final int i = Integer.parseInt(line.getOptionValue(ARGUMENT.SYM_LINK_DEPTH));
                    if (i < 0) {
                        throw new ParseException("Symbolic Link Depth (symLink) must be greater than zero.");
                    }
                } catch (NumberFormatException ex) {
                    throw new ParseException("Symbolic Link Depth (symLink) is not a number.");
                }
            }
        }
    }

    /**
     * Validates whether or not the path(s) points at a file that exists; if the
     * path(s) does not point to an existing file a FileNotFoundException is
     * thrown.
     *
     * @param paths the paths to validate if they exists
     * @param optType the option being validated (e.g. scan, out, etc.)
     * @throws FileNotFoundException is thrown if one of the paths being
     * validated does not exist.
     */
    private void validatePathExists(String[] paths, String optType) throws FileNotFoundException {
        for (String path : paths) {
            validatePathExists(path, optType);
        }
    }

    /**
     * Validates whether or not the path points at a file that exists; if the
     * path does not point to an existing file a FileNotFoundException is
     * thrown.
     *
     * @param path the paths to validate if they exists
     * @param argumentName the argument being validated (e.g. scan, out, etc.)
     * @throws FileNotFoundException is thrown if the path being validated does
     * not exist.
     */
    private void validatePathExists(String path, String argumentName) throws FileNotFoundException {
        if (path == null) {
            isValid = false;
            final String msg = String.format("Invalid '%s' argument: null", argumentName);
            throw new FileNotFoundException(msg);
        } else if (!path.contains("*") && !path.contains("?")) {
            File f = new File(path);
            if ("o".equalsIgnoreCase(argumentName.substring(0, 1)) && !"ALL".equalsIgnoreCase(this.getReportFormat())) {
                final String checkPath = path.toLowerCase();
                if (checkPath.endsWith(".html") || checkPath.endsWith(".xml") || checkPath.endsWith(".htm")) {
                    if (f.getParentFile() == null) {
                        f = new File(".", path);
                    }
                    if (!f.getParentFile().isDirectory()) {
                        isValid = false;
                        final String msg = String.format("Invalid '%s' argument: '%s'", argumentName, path);
                        throw new FileNotFoundException(msg);
                    }
                }
            } else if (!f.exists()) {
                isValid = false;
                final String msg = String.format("Invalid '%s' argument: '%s'", argumentName, path);
                throw new FileNotFoundException(msg);
            }
        } else if (path.startsWith("//") || path.startsWith("\\\\")) {
            isValid = false;
            final String msg = String.format("Invalid '%s' argument: '%s'%nUnable to scan paths that start with '//'.", argumentName, path);
            throw new FileNotFoundException(msg);
        } else if ((path.endsWith("/*") && !path.endsWith("**/*")) || (path.endsWith("\\*") && path.endsWith("**\\*"))) {
            final String msg = String.format("Possibly incorrect path '%s' from argument '%s' because it ends with a slash star; "
                    + "dependency-check uses ant-style paths", path, argumentName);
            LOGGER.warn(msg);
        }
    }

    /**
     * Generates an Options collection that is used to parse the command line
     * and to display the help message.
     *
     * @return the command line options used for parsing the command line
     */
    @SuppressWarnings("static-access")
    private Options createCommandLineOptions() {
        final Options options = new Options();
        addStandardOptions(options);
        addAdvancedOptions(options);
        addDeprecatedOptions(options);
        return options;
    }

    /**
     * Adds the standard command line options to the given options collection.
     *
     * @param options a collection of command line arguments
     * @throws IllegalArgumentException thrown if there is an exception
     */
    @SuppressWarnings("static-access")
    private void addStandardOptions(final Options options) throws IllegalArgumentException {
        final Option help = new Option(ARGUMENT.HELP_SHORT, ARGUMENT.HELP, false,
                "Print this message.");

        final Option advancedHelp = Option.builder().longOpt(ARGUMENT.ADVANCED_HELP)
                .desc("Print the advanced help message.").build();

        final Option version = new Option(ARGUMENT.VERSION_SHORT, ARGUMENT.VERSION,
                false, "Print the version information.");

        final Option noUpdate = new Option(ARGUMENT.DISABLE_AUTO_UPDATE_SHORT, ARGUMENT.DISABLE_AUTO_UPDATE,
                false, "Disables the automatic updating of the CPE data.");

        final Option projectName = Option.builder().hasArg().argName("name").longOpt(ARGUMENT.PROJECT)
                .desc("The name of the project being scanned. This is a required argument.")
                .build();

        final Option path = Option.builder(ARGUMENT.SCAN_SHORT).argName("path").hasArg().longOpt(ARGUMENT.SCAN)
                .desc("The path to scan - this option can be specified multiple times. Ant style"
                        + " paths are supported (e.g. path/**/*.jar).")
                .build();

        final Option excludes = Option.builder().argName("pattern").hasArg().longOpt(ARGUMENT.EXCLUDE)
                .desc("Specify and exclusion pattern. This option can be specified multiple times"
                        + " and it accepts Ant style excludsions.")
                .build();

        final Option props = Option.builder(ARGUMENT.PROP_SHORT).argName("file").hasArg().longOpt(ARGUMENT.PROP)
                .desc("A property file to load.")
                .build();

        final Option out = Option.builder(ARGUMENT.OUT_SHORT).argName("path").hasArg().longOpt(ARGUMENT.OUT)
                .desc("The folder to write reports to. This defaults to the current directory. "
                        + "It is possible to set this to a specific file name if the format argument is not set to ALL.")
                .build();

        final Option outputFormat = Option.builder(ARGUMENT.OUTPUT_FORMAT_SHORT).argName("format").hasArg().longOpt(ARGUMENT.OUTPUT_FORMAT)
                .desc("The output format to write to (XML, HTML, VULN, ALL). The default is HTML.")
                .build();

        final Option verboseLog = Option.builder(ARGUMENT.VERBOSE_LOG_SHORT).argName("file").hasArg().longOpt(ARGUMENT.VERBOSE_LOG)
                .desc("The file path to write verbose logging information.")
                .build();

        final Option symLinkDepth = Option.builder().argName("depth").hasArg().longOpt(ARGUMENT.SYM_LINK_DEPTH)
                .desc("Sets how deep nested symbolic links will be followed; 0 indicates symbolic links will not be followed.")
                .build();

        final Option suppressionFile = Option.builder().argName("file").hasArg().longOpt(ARGUMENT.SUPPRESSION_FILE)
                .desc("The file path to the suppression XML file.")
                .build();

        final Option hintsFile = Option.builder().argName("file").hasArg().longOpt(ARGUMENT.HINTS_FILE)
                .desc("The file path to the hints XML file.")
                .build();

        final Option cveValidForHours = Option.builder().argName("hours").hasArg().longOpt(ARGUMENT.CVE_VALID_FOR_HOURS)
                .desc("The number of hours to wait before checking for new updates from the NVD.")
                .build();

        final Option experimentalEnabled = Option.builder().longOpt(ARGUMENT.EXPERIMENTAL)
                .desc("Enables the experimental analzers.")
                .build();

        final Option failOnCVSS = Option.builder().hasArg().longOpt(ARGUMENT.FAIL_ON_CVSS)
                .desc("Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11; since the CVSS scores are 0-10, by default the build will never fail.")
                .build();

        //This is an option group because it can be specified more then once.
        final OptionGroup og = new OptionGroup();
        og.addOption(path);

        final OptionGroup exog = new OptionGroup();
        exog.addOption(excludes);

        options.addOptionGroup(og)
                .addOptionGroup(exog)
                .addOption(projectName)
                .addOption(out)
                .addOption(outputFormat)
                .addOption(version)
                .addOption(help)
                .addOption(advancedHelp)
                .addOption(noUpdate)
                .addOption(symLinkDepth)
                .addOption(props)
                .addOption(verboseLog)
                .addOption(suppressionFile)
                .addOption(hintsFile)
                .addOption(cveValidForHours)
                .addOption(experimentalEnabled)
                .addOption(failOnCVSS);
    }

    /**
     * Adds the advanced command line options to the given options collection.
     * These are split out for purposes of being able to display two different
     * help messages.
     *
     * @param options a collection of command line arguments
     * @throws IllegalArgumentException thrown if there is an exception
     */
    @SuppressWarnings("static-access")
    private void addAdvancedOptions(final Options options) throws IllegalArgumentException {

        final Option cve12Base = Option.builder().argName("url").hasArg().longOpt(ARGUMENT.CVE_BASE_12)
                .desc("Base URL for each year’s CVE 1.2, the %d will be replaced with the year. ")
                .build();

        final Option cve20Base = Option.builder().argName("url").hasArg().longOpt(ARGUMENT.CVE_BASE_20)
                .desc("Base URL for each year’s CVE 2.0, the %d will be replaced with the year.")
                .build();

        final Option cve12Modified = Option.builder().argName("url").hasArg().longOpt(ARGUMENT.CVE_MOD_12)
                .desc("URL for the modified CVE 1.2.")
                .build();

        final Option cve20Modified = Option.builder().argName("url").hasArg().longOpt(ARGUMENT.CVE_MOD_20)
                .desc("URL for the modified CVE 2.0.")
                .build();

        final Option updateOnly = Option.builder().longOpt(ARGUMENT.UPDATE_ONLY)
                .desc("Only update the local NVD data cache; no scan will be executed.").build();

        final Option data = Option.builder(ARGUMENT.DATA_DIRECTORY_SHORT).argName("path").hasArg().longOpt(ARGUMENT.DATA_DIRECTORY)
                .desc("The location of the H2 Database file. This option should generally not be set.")
                .build();

        final Option nexusUrl = Option.builder().argName("url").hasArg().longOpt(ARGUMENT.NEXUS_URL)
                .desc("The url to the Nexus Server's REST API Endpoint (http://domain/nexus/service/local). "
                        + "If not set the Nexus Analyzer will be disabled.").build();

        final Option nexusUsesProxy = Option.builder().argName("true/false").hasArg().longOpt(ARGUMENT.NEXUS_USES_PROXY)
                .desc("Whether or not the configured proxy should be used when connecting to Nexus.")
                .build();

        final Option additionalZipExtensions = Option.builder().argName("extensions").hasArg()
                .longOpt(ARGUMENT.ADDITIONAL_ZIP_EXTENSIONS)
                .desc("A comma separated list of additional extensions to be scanned as ZIP files "
                        + "(ZIP, EAR, WAR are already treated as zip files)").build();

        final Option pathToMono = Option.builder().argName("path").hasArg().longOpt(ARGUMENT.PATH_TO_MONO)
                .desc("The path to Mono for .NET Assembly analysis on non-windows systems.")
                .build();

        final Option pathToBundleAudit = Option.builder().argName("path").hasArg()
                .longOpt(ARGUMENT.PATH_TO_BUNDLE_AUDIT)
                .desc("The path to bundle-audit for Gem bundle analysis.").build();

        final Option connectionTimeout = Option.builder(ARGUMENT.CONNECTION_TIMEOUT_SHORT).argName("timeout").hasArg()
                .longOpt(ARGUMENT.CONNECTION_TIMEOUT).desc("The connection timeout (in milliseconds) to use when downloading resources.")
                .build();

        final Option proxyServer = Option.builder().argName("server").hasArg().longOpt(ARGUMENT.PROXY_SERVER)
                .desc("The proxy server to use when downloading resources.").build();

        final Option proxyPort = Option.builder().argName("port").hasArg().longOpt(ARGUMENT.PROXY_PORT)
                .desc("The proxy port to use when downloading resources.").build();

        final Option proxyUsername = Option.builder().argName("user").hasArg().longOpt(ARGUMENT.PROXY_USERNAME)
                .desc("The proxy username to use when downloading resources.").build();

        final Option proxyPassword = Option.builder().argName("pass").hasArg().longOpt(ARGUMENT.PROXY_PASSWORD)
                .desc("The proxy password to use when downloading resources.").build();

        final Option connectionString = Option.builder().argName("connStr").hasArg().longOpt(ARGUMENT.CONNECTION_STRING)
                .desc("The connection string to the database.").build();

        final Option dbUser = Option.builder().argName("user").hasArg().longOpt(ARGUMENT.DB_NAME)
                .desc("The username used to connect to the database.").build();

        final Option dbPassword = Option.builder().argName("password").hasArg().longOpt(ARGUMENT.DB_PASSWORD)
                .desc("The password for connecting to the database.").build();

        final Option dbDriver = Option.builder().argName("driver").hasArg().longOpt(ARGUMENT.DB_DRIVER)
                .desc("The database driver name.").build();

        final Option dbDriverPath = Option.builder().argName("path").hasArg().longOpt(ARGUMENT.DB_DRIVER_PATH)
                .desc("The path to the database driver; note, this does not need to be set unless the JAR is outside of the classpath.")
                .build();

        final Option disableJarAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_JAR)
                .desc("Disable the Jar Analyzer.").build();

        final Option disableArchiveAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_ARCHIVE)
                .desc("Disable the Archive Analyzer.").build();

        final Option disableNuspecAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_NUSPEC)
                .desc("Disable the Nuspec Analyzer.").build();

        final Option disableAssemblyAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_ASSEMBLY)
                .desc("Disable the .NET Assembly Analyzer.").build();

        final Option disablePythonDistributionAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_PY_DIST)
                .desc("Disable the Python Distribution Analyzer.").build();

        final Option disablePythonPackageAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_PY_PKG)
                .desc("Disable the Python Package Analyzer.").build();

        final Option disableComposerAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_COMPOSER)
                .desc("Disable the PHP Composer Analyzer.").build();

        final Option disableAutoconfAnalyzer = Option.builder()
                .longOpt(ARGUMENT.DISABLE_AUTOCONF)
                .desc("Disable the Autoconf Analyzer.").build();

        final Option disableOpenSSLAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_OPENSSL)
                .desc("Disable the OpenSSL Analyzer.").build();
        final Option disableCmakeAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_CMAKE)
                .desc("Disable the Cmake Analyzer.").build();

        final Option disableCentralAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_CENTRAL)
                .desc("Disable the Central Analyzer. If this analyzer is disabled it is likely you also want to disable "
                        + "the Nexus Analyzer.").build();

        final Option disableNexusAnalyzer = Option.builder().longOpt(ARGUMENT.DISABLE_NEXUS)
                .desc("Disable the Nexus Analyzer.").build();

        final Option purge = Option.builder().longOpt(ARGUMENT.PURGE_NVD)
                .desc("Purges the local NVD data cache")
                .build();

        options.addOption(updateOnly)
                .addOption(cve12Base)
                .addOption(cve20Base)
                .addOption(cve12Modified)
                .addOption(cve20Modified)
                .addOption(proxyPort)
                .addOption(proxyServer)
                .addOption(proxyUsername)
                .addOption(proxyPassword)
                .addOption(connectionTimeout)
                .addOption(connectionString)
                .addOption(dbUser)
                .addOption(data)
                .addOption(dbPassword)
                .addOption(dbDriver)
                .addOption(dbDriverPath)
                .addOption(disableJarAnalyzer)
                .addOption(disableArchiveAnalyzer)
                .addOption(disableAssemblyAnalyzer)
                .addOption(pathToBundleAudit)
                .addOption(disablePythonDistributionAnalyzer)
                .addOption(disableCmakeAnalyzer)
                .addOption(disablePythonPackageAnalyzer)
                .addOption(Option.builder().longOpt(ARGUMENT.DISABLE_RUBYGEMS)
                        .desc("Disable the Ruby Gemspec Analyzer.").build())
                .addOption(Option.builder().longOpt(ARGUMENT.DISABLE_BUNDLE_AUDIT)
                        .desc("Disable the Ruby Bundler-Audit Analyzer.").build())
                .addOption(disableAutoconfAnalyzer)
                .addOption(disableComposerAnalyzer)
                .addOption(disableOpenSSLAnalyzer)
                .addOption(disableNuspecAnalyzer)
                .addOption(disableCentralAnalyzer)
                .addOption(disableNexusAnalyzer)
                .addOption(Option.builder().longOpt(ARGUMENT.DISABLE_NODE_JS)
                        .desc("Disable the Node.js Package Analyzer.").build())
                .addOption(nexusUrl)
                .addOption(nexusUsesProxy)
                .addOption(additionalZipExtensions)
                .addOption(pathToMono)
                .addOption(pathToBundleAudit)
                .addOption(purge);
    }

    /**
     * Adds the deprecated command line options to the given options collection.
     * These are split out for purposes of not including them in the help
     * message. We need to add the deprecated options so as not to break
     * existing scripts.
     *
     * @param options a collection of command line arguments
     * @throws IllegalArgumentException thrown if there is an exception
     */
    @SuppressWarnings({"static-access", "deprecation"})
    private void addDeprecatedOptions(final Options options) throws IllegalArgumentException {

        final Option proxyServer = Option.builder().argName("url").hasArg().longOpt(ARGUMENT.PROXY_URL)
                .desc("The proxy url argument is deprecated, use proxyserver instead.")
                .build();
        final Option appName = Option.builder(ARGUMENT.APP_NAME_SHORT).argName("name").hasArg().longOpt(ARGUMENT.APP_NAME)
                .desc("The name of the project being scanned.")
                .build();

        options.addOption(proxyServer);
        options.addOption(appName);
    }

    /**
     * Determines if the 'version' command line argument was passed in.
     *
     * @return whether or not the 'version' command line argument was passed in
     */
    public boolean isGetVersion() {
        return (line != null) && line.hasOption(ARGUMENT.VERSION);
    }

    /**
     * Determines if the 'help' command line argument was passed in.
     *
     * @return whether or not the 'help' command line argument was passed in
     */
    public boolean isGetHelp() {
        return (line != null) && line.hasOption(ARGUMENT.HELP);
    }

    /**
     * Determines if the 'scan' command line argument was passed in.
     *
     * @return whether or not the 'scan' command line argument was passed in
     */
    public boolean isRunScan() {
        return (line != null) && isValid && line.hasOption(ARGUMENT.SCAN);
    }

    /**
     * Returns the symbolic link depth (how deeply symbolic links will be
     * followed).
     *
     * @return the symbolic link depth
     */
    public int getSymLinkDepth() {
        int value = 0;
        try {
            value = Integer.parseInt(line.getOptionValue(ARGUMENT.SYM_LINK_DEPTH, "0"));
            if (value < 0) {
                value = 0;
            }
        } catch (NumberFormatException ex) {
            LOGGER.debug("Symbolic link was not a number");
        }
        return value;
    }

    /**
     * Returns true if the disableJar command line argument was specified.
     *
     * @return true if the disableJar command line argument was specified;
     * otherwise false
     */
    public boolean isJarDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_JAR);
    }

    /**
     * Returns true if the disableArchive command line argument was specified.
     *
     * @return true if the disableArchive command line argument was specified;
     * otherwise false
     */
    public boolean isArchiveDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_ARCHIVE);
    }

    /**
     * Returns true if the disableNuspec command line argument was specified.
     *
     * @return true if the disableNuspec command line argument was specified;
     * otherwise false
     */
    public boolean isNuspecDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_NUSPEC);
    }

    /**
     * Returns true if the disableAssembly command line argument was specified.
     *
     * @return true if the disableAssembly command line argument was specified;
     * otherwise false
     */
    public boolean isAssemblyDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_ASSEMBLY);
    }

    /**
     * Returns true if the disableBundleAudit command line argument was
     * specified.
     *
     * @return true if the disableBundleAudit command line argument was
     * specified; otherwise false
     */
    public boolean isBundleAuditDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_BUNDLE_AUDIT);
    }

    /**
     * Returns true if the disablePyDist command line argument was specified.
     *
     * @return true if the disablePyDist command line argument was specified;
     * otherwise false
     */
    public boolean isPythonDistributionDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_PY_DIST);
    }

    /**
     * Returns true if the disablePyPkg command line argument was specified.
     *
     * @return true if the disablePyPkg command line argument was specified;
     * otherwise false
     */
    public boolean isPythonPackageDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_PY_PKG);
    }

    /**
     * Returns whether the Ruby gemspec analyzer is disabled.
     *
     * @return true if the {@link ARGUMENT#DISABLE_RUBYGEMS} command line
     * argument was specified; otherwise false
     */
    public boolean isRubyGemspecDisabled() {
        return (null != line) && line.hasOption(ARGUMENT.DISABLE_RUBYGEMS);
    }

    /**
     * Returns true if the disableCmake command line argument was specified.
     *
     * @return true if the disableCmake command line argument was specified;
     * otherwise false
     */
    public boolean isCmakeDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_CMAKE);
    }

    /**
     * Returns true if the disableAutoconf command line argument was specified.
     *
     * @return true if the disableAutoconf command line argument was specified;
     * otherwise false
     */
    public boolean isAutoconfDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_AUTOCONF);
    }

    /**
     * Returns true if the disableComposer command line argument was specified.
     *
     * @return true if the disableComposer command line argument was specified;
     * otherwise false
     */
    public boolean isComposerDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_COMPOSER);
    }

    /**
     * Returns true if the disableNexus command line argument was specified.
     *
     * @return true if the disableNexus command line argument was specified;
     * otherwise false
     */
    public boolean isNexusDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_NEXUS);
    }

    /**
     * Returns true if the disableOpenSSL command line argument was specified.
     *
     * @return true if the disableOpenSSL command line argument was specified;
     * otherwise false
     */
    public boolean isOpenSSLDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_OPENSSL);
    }

    /**
     * Returns true if the disableNodeJS command line argument was specified.
     *
     * @return true if the disableNodeJS command line argument was specified;
     * otherwise false
     */
    public boolean isNodeJsDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_NODE_JS);
    }

    /**
     * Returns true if the disableCentral command line argument was specified.
     *
     * @return true if the disableCentral command line argument was specified;
     * otherwise false
     */
    public boolean isCentralDisabled() {
        return (line != null) && line.hasOption(ARGUMENT.DISABLE_CENTRAL);
    }

    /**
     * Returns the url to the nexus server if one was specified.
     *
     * @return the url to the nexus server; if none was specified this will
     * return null;
     */
    public String getNexusUrl() {
        if (line == null || !line.hasOption(ARGUMENT.NEXUS_URL)) {
            return null;
        } else {
            return line.getOptionValue(ARGUMENT.NEXUS_URL);
        }
    }

    /**
     * Returns true if the Nexus Analyzer should use the configured proxy to
     * connect to Nexus; otherwise false is returned.
     *
     * @return true if the Nexus Analyzer should use the configured proxy to
     * connect to Nexus; otherwise false
     */
    public boolean isNexusUsesProxy() {
        // If they didn't specify whether Nexus needs to use the proxy, we should
        // still honor the property if it's set.
        if (line == null || !line.hasOption(ARGUMENT.NEXUS_USES_PROXY)) {
            try {
                return Settings.getBoolean(Settings.KEYS.ANALYZER_NEXUS_USES_PROXY);
            } catch (InvalidSettingException ise) {
                return true;
            }
        } else {
            return Boolean.parseBoolean(line.getOptionValue(ARGUMENT.NEXUS_USES_PROXY));
        }
    }

    /**
     * Displays the command line help message to the standard output.
     */
    public void printHelp() {
        final HelpFormatter formatter = new HelpFormatter();
        final Options options = new Options();
        addStandardOptions(options);
        if (line != null && line.hasOption(ARGUMENT.ADVANCED_HELP)) {
            addAdvancedOptions(options);
        }
        final String helpMsg = String.format("%n%s"
                + " can be used to identify if there are any known CVE vulnerabilities in libraries utilized by an application. "
                + "%s will automatically update required data from the Internet, such as the CVE and CPE data files from nvd.nist.gov.%n%n",
                Settings.getString("application.name", "DependencyCheck"),
                Settings.getString("application.name", "DependencyCheck"));

        formatter.printHelp(Settings.getString("application.name", "DependencyCheck"),
                helpMsg,
                options,
                "",
                true);
    }

    /**
     * Retrieves the file command line parameter(s) specified for the 'scan'
     * argument.
     *
     * @return the file paths specified on the command line for scan
     */
    public String[] getScanFiles() {
        return line.getOptionValues(ARGUMENT.SCAN);
    }

    /**
     * Retrieves the list of excluded file patterns specified by the 'exclude'
     * argument.
     *
     * @return the excluded file patterns
     */
    public String[] getExcludeList() {
        return line.getOptionValues(ARGUMENT.EXCLUDE);
    }

    /**
     * Returns the directory to write the reports to specified on the command
     * line.
     *
     * @return the path to the reports directory.
     */
    public String getReportDirectory() {
        return line.getOptionValue(ARGUMENT.OUT, ".");
    }

    /**
     * Returns the path to Mono for .NET Assembly analysis on non-windows
     * systems.
     *
     * @return the path to Mono
     */
    public String getPathToMono() {
        return line.getOptionValue(ARGUMENT.PATH_TO_MONO);
    }

    /**
     * Returns the path to bundle-audit for Ruby bundle analysis.
     *
     * @return the path to Mono
     */
    public String getPathToBundleAudit() {
        return line.getOptionValue(ARGUMENT.PATH_TO_BUNDLE_AUDIT);
    }

    /**
     * Returns the output format specified on the command line. Defaults to HTML
     * if no format was specified.
     *
     * @return the output format name.
     */
    public String getReportFormat() {
        return line.getOptionValue(ARGUMENT.OUTPUT_FORMAT, "HTML");
    }

    /**
     * Returns the application name specified on the command line.
     *
     * @return the application name.
     */
    public String getProjectName() {
        final String appName = line.getOptionValue(ARGUMENT.APP_NAME);
        String name = line.getOptionValue(ARGUMENT.PROJECT);
        if (name == null && appName != null) {
            name = appName;
            LOGGER.warn("The '" + ARGUMENT.APP_NAME + "' argument should no longer be used; use '" + ARGUMENT.PROJECT + "' instead.");
        }
        return name;
    }

    /**
     * Returns the base URL for the CVE 1.2 XMl file.
     *
     * @return the URL to the CVE 1.2 XML file.
     */
    public String getBaseCve12Url() {
        return line.getOptionValue(ARGUMENT.CVE_BASE_12);
    }

    /**
     * Returns the base URL for the CVE 2.0 XMl file.
     *
     * @return the URL to the CVE 2.0 XML file.
     */
    public String getBaseCve20Url() {
        return line.getOptionValue(ARGUMENT.CVE_BASE_20);
    }

    /**
     * Returns the URL for the modified CVE 1.2 XMl file.
     *
     * @return the URL to the modified CVE 1.2 XML file.
     */
    public String getModifiedCve12Url() {
        return line.getOptionValue(ARGUMENT.CVE_MOD_12);
    }

    /**
     * Returns the URL for the modified CVE 2.0 XMl file.
     *
     * @return the URL to the modified CVE 2.0 XML file.
     */
    public String getModifiedCve20Url() {
        return line.getOptionValue(ARGUMENT.CVE_MOD_20);
    }

    /**
     * Returns the connection timeout.
     *
     * @return the connection timeout
     */
    public String getConnectionTimeout() {
        return line.getOptionValue(ARGUMENT.CONNECTION_TIMEOUT);
    }

    /**
     * Returns the proxy server.
     *
     * @return the proxy server
     */
    @SuppressWarnings("deprecation")
    public String getProxyServer() {

        String server = line.getOptionValue(ARGUMENT.PROXY_SERVER);
        if (server == null) {
            server = line.getOptionValue(ARGUMENT.PROXY_URL);
            if (server != null) {
                LOGGER.warn("An old command line argument 'proxyurl' was detected; use proxyserver instead");
            }
        }
        return server;
    }

    /**
     * Returns the proxy port.
     *
     * @return the proxy port
     */
    public String getProxyPort() {
        return line.getOptionValue(ARGUMENT.PROXY_PORT);
    }

    /**
     * Returns the proxy username.
     *
     * @return the proxy username
     */
    public String getProxyUsername() {
        return line.getOptionValue(ARGUMENT.PROXY_USERNAME);
    }

    /**
     * Returns the proxy password.
     *
     * @return the proxy password
     */
    public String getProxyPassword() {
        return line.getOptionValue(ARGUMENT.PROXY_PASSWORD);
    }

    /**
     * Get the value of dataDirectory.
     *
     * @return the value of dataDirectory
     */
    public String getDataDirectory() {
        return line.getOptionValue(ARGUMENT.DATA_DIRECTORY);
    }

    /**
     * Returns the properties file specified on the command line.
     *
     * @return the properties file specified on the command line
     */
    public File getPropertiesFile() {
        final String path = line.getOptionValue(ARGUMENT.PROP);
        if (path != null) {
            return new File(path);
        }
        return null;
    }

    /**
     * Returns the path to the verbose log file.
     *
     * @return the path to the verbose log file
     */
    public String getVerboseLog() {
        return line.getOptionValue(ARGUMENT.VERBOSE_LOG);
    }

    /**
     * Returns the path to the suppression file.
     *
     * @return the path to the suppression file
     */
    public String getSuppressionFile() {
        return line.getOptionValue(ARGUMENT.SUPPRESSION_FILE);
    }

    /**
     * Returns the path to the hints file.
     *
     * @return the path to the hints file
     */
    public String getHintsFile() {
        return line.getOptionValue(ARGUMENT.HINTS_FILE);
    }

    /**
     * <p>
     * Prints the manifest information to standard output.</p>
     * <ul><li>Implementation-Title: ${pom.name}</li>
     * <li>Implementation-Version: ${pom.version}</li></ul>
     */
    public void printVersionInfo() {
        final String version = String.format("%s version %s",
                Settings.getString(Settings.KEYS.APPLICATION_NAME, "dependency-check"),
                Settings.getString(Settings.KEYS.APPLICATION_VERSION, "Unknown"));
        System.out.println(version);
    }

    /**
     * Checks if the auto update feature has been disabled. If it has been
     * disabled via the command line this will return false.
     *
     * @return <code>true</code> if auto-update is allowed; otherwise
     * <code>false</code>
     */
    public boolean isAutoUpdate() {
        return line != null && !line.hasOption(ARGUMENT.DISABLE_AUTO_UPDATE);
    }

    /**
     * Checks if the update only flag has been set.
     *
     * @return <code>true</code> if the update only flag has been set; otherwise
     * <code>false</code>.
     */
    public boolean isUpdateOnly() {
        return line != null && line.hasOption(ARGUMENT.UPDATE_ONLY);
    }

    /**
     * Checks if the purge NVD flag has been set.
     *
     * @return <code>true</code> if the purge nvd flag has been set; otherwise
     * <code>false</code>.
     */
    public boolean isPurge() {
        return line != null && line.hasOption(ARGUMENT.PURGE_NVD);
    }

    /**
     * Returns the database driver name if specified; otherwise null is
     * returned.
     *
     * @return the database driver name if specified; otherwise null is returned
     */
    public String getDatabaseDriverName() {
        return line.getOptionValue(ARGUMENT.DB_DRIVER);
    }

    /**
     * Returns the database driver path if specified; otherwise null is
     * returned.
     *
     * @return the database driver name if specified; otherwise null is returned
     */
    public String getDatabaseDriverPath() {
        return line.getOptionValue(ARGUMENT.DB_DRIVER_PATH);
    }

    /**
     * Returns the database connection string if specified; otherwise null is
     * returned.
     *
     * @return the database connection string if specified; otherwise null is
     * returned
     */
    public String getConnectionString() {
        return line.getOptionValue(ARGUMENT.CONNECTION_STRING);
    }

    /**
     * Returns the database database user name if specified; otherwise null is
     * returned.
     *
     * @return the database database user name if specified; otherwise null is
     * returned
     */
    public String getDatabaseUser() {
        return line.getOptionValue(ARGUMENT.DB_NAME);
    }

    /**
     * Returns the database database password if specified; otherwise null is
     * returned.
     *
     * @return the database database password if specified; otherwise null is
     * returned
     */
    public String getDatabasePassword() {
        return line.getOptionValue(ARGUMENT.DB_PASSWORD);
    }

    /**
     * Returns the additional Extensions if specified; otherwise null is
     * returned.
     *
     * @return the additional Extensions; otherwise null is returned
     */
    public String getAdditionalZipExtensions() {
        return line.getOptionValue(ARGUMENT.ADDITIONAL_ZIP_EXTENSIONS);
    }

    /**
     * Get the value of cveValidForHours.
     *
     * @return the value of cveValidForHours
     */
    public Integer getCveValidForHours() {
        final String v = line.getOptionValue(ARGUMENT.CVE_VALID_FOR_HOURS);
        if (v != null) {
            return Integer.parseInt(v);
        }
        return null;
    }

    /**
     * Returns true if the experimental analyzers are enabled.
     *
     * @return true if the experimental analyzers are enabled; otherwise false
     */
    public boolean isExperimentalEnabled() {
        return line.hasOption(ARGUMENT.EXPERIMENTAL);
    }

    /**
     * Returns the CVSS value to fail on
     *
     * @return 11 if nothing is set. Otherwise it returns the int passed from the command line arg
     */
    public int getFailOnCVSS() {
        if(line.hasOption(ARGUMENT.FAIL_ON_CVSS)) {
            String value = line.getOptionValue(ARGUMENT.FAIL_ON_CVSS);
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException nfe) {
                return 11;
            }
        } else {
            return 11;
        }
    }

    /**
     * A collection of static final strings that represent the possible command
     * line arguments.
     */
    public static class ARGUMENT {

        /**
         * The long CLI argument name specifying the directory/file to scan.
         */
        public static final String SCAN = "scan";
        /**
         * The short CLI argument name specifying the directory/file to scan.
         */
        public static final String SCAN_SHORT = "s";
        /**
         * The long CLI argument name specifying that the CPE/CVE/etc. data
         * should not be automatically updated.
         */
        public static final String DISABLE_AUTO_UPDATE = "noupdate";
        /**
         * The short CLI argument name specifying that the CPE/CVE/etc. data
         * should not be automatically updated.
         */
        public static final String DISABLE_AUTO_UPDATE_SHORT = "n";
        /**
         * The long CLI argument name specifying that only the update phase
         * should be executed; no scan should be run.
         */
        public static final String UPDATE_ONLY = "updateonly";
        /**
         * The long CLI argument name specifying that only the update phase
         * should be executed; no scan should be run.
         */
        public static final String PURGE_NVD = "purge";
        /**
         * The long CLI argument name specifying the directory to write the
         * reports to.
         */
        public static final String OUT = "out";
        /**
         * The short CLI argument name specifying the directory to write the
         * reports to.
         */
        public static final String OUT_SHORT = "o";
        /**
         * The long CLI argument name specifying the output format to write the
         * reports to.
         */
        public static final String OUTPUT_FORMAT = "format";
        /**
         * The short CLI argument name specifying the output format to write the
         * reports to.
         */
        public static final String OUTPUT_FORMAT_SHORT = "f";
        /**
         * The long CLI argument name specifying the name of the project to be
         * scanned.
         */
        public static final String PROJECT = "project";
        /**
         * The long CLI argument name specifying the name of the application to
         * be scanned.
         *
         * @deprecated project should be used instead
         */
        @Deprecated
        public static final String APP_NAME = "app";
        /**
         * The short CLI argument name specifying the name of the application to
         * be scanned.
         *
         * @deprecated project should be used instead
         */
        @Deprecated
        public static final String APP_NAME_SHORT = "a";
        /**
         * The long CLI argument name asking for help.
         */
        public static final String HELP = "help";
        /**
         * The long CLI argument name asking for advanced help.
         */
        public static final String ADVANCED_HELP = "advancedHelp";
        /**
         * The short CLI argument name asking for help.
         */
        public static final String HELP_SHORT = "h";
        /**
         * The long CLI argument name asking for the version.
         */
        public static final String VERSION_SHORT = "v";
        /**
         * The short CLI argument name asking for the version.
         */
        public static final String VERSION = "version";
        /**
         * The CLI argument name indicating the proxy port.
         */
        public static final String PROXY_PORT = "proxyport";
        /**
         * The CLI argument name indicating the proxy server.
         */
        public static final String PROXY_SERVER = "proxyserver";
        /**
         * The CLI argument name indicating the proxy url.
         *
         * @deprecated use {@link #PROXY_SERVER} instead
         */
        @Deprecated
        public static final String PROXY_URL = "proxyurl";
        /**
         * The CLI argument name indicating the proxy username.
         */
        public static final String PROXY_USERNAME = "proxyuser";
        /**
         * The CLI argument name indicating the proxy password.
         */
        public static final String PROXY_PASSWORD = "proxypass";
        /**
         * The short CLI argument name indicating the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT_SHORT = "c";
        /**
         * The CLI argument name indicating the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT = "connectiontimeout";
        /**
         * The short CLI argument name for setting the location of an additional
         * properties file.
         */
        public static final String PROP_SHORT = "P";
        /**
         * The CLI argument name for setting the location of an additional
         * properties file.
         */
        public static final String PROP = "propertyfile";
        /**
         * The CLI argument name for setting the location of the data directory.
         */
        public static final String DATA_DIRECTORY = "data";
        /**
         * The CLI argument name for setting the URL for the CVE Data Files.
         */
        public static final String CVE_MOD_12 = "cveUrl12Modified";
        /**
         * The CLI argument name for setting the URL for the CVE Data Files.
         */
        public static final String CVE_MOD_20 = "cveUrl20Modified";
        /**
         * The CLI argument name for setting the URL for the CVE Data Files.
         */
        public static final String CVE_BASE_12 = "cveUrl12Base";
        /**
         * The CLI argument name for setting the URL for the CVE Data Files.
         */
        public static final String CVE_BASE_20 = "cveUrl20Base";
        /**
         * The short CLI argument name for setting the location of the data
         * directory.
         */
        public static final String DATA_DIRECTORY_SHORT = "d";
        /**
         * The CLI argument name for setting the location of the data directory.
         */
        public static final String VERBOSE_LOG = "log";
        /**
         * The short CLI argument name for setting the location of the data
         * directory.
         */
        public static final String VERBOSE_LOG_SHORT = "l";

        /**
         * The CLI argument name for setting the depth of symbolic links that
         * will be followed.
         */
        public static final String SYM_LINK_DEPTH = "symLink";
        /**
         * The CLI argument name for setting the location of the suppression
         * file.
         */
        public static final String SUPPRESSION_FILE = "suppression";
        /**
         * The CLI argument name for setting the location of the hint
         * file.
         */
        public static final String HINTS_FILE = "hints";
        /**
         * The CLI argument name for setting the number of hours to wait before
         * checking for new updates from the NVD.
         */
        public static final String CVE_VALID_FOR_HOURS = "cveValidForHours";
        /**
         * Disables the Jar Analyzer.
         */
        public static final String DISABLE_JAR = "disableJar";
        /**
         * Disables the Archive Analyzer.
         */
        public static final String DISABLE_ARCHIVE = "disableArchive";
        /**
         * Disables the Python Distribution Analyzer.
         */
        public static final String DISABLE_PY_DIST = "disablePyDist";
        /**
         * Disables the Python Package Analyzer.
         */
        public static final String DISABLE_PY_PKG = "disablePyPkg";
        /**
         * Disables the Python Package Analyzer.
         */
        public static final String DISABLE_COMPOSER = "disableComposer";
        /**
         * Disables the Ruby Gemspec Analyzer.
         */
        public static final String DISABLE_RUBYGEMS = "disableRubygems";
        /**
         * Disables the Autoconf Analyzer.
         */
        public static final String DISABLE_AUTOCONF = "disableAutoconf";
        /**
         * Disables the Cmake Analyzer.
         */
        public static final String DISABLE_CMAKE = "disableCmake";
        /**
         * Disables the Assembly Analyzer.
         */
        public static final String DISABLE_ASSEMBLY = "disableAssembly";
        /**
         * Disables the Ruby Bundler Audit Analyzer.
         */
        public static final String DISABLE_BUNDLE_AUDIT = "disableBundleAudit";
        /**
         * Disables the Nuspec Analyzer.
         */
        public static final String DISABLE_NUSPEC = "disableNuspec";
        /**
         * Disables the Central Analyzer.
         */
        public static final String DISABLE_CENTRAL = "disableCentral";
        /**
         * Disables the Nexus Analyzer.
         */
        public static final String DISABLE_NEXUS = "disableNexus";
        /**
         * Disables the OpenSSL Analyzer.
         */
        public static final String DISABLE_OPENSSL = "disableOpenSSL";
        /**
         * Disables the Node.js Package Analyzer.
         */
        public static final String DISABLE_NODE_JS = "disableNodeJS";
        /**
         * The URL of the nexus server.
         */
        public static final String NEXUS_URL = "nexus";
        /**
         * Whether or not the defined proxy should be used when connecting to
         * Nexus.
         */
        public static final String NEXUS_USES_PROXY = "nexusUsesProxy";
        /**
         * The CLI argument name for setting the connection string.
         */
        public static final String CONNECTION_STRING = "connectionString";
        /**
         * The CLI argument name for setting the database user name.
         */
        public static final String DB_NAME = "dbUser";
        /**
         * The CLI argument name for setting the database password.
         */
        public static final String DB_PASSWORD = "dbPassword";
        /**
         * The CLI argument name for setting the database driver name.
         */
        public static final String DB_DRIVER = "dbDriverName";
        /**
         * The CLI argument name for setting the path to the database driver; in
         * case it is not on the class path.
         */
        public static final String DB_DRIVER_PATH = "dbDriverPath";
        /**
         * The CLI argument name for setting the path to mono for .NET Assembly
         * analysis on non-windows systems.
         */
        public static final String PATH_TO_MONO = "mono";
        /**
         * The CLI argument name for setting extra extensions.
         */
        public static final String ADDITIONAL_ZIP_EXTENSIONS = "zipExtensions";
        /**
         * Exclude path argument.
         */
        public static final String EXCLUDE = "exclude";
        /**
         * The CLI argument name for setting the path to bundle-audit for Ruby
         * bundle analysis.
         */
        public static final String PATH_TO_BUNDLE_AUDIT = "bundleAudit";
        /**
         * The CLI argument to enable the experimental analyzers.
         */
        private static final String EXPERIMENTAL = "enableExperimental";
        /**
         * The CLI argument to enable the experimental analyzers.
         */
        private static final String FAIL_ON_CVSS = "failOnCVSS";
    }
}
