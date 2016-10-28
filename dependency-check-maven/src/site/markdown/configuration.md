Goals
====================

Goal        | Description
------------|-----------------------
aggregate   | Runs dependency-check against the child projects and aggregates the results into a single report. **Warning**: if the aggregate goal is used within the site reporting a blank report will likely be present for any goal beyond site:site (i.e. site:stage or site:deploy will likely result in blank reports being staged or deployed); however, site:site will work. See issue [#325](https://github.com/jeremylong/DependencyCheck/issues/325) for more information.
check       | Runs dependency-check against the project and generates a report.
update-only | Updates the local cache of the NVD data from NIST.
purge       | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration
====================
The following properties can be set on the dependency-check-maven plugin.

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
autoUpdate           | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false. | true
cveValidForHours     | Sets the number of hours to wait before checking for new updates from the NVD.                                     | 4
failBuildOnCVSS      | Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11 which means since the CVSS scores are 0-10, by default the build will never fail.         | 11
failOnError          | Whether the build should fail if there is an error executing the dependency-check analysis | true
format               | The report format to be generated (HTML, XML, VULN, ALL). This configuration option has no affect if using this within the Site plugin unless the externalReport is set to true. | HTML
name                 | The name of the report in the site | dependency-check or dependency-check:aggregate
outputDirectory      | The location to write the report(s). Note, this is not used if generating the report as part of a `mvn site` build | 'target'
skip                 | Skips the dependency-check analysis                       | false
skipTestScope        | Skip analysis for artifacts with Test Scope               | true
skipProvidedScope    | Skip analysis for artifacts with Provided Scope           | false
skipRuntimeScope     | Skip analysis for artifacts with Runtime Scope            | false
suppressionFile      | The file path to the XML suppression file \- used to suppress [false positives](../general/suppression.html) | &nbsp;
hintsFile            | The file path to the XML hints file \- used to resolve [false negatives](../general/hints.html)       | &nbsp;
enableExperimental   | Enable the [experimental analyzers](../analyzers/index.html). If not enabled the experimental analyzers (see below) will not be loaded or used. | false

Analyzer Configuration
====================
The following properties are used to configure the various file type analyzers.
These properties can be used to turn off specific analyzers if it is not needed.
Note, that specific analyzers will automatically disable themselves if no file
types that they support are detected - so specifically disabling them may not
be needed.

Property                      | Description                                                               | Default Value
------------------------------|---------------------------------------------------------------------------|------------------
archiveAnalyzerEnabled        | Sets whether the Archive Analyzer will be used.                           | true
zipExtensions                 | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
jarAnalyzer                   | Sets whether Jar Analyzer will be used.                                   | true
centralAnalyzerEnabled        | Sets whether Central Analyzer will be used. If this analyzer is being disabled there is a good chance you also want to disable the Nexus Analyzer (see below). | true
nexusAnalyzerEnabled          | Sets whether Nexus Analyzer will be used. This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation. | true
nexusUrl                      | Defines the Nexus Server's web service end point (example http://domain.enterprise/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp;
nexusUsesProxy                | Whether or not the defined proxy should be used when connecting to Nexus. | true
pyDistributionAnalyzerEnabled | Sets whether the [experimental](../analyzers/index.html) Python Distribution Analyzer will be used.               | true
pyPackageAnalyzerEnabled      | Sets whether the [experimental](../analyzers/index.html) Python Package Analyzer will be used.                    | true
rubygemsAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) Ruby Gemspec Analyzer will be used.                      | true
opensslAnalyzerEnabled        | Sets whether the openssl Analyzer should be used.                  | true
cmakeAnalyzerEnabled          | Sets whether the [experimental](../analyzers/index.html) CMake Analyzer should be used.                    | true
autoconfAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) autoconf Analyzer should be used.                 | true
composerAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should be used.   | true
nodeAnalyzerEnabled           | Sets whether the [experimental](../analyzers/index.html) Node.js Analyzer should be used.                  | true
nuspecAnalyzerEnabled         | Sets whether the .NET Nuget Nuspec Analyzer will be used.          | true
assemblyAnalyzerEnabled       | Sets whether the .NET Assembly Analyzer should be used.            | true
pathToMono                    | The path to Mono for .NET assembly analysis on non-windows systems.       | &nbsp;

Advanced Configuration
====================
The following properties can be configured in the plugin. However, they are less frequently changed. One exception
may be the cvedUrl properties, which can be used to host a mirror of the NVD within an enterprise environment.

Property             | Description                                                                                 | Default Value
---------------------|---------------------------------------------------------------------------------------------|------------------
cveUrl12Modified     | URL for the modified CVE 1.2.                                                               | https://nvd.nist.gov/download/nvdcve-Modified.xml.gz
cveUrl20Modified     | URL for the modified CVE 2.0.                                                               | https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz
cveUrl12Base         | Base URL for each year's CVE 1.2, the %d will be replaced with the year.                    | https://nvd.nist.gov/download/nvdcve-%d.xml.gz
cveUrl20Base         | Base URL for each year's CVE 2.0, the %d will be replaced with the year.                    | https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz
connectionTimeout    | Sets the URL Connection Timeout used when downloading external data.                        | &nbsp;
dataDirectory        | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.    | &nbsp;
databaseDriverName   | The name of the database driver. Example: org.h2.Driver.                                    | &nbsp;
databaseDriverPath   | The path to the database driver JAR file; only used if the driver is not in the class path. | &nbsp;
connectionString     | The connection string used to connect to the database.                                      | &nbsp;
serverId             | The id of a server defined in the settings.xml; this can be used to encrypt the database password. See [password encryption](http://maven.apache.org/guides/mini/guide-encryption.html) for more information. | &nbsp;
databaseUser         | The username used when connecting to the database.                                          | &nbsp;
databasePassword     | The password used when connecting to the database.                                          | &nbsp;
metaFileName         | Sets the name of the file to use for storing the metadata about the project.                | dependency-check.ser

Proxy Configuration
====================
Use [Maven's settings](https://maven.apache.org/settings.html#Proxies) to configure a proxy server. Please see the
dependency-check [proxy configuration](../data/proxy.html) page for additional problem solving techniques. If multiple proxies
are configured in the Maven settings file you must tell dependency-check which proxy to use with the following property:

Property             | Description                                                                          | Default Value
---------------------|--------------------------------------------------------------------------------------|------------------
mavenSettingsProxyId | The id for the proxy, configured via settings.xml, that dependency-check should use. | &nbsp;

