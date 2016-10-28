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
import java.util.HashSet;
import java.util.Iterator;
import java.util.ListIterator;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * This analyzer ensures dependencies that should be grouped together, to remove
 * excess noise from the report, are grouped. An example would be Spring, Spring
 * Beans, Spring MVC, etc. If they are all for the same version and have the
 * same relative path then these should be grouped into a single dependency
 * under the core/main library.</p>
 * <p>
 * Note, this grouping only works on dependencies with identified CVE
 * entries</p>
 *
 * @author Jeremy Long
 */
public class DependencyBundlingAnalyzer extends AbstractAnalyzer {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DependencyBundlingAnalyzer.class);

    //<editor-fold defaultstate="collapsed" desc="Constants and Member Variables">
    /**
     * A pattern for obtaining the first part of a filename.
     */
    private static final Pattern STARTING_TEXT_PATTERN = Pattern.compile("^[a-zA-Z0-9]*");

    /**
     * a flag indicating if this analyzer has run. This analyzer only runs once.
     */
    private boolean analyzed = false;

    /**
     * Returns a flag indicating if this analyzer has run. This analyzer only
     * runs once. Note this is currently only used in the unit tests.
     *
     * @return a flag indicating if this analyzer has run. This analyzer only
     * runs once
     */
    protected boolean getAnalyzed() {
        return analyzed;
    }

    //</editor-fold>
    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Dependency Bundling Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.PRE_FINDING_ANALYSIS;

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
     * Does not support parallel processing as it only runs once and then
     * operates on <em>all</em> dependencies.
     *
     * @return whether or not parallel processing is enabled
     * @see #analyze(Dependency, Engine)
     */
    @Override
    public boolean supportsParallelProcessing() {
        return false;
    }

    /**
     * Analyzes a set of dependencies. If they have been found to have the same
     * base path and the same set of identifiers they are likely related. The
     * related dependencies are bundled into a single reportable item.
     *
     * @param ignore this analyzer ignores the dependency being analyzed
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    @Override
    public void analyze(Dependency ignore, Engine engine) throws AnalysisException {
        if (!analyzed) {
            analyzed = true;
            final Set<Dependency> dependenciesToRemove = new HashSet<Dependency>();
            final ListIterator<Dependency> mainIterator = engine.getDependencies().listIterator();
            //for (Dependency nextDependency : engine.getDependencies()) {
            while (mainIterator.hasNext()) {
                final Dependency dependency = mainIterator.next();
                if (mainIterator.hasNext() && !dependenciesToRemove.contains(dependency)) {
                    final ListIterator<Dependency> subIterator = engine.getDependencies().listIterator(mainIterator.nextIndex());
                    while (subIterator.hasNext()) {
                        final Dependency nextDependency = subIterator.next();
                        Dependency main = null;
                        if (hashesMatch(dependency, nextDependency) && !containedInWar(dependency.getFilePath())
                                && !containedInWar(nextDependency.getFilePath())) {
                            if (firstPathIsShortest(dependency.getFilePath(), nextDependency.getFilePath())) {
                                mergeDependencies(dependency, nextDependency, dependenciesToRemove);
                            } else {
                                mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                                break; //since we merged into the next dependency - skip forward to the next in mainIterator
                            }
                        } else if (isShadedJar(dependency, nextDependency)) {
                            if (dependency.getFileName().toLowerCase().endsWith("pom.xml")) {
                                mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                                nextDependency.getRelatedDependencies().remove(dependency);
                                break;
                            } else {
                                mergeDependencies(dependency, nextDependency, dependenciesToRemove);
                                dependency.getRelatedDependencies().remove(nextDependency);
                            }
                        } else if (cpeIdentifiersMatch(dependency, nextDependency)
                                && hasSameBasePath(dependency, nextDependency)
                                && fileNameMatch(dependency, nextDependency)) {
                            if (isCore(dependency, nextDependency)) {
                                mergeDependencies(dependency, nextDependency, dependenciesToRemove);
                            } else {
                                mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                                break; //since we merged into the next dependency - skip forward to the next in mainIterator
                            }
                        } else if ((main = getMainGemspecDependency(dependency, nextDependency)) != null) {
                            if (main == dependency) {
                                mergeDependencies(dependency, nextDependency, dependenciesToRemove);
                            } else {
                                mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                                break; //since we merged into the next dependency - skip forward to the next in mainIterator
                            }
                        } else if ((main = getMainSwiftDependency(dependency, nextDependency)) != null) {
                            if (main == dependency) {
                                mergeDependencies(dependency, nextDependency, dependenciesToRemove);
                            } else {
                                mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                                break; //since we merged into the next dependency - skip forward to the next in mainIterator
                            }
                        }
                    }
                }
            }
            //removing dependencies here as ensuring correctness and avoiding ConcurrentUpdateExceptions
            // was difficult because of the inner iterator.
            engine.getDependencies().removeAll(dependenciesToRemove);
        }
    }

    /**
     * Adds the relatedDependency to the dependency's related dependencies.
     *
     * @param dependency the main dependency
     * @param relatedDependency a collection of dependencies to be removed from
     * the main analysis loop, this is the source of dependencies to remove
     * @param dependenciesToRemove a collection of dependencies that will be
     * removed from the main analysis loop, this function adds to this
     * collection
     */
    private void mergeDependencies(final Dependency dependency, final Dependency relatedDependency, final Set<Dependency> dependenciesToRemove) {
        dependency.addRelatedDependency(relatedDependency);
        final Iterator<Dependency> i = relatedDependency.getRelatedDependencies().iterator();
        while (i.hasNext()) {
            dependency.addRelatedDependency(i.next());
            i.remove();
        }
        if (dependency.getSha1sum().equals(relatedDependency.getSha1sum())) {
            dependency.addAllProjectReferences(relatedDependency.getProjectReferences());
        }
        dependenciesToRemove.add(relatedDependency);
    }

    /**
     * Attempts to trim a maven repo to a common base path. This is typically
     * [drive]\[repo_location]\repository\[path1]\[path2].
     *
     * @param path the path to trim
     * @return a string representing the base path.
     */
    private String getBaseRepoPath(final String path) {
        int pos = path.indexOf("repository" + File.separator) + 11;
        if (pos < 0) {
            return path;
        }
        int tmp = path.indexOf(File.separator, pos);
        if (tmp <= 0) {
            return path;
        }
        if (tmp > 0) {
            pos = tmp + 1;
        }
        tmp = path.indexOf(File.separator, pos);
        if (tmp > 0) {
            pos = tmp + 1;
        }
        return path.substring(0, pos);
    }

    /**
     * Returns true if the file names (and version if it exists) of the two
     * dependencies are sufficiently similar.
     *
     * @param dependency1 a dependency2 to compare
     * @param dependency2 a dependency2 to compare
     * @return true if the identifiers in the two supplied dependencies are
     * equal
     */
    private boolean fileNameMatch(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency1.getFileName() == null
                || dependency2 == null || dependency2.getFileName() == null) {
            return false;
        }
        final String fileName1 = dependency1.getActualFile().getName();
        final String fileName2 = dependency2.getActualFile().getName();

        //version check
        final DependencyVersion version1 = DependencyVersionUtil.parseVersion(fileName1);
        final DependencyVersion version2 = DependencyVersionUtil.parseVersion(fileName2);
        if (version1 != null && version2 != null && !version1.equals(version2)) {
            return false;
        }

        //filename check
        final Matcher match1 = STARTING_TEXT_PATTERN.matcher(fileName1);
        final Matcher match2 = STARTING_TEXT_PATTERN.matcher(fileName2);
        if (match1.find() && match2.find()) {
            return match1.group().equals(match2.group());
        }

        return false;
    }

    /**
     * Returns true if the CPE identifiers in the two supplied dependencies are
     * equal.
     *
     * @param dependency1 a dependency2 to compare
     * @param dependency2 a dependency2 to compare
     * @return true if the identifiers in the two supplied dependencies are
     * equal
     */
    private boolean cpeIdentifiersMatch(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency1.getIdentifiers() == null
                || dependency2 == null || dependency2.getIdentifiers() == null) {
            return false;
        }
        boolean matches = false;
        int cpeCount1 = 0;
        int cpeCount2 = 0;
        for (Identifier i : dependency1.getIdentifiers()) {
            if ("cpe".equals(i.getType())) {
                cpeCount1 += 1;
            }
        }
        for (Identifier i : dependency2.getIdentifiers()) {
            if ("cpe".equals(i.getType())) {
                cpeCount2 += 1;
            }
        }
        if (cpeCount1 > 0 && cpeCount1 == cpeCount2) {
            for (Identifier i : dependency1.getIdentifiers()) {
                if ("cpe".equals(i.getType())) {
                    matches |= dependency2.getIdentifiers().contains(i);
                    if (!matches) {
                        break;
                    }
                }
            }
        }
        LOGGER.debug("IdentifiersMatch={} ({}, {})", matches, dependency1.getFileName(), dependency2.getFileName());
        return matches;
    }

    /**
     * Determines if the two dependencies have the same base path.
     *
     * @param dependency1 a Dependency object
     * @param dependency2 a Dependency object
     * @return true if the base paths of the dependencies are identical
     */
    private boolean hasSameBasePath(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency2 == null) {
            return false;
        }
        final File lFile = new File(dependency1.getFilePath());
        String left = lFile.getParent();
        final File rFile = new File(dependency2.getFilePath());
        String right = rFile.getParent();
        if (left == null) {
            return right == null;
        } else if (right == null) {
            return false;
        }
        if (left.equalsIgnoreCase(right)) {
            return true;
        }

        if (left.matches(".*[/\\\\]repository[/\\\\].*") && right.matches(".*[/\\\\]repository[/\\\\].*")) {
            left = getBaseRepoPath(left);
            right = getBaseRepoPath(right);
        }
        if (left.equalsIgnoreCase(right)) {
            return true;
        }
        //new code
        for (Dependency child : dependency2.getRelatedDependencies()) {
            if (hasSameBasePath(dependency1, child)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Bundling Ruby gems that are identified from different .gemspec files but
     * denote the same package path. This happens when Ruby bundler installs an
     * application's dependencies by running "bundle install".
     *
     * @param dependency1 dependency to compare
     * @param dependency2 dependency to compare
     * @return true if the the dependencies being analyzed appear to be the
     * same; otherwise false
     */
    private boolean isSameRubyGem(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency2 == null
                || !dependency1.getFileName().endsWith(".gemspec")
                || !dependency2.getFileName().endsWith(".gemspec")
                || dependency1.getPackagePath() == null
                || dependency2.getPackagePath() == null) {
            return false;
        }
        return dependency1.getPackagePath().equalsIgnoreCase(dependency2.getPackagePath());
    }

    /**
     * Ruby gems installed by "bundle install" can have zero or more *.gemspec
     * files, all of which have the same packagePath and should be grouped. If
     * one of these gemspec is from <parent>/specifications/*.gemspec, because
     * it is a stub with fully resolved gem meta-data created by Ruby bundler,
     * this dependency should be the main one. Otherwise, use dependency2 as
     * main.
     *
     * This method returns null if any dependency is not from *.gemspec, or the
     * two do not have the same packagePath. In this case, they should not be
     * grouped.
     *
     * @param dependency1 dependency to compare
     * @param dependency2 dependency to compare
     * @return the main dependency; or null if a gemspec is not included in the
     * analysis
     */
    private Dependency getMainGemspecDependency(Dependency dependency1, Dependency dependency2) {
        if (isSameRubyGem(dependency1, dependency2)) {
            final File lFile = dependency1.getActualFile();
            final File left = lFile.getParentFile();
            if (left != null && left.getName().equalsIgnoreCase("specifications")) {
                return dependency1;
            }
            return dependency2;
        }
        return null;
    }

    /**
     * Bundling same swift dependencies with the same packagePath but identified
     * by different analyzers.
     *
     * @param dependency1 dependency to test
     * @param dependency2 dependency to test
     * @return <code>true</code> if the dependencies appear to be the same;
     * otherwise <code>false</code>
     */
    private boolean isSameSwiftPackage(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency2 == null
                || (!dependency1.getFileName().endsWith(".podspec")
                && !dependency1.getFileName().equals("Package.swift"))
                || (!dependency2.getFileName().endsWith(".podspec")
                && !dependency2.getFileName().equals("Package.swift"))
                || dependency1.getPackagePath() == null
                || dependency2.getPackagePath() == null) {
            return false;
        }
        return dependency1.getPackagePath().equalsIgnoreCase(dependency2.getPackagePath());
    }

    /**
     * Determines which of the swift dependencies should be considered the
     * primary.
     *
     * @param dependency1 the first swift dependency to compare
     * @param dependency2 the second swift dependency to compare
     * @return the primary swift dependency
     */
    private Dependency getMainSwiftDependency(Dependency dependency1, Dependency dependency2) {
        if (isSameSwiftPackage(dependency1, dependency2)) {
            if (dependency1.getFileName().endsWith(".podspec")) {
                return dependency1;
            }
            return dependency2;
        }
        return null;
    }

    /**
     * This is likely a very broken attempt at determining if the 'left'
     * dependency is the 'core' library in comparison to the 'right' library.
     *
     * @param left the dependency to test
     * @param right the dependency to test against
     * @return a boolean indicating whether or not the left dependency should be
     * considered the "core" version.
     */
    boolean isCore(Dependency left, Dependency right) {
        final String leftName = left.getFileName().toLowerCase();
        final String rightName = right.getFileName().toLowerCase();

        final boolean returnVal;
        if (!rightName.matches(".*\\.(tar|tgz|gz|zip|ear|war).+") && leftName.matches(".*\\.(tar|tgz|gz|zip|ear|war).+")
                || rightName.contains("core") && !leftName.contains("core")
                || rightName.contains("kernel") && !leftName.contains("kernel")) {
            returnVal = false;
        } else if (rightName.matches(".*\\.(tar|tgz|gz|zip|ear|war).+") && !leftName.matches(".*\\.(tar|tgz|gz|zip|ear|war).+")
                || !rightName.contains("core") && leftName.contains("core")
                || !rightName.contains("kernel") && leftName.contains("kernel")) {
            returnVal = true;
//        } else if (leftName.matches(".*struts2\\-core.*") && rightName.matches(".*xwork\\-core.*")) {
//            returnVal = true;
//        } else if (rightName.matches(".*struts2\\-core.*") && leftName.matches(".*xwork\\-core.*")) {
//            returnVal = false;
        } else {
            /*
             * considered splitting the names up and comparing the components,
             * but decided that the file name length should be sufficient as the
             * "core" component, if this follows a normal naming protocol should
             * be shorter:
             * axis2-saaj-1.4.1.jar
             * axis2-1.4.1.jar       <-----
             * axis2-kernel-1.4.1.jar
             */
            returnVal = leftName.length() <= rightName.length();
        }
        LOGGER.debug("IsCore={} ({}, {})", returnVal, left.getFileName(), right.getFileName());
        return returnVal;
    }

    /**
     * Compares the SHA1 hashes of two dependencies to determine if they are
     * equal.
     *
     * @param dependency1 a dependency object to compare
     * @param dependency2 a dependency object to compare
     * @return true if the sha1 hashes of the two dependencies match; otherwise
     * false
     */
    private boolean hashesMatch(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency2 == null || dependency1.getSha1sum() == null || dependency2.getSha1sum() == null) {
            return false;
        }
        return dependency1.getSha1sum().equals(dependency2.getSha1sum());
    }

    /**
     * Determines if the jar is shaded and the created pom.xml identified the
     * same CPE as the jar - if so, the pom.xml dependency should be removed.
     *
     * @param dependency a dependency to check
     * @param nextDependency another dependency to check
     * @return true if on of the dependencies is a pom.xml and the identifiers
     * between the two collections match; otherwise false
     */
    private boolean isShadedJar(Dependency dependency, Dependency nextDependency) {
        final String mainName = dependency.getFileName().toLowerCase();
        final String nextName = nextDependency.getFileName().toLowerCase();
        if (mainName.endsWith(".jar") && nextName.endsWith("pom.xml")) {
            return dependency.getIdentifiers().containsAll(nextDependency.getIdentifiers());
        } else if (nextName.endsWith(".jar") && mainName.endsWith("pom.xml")) {
            return nextDependency.getIdentifiers().containsAll(dependency.getIdentifiers());
        }
        return false;
    }

    /**
     * Determines which path is shortest; if path lengths are equal then we use
     * compareTo of the string method to determine if the first path is smaller.
     *
     * @param left the first path to compare
     * @param right the second path to compare
     * @return <code>true</code> if the leftPath is the shortest; otherwise
     * <code>false</code>
     */
    protected boolean firstPathIsShortest(String left, String right) {
        if (left.contains("dctemp")) {
            return false;
        }
        final String leftPath = left.replace('\\', '/');
        final String rightPath = right.replace('\\', '/');

        final int leftCount = countChar(leftPath, '/');
        final int rightCount = countChar(rightPath, '/');
        if (leftCount == rightCount) {
            return leftPath.compareTo(rightPath) <= 0;
        } else {
            return leftCount < rightCount;
        }
    }

    /**
     * Counts the number of times the character is present in the string.
     *
     * @param string the string to count the characters in
     * @param c the character to count
     * @return the number of times the character is present in the string
     */
    private int countChar(String string, char c) {
        int count = 0;
        final int max = string.length();
        for (int i = 0; i < max; i++) {
            if (c == string.charAt(i)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Checks if the given file path is contained within a war or ear file.
     *
     * @param filePath the file path to check
     * @return true if the path contains '.war\' or '.ear\'.
     */
    private boolean containedInWar(String filePath) {
        return filePath == null ? false : filePath.matches(".*\\.(ear|war)[\\\\/].*");
    }
}
