package org.owasp.dependencycheck.analyzer;

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CarthageAnalyzerTest {

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testPatternWorks() throws Exception {
        Matcher matcher = CarthageAnalyzer.GITHUB_LINE_PATTERN.matcher("github \"AFNetworking/AFNetworking\" -> 2.5.1\n");
        assertTrue(matcher.find());
        assertEquals("AFNetworking/AFNetworking", matcher.group(1));
        assertEquals("2.5.1", matcher.group(2));
    }

    @Test
    public void testTagPatternWorks() throws Exception {
        Matcher matcher = CarthageAnalyzer.GIT_TAG_COMMIT_PATTERN.matcher("github \"AFNetworking/AFNetworking\" \"83dcaf7edf4999ad11337db3b401d6069ccc334b\"\n");
        assertTrue(matcher.find());
        assertEquals("AFNetworking/AFNetworking", matcher.group(1));
        assertEquals("83dcaf7edf4999ad11337db3b401d6069ccc334b", matcher.group(2));
    }

    @Test
    public void testGitTagPatternWorks() throws Exception {
        Matcher matcher = CarthageAnalyzer.GIT_TAG_COMMIT_PATTERN.matcher("git \"AFNetworking/AFNetworking\" \"83dcaf7edf4999ad11337db3b401d6069ccc334b\"\n");
        assertTrue(matcher.find());
        assertEquals("AFNetworking/AFNetworking", matcher.group(1));
        assertEquals("83dcaf7edf4999ad11337db3b401d6069ccc334b", matcher.group(2));
    }
}