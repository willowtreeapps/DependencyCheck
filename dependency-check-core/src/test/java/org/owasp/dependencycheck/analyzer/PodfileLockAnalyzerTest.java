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

public class PodfileLockAnalyzerTest {

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testPatternWorks() throws Exception {
        Matcher matcher = PodfileLockAnalyzer.PODFILE_LINE_PATTERN.matcher("  - AFNetworking (2.5.3):\n");
        assertTrue(matcher.find());
        assertEquals("AFNetworking", matcher.group(1));
        assertEquals("2.5.3", matcher.group(2));
    }

    @Test
    public void testTagPatternWorks() throws Exception {
        Matcher matcher = PodfileLockAnalyzer.PODFILE_TAG_PATTERN.matcher("  - WTAHelpers (from `https://github.com/willowtreeapps/WTAHelpers.git`, tag `0.1.3`)\n");
        assertTrue(matcher.find());
        assertEquals("WTAHelpers", matcher.group(1));
        assertEquals("0.1.3", matcher.group(2));
    }

    @Test
    public void testCommitPatternWorks() throws Exception {
        Matcher matcher = PodfileLockAnalyzer.PODFILE_COMMIT_PATTERN.matcher("  - youtube-ios-player-helper (from `https://github.com/regalcinemas/youtube-ios-player-helper.git`, commit `83dcaf7edf4999ad11337db3b401d6069ccc334b`)\n");
        assertTrue(matcher.find());
        assertEquals("youtube-ios-player-helper", matcher.group(1));
        assertEquals("83dcaf7edf4999ad11337db3b401d6069ccc334b", matcher.group(2));
    }

    @Test
    public void testHashPatternWorks() throws Exception {
        Matcher matcher = PodfileLockAnalyzer.PODFILE_HASH_PATTERN.matcher("  AFNetworking: e1d86c2a96bb5d2e7408da36149806706ee122fe");
        assertTrue(matcher.find());
        assertEquals("AFNetworking", matcher.group(1));
        assertEquals("e1d86c2a96bb5d2e7408da36149806706ee122fe", matcher.group(2));
    }
}