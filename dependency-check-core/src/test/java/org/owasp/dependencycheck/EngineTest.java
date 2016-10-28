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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import mockit.Expectations;
import mockit.Mocked;
import org.junit.Test;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.ExceptionCollection;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Jeremy Long
 */
public class EngineTest extends BaseDBTestCase {

    @Mocked
    Analyzer analyzer;

    @Mocked
    AnalysisTask analysisTask;


    /**
     * Test of scanFile method, of class Engine.
     */
    @Test
    public void testScanFile() throws DatabaseException {
        Engine instance = new Engine();
        instance.addFileTypeAnalyzer(new JarAnalyzer());
        File file = BaseTest.getResourceAsFile(this, "dwr.jar");
        Dependency dwr = instance.scanFile(file);
        file = BaseTest.getResourceAsFile(this, "org.mortbay.jmx.jar");
        instance.scanFile(file);
        assertEquals(2, instance.getDependencies().size());

        file = BaseTest.getResourceAsFile(this, "dwr.jar");
        Dependency secondDwr = instance.scanFile(file);

        assertEquals(2, instance.getDependencies().size());
        assertTrue(dwr == secondDwr);
    }

    @Test(expected = ExceptionCollection.class)
    public void exceptionDuringAnalysisTaskExecutionIsFatal() throws DatabaseException, ExceptionCollection {
        final ExecutorService executorService = Executors.newFixedThreadPool(3);
        final Engine instance = new Engine();
        final List<Throwable> exceptions = new ArrayList<Throwable>();

        new Expectations() {{
            analysisTask.call();
            result = new IllegalStateException("Analysis task execution threw an exception");
        }};

        final List<AnalysisTask> failingAnalysisTask = new ArrayList<AnalysisTask>();
        failingAnalysisTask.add(analysisTask);

        new Expectations(instance) {{
            instance.getExecutorService(analyzer);
            result = executorService;

            instance.getAnalysisTasks(analyzer, exceptions);
            result = failingAnalysisTask;
        }};

        instance.executeAnalysisTasks(analyzer, exceptions);

        assertTrue(executorService.isShutdown());
    }
}
