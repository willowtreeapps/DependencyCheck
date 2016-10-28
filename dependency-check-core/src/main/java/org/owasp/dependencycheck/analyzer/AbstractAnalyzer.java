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

import org.owasp.dependencycheck.exception.InitializationException;

/**
 * Base class for analyzers to avoid code duplication of initialize and close
 * as most analyzers do not need these methods.
 *
 * @author Jeremy Long
 */
public abstract class AbstractAnalyzer implements Analyzer {

    /**
     * The initialize method does nothing for this Analyzer.
     *
     * @throws InitializationException thrown if there is an exception
     */
    @Override
    public void initialize() throws InitializationException {
        //do nothing
    }

    /**
     * The close method does nothing for this Analyzer.
     *
     * @throws Exception thrown if there is an exception
     */
    @Override
    public void close() throws Exception {
        //do nothing
    }

    /**
     * The default is to support parallel processing.
     */
    @Override
    public boolean supportsParallelProcessing() {
        return true;
    }
}
