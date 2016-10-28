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
package org.owasp.dependencycheck.exception;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * A collection of several exceptions.
 *
 * @author Jeremy Long
 */
public class ExceptionCollection extends Exception {

    /**
     * Instantiates a new exception collection.
     *
     * @param exceptions a list of exceptions
     */
    public ExceptionCollection(List<Throwable> exceptions) {
        super();
        this.exceptions = exceptions;
    }

    /**
     * Instantiates a new exception collection.
     *
     * @param msg the exception message
     * @param exceptions a list of exceptions
     */
    public ExceptionCollection(String msg, List<Throwable> exceptions) {
        super(msg);
        this.exceptions = exceptions;
    }

    /**
     * Instantiates a new exception collection.
     *
     * @param exceptions a list of exceptions
     * @param fatal indicates if any of the exceptions that occurred is fatal - meaning
     * that no analysis was performed.
     */
    public ExceptionCollection(List<Throwable> exceptions, boolean fatal) {
        super();
        this.exceptions = exceptions;
        this.fatal = fatal;
    }

    /**
     * Instantiates a new exception collection.
     *
     * @param msg the exception message
     * @param exceptions a list of exceptions
     * @param fatal indicates if any of the exceptions that occurred is fatal - meaning
     * that no analysis was performed.
     */
    public ExceptionCollection(String msg, List<Throwable> exceptions, boolean fatal) {
        super(msg);
        this.exceptions = exceptions;
        this.fatal = fatal;
    }

    /**
     * Instantiates a new exception collection.
     *
     * @param exceptions a list of exceptions
     * @param fatal indicates if the exception that occurred is fatal - meaning
     * that no analysis was performed.
     */
    public ExceptionCollection(Throwable exceptions, boolean fatal) {
        super();
        this.exceptions = new ArrayList<Throwable>();
        this.exceptions.add(exceptions);
        this.fatal = fatal;
    }

    /**
     * Instantiates a new exception collection.
     *
     * @param msg the exception message
     * @param exception a list of exceptions
     */
    public ExceptionCollection(String msg, Throwable exception) {
        super(msg);
        this.exceptions = new ArrayList<Throwable>();
        this.exceptions.add(exception);
        this.fatal = false;
    }

    /**
     * Instantiates a new exception collection.
     */
    public ExceptionCollection() {
        super();
        this.exceptions = new ArrayList<Throwable>();
    }
    /**
     * The serial version uid.
     */
    private static final long serialVersionUID = 1L;

    /**
     * A collection of exceptions.
     */
    private List<Throwable> exceptions;

    /**
     * Get the value of exceptions.
     *
     * @return the value of exceptions
     */
    public List<Throwable> getExceptions() {
        return exceptions;
    }

    /**
     * Adds an exception to the collection.
     *
     * @param ex the exception to add
     */
    public void addException(Throwable ex) {
        this.exceptions.add(ex);
    }

    /**
     * Adds an exception to the collection.
     *
     * @param ex the exception to add
     * @param fatal flag indicating if this is a fatal error
     */
    public void addException(Throwable ex, boolean fatal) {
        addException(ex);
        this.fatal = fatal;
    }

    /**
     * Flag indicating if a fatal exception occurred that would prevent the
     * attempt at completing the analysis even if exceptions occurred.
     */
    private boolean fatal = false;

    /**
     * Get the value of fatal.
     *
     * @return the value of fatal
     */
    public boolean isFatal() {
        return fatal;
    }

    /**
     * Set the value of fatal.
     *
     * @param fatal new value of fatal
     */
    public void setFatal(boolean fatal) {
        this.fatal = fatal;
    }

    /**
     * Prints the stack trace.
     *
     * @param s the writer to print to
     */
    @Override
    public void printStackTrace(PrintWriter s) {
        s.println("Multiple Exceptions Occurred");
        super.printStackTrace(s);
        for (Throwable t : this.exceptions) {
            s.println("Next Exception:");
            t.printStackTrace(s);
        }
    }

    /**
     * Prints the stack trace.
     *
     * @param s the stream to write the stack trace to
     */
    @Override
    public void printStackTrace(PrintStream s) {
        s.println("Multiple Exceptions Occurred");
        super.printStackTrace(s);
        for (Throwable t : this.exceptions) {
            s.println("Next Exception:");
            t.printStackTrace(s);
        }
    }

    /**
     * Returns the error message, including the message from all contained
     * exceptions.
     *
     * @return the error message
     */
    @Override
    public String getMessage() {
        final StringBuilder sb = new StringBuilder();
        final String msg = super.getMessage();
        if (msg == null || msg.isEmpty()) {
            sb.append("One or more exceptions occurred during analysis:");
        } else {
            sb.append(msg);
        }
        for (Throwable t : this.exceptions) {
            sb.append("\n\t").append(t.getMessage());
        }
        return sb.toString();
    }
}
