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
package org.owasp.dependencycheck.xml.hints;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * A simple validating parser for XML Hint Rules.
 *
 * @author Jeremy Long
 */
public class HintParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HintParser.class);
    /**
     * JAXP Schema Language. Source:
     * http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String JAXP_SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
    /**
     * W3C XML Schema. Source:
     * http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String W3C_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";
    /**
     * JAXP Schema Source. Source:
     * http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String JAXP_SCHEMA_SOURCE = "http://java.sun.com/xml/jaxp/properties/schemaSource";

    /**
     * The schema for the hint XML files.
     */
    private static final String HINT_SCHEMA = "schema/dependency-hint.1.1.xsd";

    /**
     * Parses the given XML file and returns a list of the hints contained.
     *
     * @param file an XML file containing hints
     * @return a list of hint rules
     * @throws HintParseException thrown if the XML file cannot be parsed
     */
    public Hints parseHints(File file) throws HintParseException {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            return parseHints(fis);
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            throw new HintParseException(ex);
        } catch (SAXException ex) {
            throw new HintParseException(ex);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ex) {
                    LOGGER.debug("Unable to close stream", ex);
                }
            }
        }
    }

    /**
     * Parses the given XML stream and returns a list of the hint rules
     * contained.
     *
     * @param inputStream an InputStream containing hint rules
     * @return a list of hint rules
     * @throws HintParseException thrown if the XML cannot be parsed
     * @throws SAXException thrown if the XML cannot be parsed
     */
    public Hints parseHints(InputStream inputStream) throws HintParseException, SAXException {
        InputStream schemaStream = null;
        try {
            schemaStream = this.getClass().getClassLoader().getResourceAsStream(HINT_SCHEMA);
            final HintHandler handler = new HintHandler();
            final SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setNamespaceAware(true);
            factory.setValidating(true);
            final SAXParser saxParser = factory.newSAXParser();
            saxParser.setProperty(HintParser.JAXP_SCHEMA_LANGUAGE, HintParser.W3C_XML_SCHEMA);
            saxParser.setProperty(HintParser.JAXP_SCHEMA_SOURCE, new InputSource(schemaStream));
            final XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setErrorHandler(new HintErrorHandler());
            xmlReader.setContentHandler(handler);

            final Reader reader = new InputStreamReader(inputStream, "UTF-8");
            final InputSource in = new InputSource(reader);

            xmlReader.parse(in);
            final Hints hints = new Hints();
            hints.setHintRules(handler.getHintRules());
            hints.setVendorDuplicatingHintRules(handler.getVendorDuplicatingHintRules());
            return hints;
        } catch (ParserConfigurationException ex) {
            LOGGER.debug("", ex);
            throw new HintParseException(ex);
        } catch (SAXException ex) {
            if (ex.getMessage().contains("Cannot find the declaration of element 'hints'.")) {
                throw ex;
            } else {
                LOGGER.debug("", ex);
                throw new HintParseException(ex);
            }
        } catch (FileNotFoundException ex) {
            LOGGER.debug("", ex);
            throw new HintParseException(ex);
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            throw new HintParseException(ex);
        } finally {
            if (schemaStream != null) {
                try {
                    schemaStream.close();
                } catch (IOException ex) {
                    LOGGER.debug("Error closing hint file stream", ex);
                }
            }
        }
    }
}
