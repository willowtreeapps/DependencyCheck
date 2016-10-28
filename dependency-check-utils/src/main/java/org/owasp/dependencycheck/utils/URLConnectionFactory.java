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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.HttpsURLConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A URLConnection Factory to create new connections. This encapsulates several
 * configuration checks to ensure that the connection uses the correct proxy
 * settings.
 *
 * @author Jeremy Long
 */
public final class URLConnectionFactory {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(URLConnectionFactory.class);

    /**
     * Private constructor for this factory.
     */
    private URLConnectionFactory() {
    }

    /**
     * Utility method to create an HttpURLConnection. If the application is
     * configured to use a proxy this method will retrieve the proxy settings
     * and use them when setting up the connection.
     *
     * @param url the url to connect to
     * @return an HttpURLConnection
     * @throws URLConnectionFailureException thrown if there is an exception
     */
    @SuppressFBWarnings(value = "RCN_REDUNDANT_NULLCHECK_OF_NULL_VALUE", justification = "Just being extra safe")
    public static HttpURLConnection createHttpURLConnection(URL url) throws URLConnectionFailureException {
        HttpURLConnection conn = null;
        final String proxyUrl = Settings.getString(Settings.KEYS.PROXY_SERVER);

        try {
            if (proxyUrl != null && !matchNonProxy(url)) {
                final int proxyPort = Settings.getInt(Settings.KEYS.PROXY_PORT);
                final SocketAddress address = new InetSocketAddress(proxyUrl, proxyPort);

                final String username = Settings.getString(Settings.KEYS.PROXY_USERNAME);
                final String password = Settings.getString(Settings.KEYS.PROXY_PASSWORD);

                if (username != null && password != null) {
                    final Authenticator auth = new Authenticator() {
                        @Override
                        public PasswordAuthentication getPasswordAuthentication() {
                            if (getRequestorType().equals(Authenticator.RequestorType.PROXY)) {
                                return new PasswordAuthentication(username, password.toCharArray());
                            }
                            return super.getPasswordAuthentication();
                        }
                    };
                    Authenticator.setDefault(auth);
                }

                final Proxy proxy = new Proxy(Proxy.Type.HTTP, address);
                conn = (HttpURLConnection) url.openConnection(proxy);
            } else {
                conn = (HttpURLConnection) url.openConnection();
            }
            final int timeout = Settings.getInt(Settings.KEYS.CONNECTION_TIMEOUT, 10000);
            conn.setConnectTimeout(timeout);
            conn.setInstanceFollowRedirects(true);
        } catch (IOException ex) {
            if (conn != null) {
                try {
                    conn.disconnect();
                } finally {
                    conn = null;
                }
            }
            throw new URLConnectionFailureException("Error getting connection.", ex);
        }
        configureTLS(url, conn);
        return conn;
    }

    /**
     * Check if hostname matches nonProxy settings
     *
     * @param url the url to connect to
     * @return matching result. true: match nonProxy
     */
    private static boolean matchNonProxy(final URL url) {
        final String host = url.getHost();

        // code partially from org.apache.maven.plugins.site.AbstractDeployMojo#getProxyInfo
        final String nonProxyHosts = Settings.getString(Settings.KEYS.PROXY_NON_PROXY_HOSTS);
        if (null != nonProxyHosts) {
            final String[] nonProxies = nonProxyHosts.split("(,)|(;)|(\\|)");
            for (final String nonProxyHost : nonProxies) {
                //if ( StringUtils.contains( nonProxyHost, "*" ) )
                if (null != nonProxyHost && nonProxyHost.contains("*")) {
                    // Handle wildcard at the end, beginning or middle of the nonProxyHost
                    final int pos = nonProxyHost.indexOf('*');
                    final String nonProxyHostPrefix = nonProxyHost.substring(0, pos);
                    final String nonProxyHostSuffix = nonProxyHost.substring(pos + 1);
                    // prefix*
                    if (!StringUtils.isEmpty(nonProxyHostPrefix) && host.startsWith(nonProxyHostPrefix) && StringUtils.isEmpty(nonProxyHostSuffix)) {
                        return true;
                    }
                    // *suffix
                    if (StringUtils.isEmpty(nonProxyHostPrefix) && !StringUtils.isEmpty(nonProxyHostSuffix) && host.endsWith(nonProxyHostSuffix)) {
                        return true;
                    }
                    // prefix*suffix
                    if (!StringUtils.isEmpty(nonProxyHostPrefix) && host.startsWith(nonProxyHostPrefix) && !StringUtils.isEmpty(nonProxyHostSuffix)
                            && host.endsWith(nonProxyHostSuffix)) {
                        return true;
                    }
                } else if (host.equals(nonProxyHost)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Utility method to create an HttpURLConnection. The use of a proxy here is
     * optional as there may be cases where a proxy is configured but we don't
     * want to use it (for example, if there's an internal repository
     * configured)
     *
     * @param url the URL to connect to
     * @param proxy whether to use the proxy (if configured)
     * @return a newly constructed HttpURLConnection
     * @throws URLConnectionFailureException thrown if there is an exception
     */
    public static HttpURLConnection createHttpURLConnection(URL url, boolean proxy) throws URLConnectionFailureException {
        if (proxy) {
            return createHttpURLConnection(url);
        }
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) url.openConnection();
            final int timeout = Settings.getInt(Settings.KEYS.CONNECTION_TIMEOUT, 10000);
            conn.setConnectTimeout(timeout);
            conn.setInstanceFollowRedirects(true);
        } catch (IOException ioe) {
            throw new URLConnectionFailureException("Error getting connection.", ioe);
        }
        configureTLS(url, conn);
        return conn;
    }

    /**
     * If the protocol is HTTPS, this will configure the cipher suites so that
     * connections can be made to the NVD, and others, using older versions of
     * Java.
     *
     * @param url the URL
     * @param conn the connection
     */
    private static void configureTLS(URL url, URLConnection conn) {
        if ("https".equals(url.getProtocol())) {
            try {
                final HttpsURLConnection secCon = (HttpsURLConnection) conn;
                final SSLSocketFactoryEx factory = new SSLSocketFactoryEx();
                secCon.setSSLSocketFactory(factory);
            } catch (NoSuchAlgorithmException ex) {
                LOGGER.debug("Unsupported algorithm in SSLSocketFactoryEx", ex);
            } catch (KeyManagementException ex) {
                LOGGER.debug("Key management exception in SSLSocketFactoryEx", ex);
            }
        }
    }
}
