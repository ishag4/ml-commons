/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.ml.common.httpclient;

import static org.opensearch.secure_sm.AccessController.doPrivileged;

import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.opensearch.ml.common.connector.CertificateProcessor;
import org.opensearch.ml.common.connector.ConnectorClientConfig;
import org.opensearch.ml.common.exception.MLException;
import org.opensearch.ml.common.exception.MLValidationException;

import lombok.extern.log4j.Log4j2;

/**
 * Builds the {@link SSLContext} used by consumers that talk to remote services through the JDK's
 * {@code java.net.http.HttpClient} - currently the MCP connector transports.
 *
 * <p>The AWS-SDK based path ({@link MLHttpClientFactory}) accepts {@code KeyManager[]}/
 * {@code TrustManager[]} directly through its own provider hooks, so it never needs an
 * {@code SSLContext}. The JDK client exposes no such hook and only accepts a fully assembled
 * {@code SSLContext}, so this class adapts the managers produced by {@link CertificateProcessor}
 * into one. TLS behaviour is otherwise kept deliberately identical between the two paths.
 */
@Log4j2
public final class MLSslContextFactory {

    private MLSslContextFactory() {}

    /**
     * Builds the SSLContext implied by the connector client configuration.
     *
     * <p>Returns {@code null} when the configuration asks for no TLS customization at all, so the
     * caller leaves the JDK client's default SSLContext untouched. That keeps connectors which do
     * not opt into mutual TLS or {@code skip_ssl_verification} on exactly the behaviour they had
     * before this class existed.
     *
     * @param config the connector client configuration, may be null
     * @param decryptedCredentials the decrypted connector credentials holding the certificate material
     * @param certificateProcessor processor used to validate the config and build the TLS managers
     * @return the SSLContext to install on the client, or null if no customization is required
     * @throws MLValidationException if the mutual TLS configuration is invalid
     */
    public static SSLContext create(
        ConnectorClientConfig config,
        Map<String, String> decryptedCredentials,
        CertificateProcessor certificateProcessor
    ) {
        if (config == null) {
            return null;
        }

        // resolveMtls returns null when mutual TLS is disabled, and rejects the
        // mutual_tls_enabled + skip_ssl_verification combination outright.
        CertificateProcessor.MtlsManagers mtlsManagers = certificateProcessor.resolveMtls(config, decryptedCredentials);

        if (mtlsManagers != null) {
            log.debug("Building mutual TLS SSLContext for the JDK HTTP client");
            return buildContext(mtlsManagers.getKeyManagers(), mtlsManagers.getTrustManagers(), "mutual TLS");
        }

        if (Boolean.TRUE.equals(config.getSkipSslVerification())) {
            log
                .warn(
                    "SSL certificate verification is DISABLED. This connection is vulnerable to man-in-the-middle"
                        + " attacks. Only use this setting in trusted environments."
                );
            return buildContext(null, new TrustManager[] { new TrustAllX509TrustManager() }, "trust-all");
        }

        return null;
    }

    /**
     * Assembles an SSLContext from the given managers. Wrapped in {@code doPrivileged} to mirror
     * {@link MLHttpClientFactory}, since SSLContext initialization reads security properties that
     * plugin code is not otherwise granted.
     */
    private static SSLContext buildContext(KeyManager[] keyManagers, TrustManager[] trustManagers, String description) {
        return doPrivileged(() -> {
            try {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(keyManagers, trustManagers, null);
                log.debug("Created {} SSLContext for the JDK HTTP client", description);
                return sslContext;
            } catch (Exception e) {
                log.error("Failed to build {} SSLContext: {}", description, e.getMessage());
                throw new MLException("Failed to build " + description + " SSLContext: " + e.getMessage(), e);
            }
        });
    }

    /**
     * Trust manager that accepts any peer certificate, backing {@code skip_ssl_verification}.
     *
     * <p>This deliberately extends {@link X509ExtendedTrustManager} rather than implementing the
     * plain {@code X509TrustManager}. The JDK's HTTP client always sets the endpoint identification
     * algorithm to "HTTPS", and hostname verification is performed inside the trust manager. A plain
     * {@code X509TrustManager} would be wrapped by the JDK in a delegate that still runs that
     * hostname check, so {@code skip_ssl_verification} would only half apply - certificate chains
     * accepted, but hostname mismatches still rejected. Extending the abstract class means these
     * no-op overrides are the ones actually invoked, and verification is genuinely skipped.
     */
    private static final class TrustAllX509TrustManager extends X509ExtendedTrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
