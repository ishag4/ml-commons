/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.ml.common.httpclient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.opensearch.ml.common.connector.CertificateProcessor.CA_CERT_PEM_FIELD;
import static org.opensearch.ml.common.connector.CertificateProcessor.CLIENT_CERT_PEM_FIELD;
import static org.opensearch.ml.common.connector.CertificateProcessor.CLIENT_KEY_PEM_FIELD;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.opensearch.ml.common.connector.CertificateProcessor;
import org.opensearch.ml.common.connector.ConnectorClientConfig;

/**
 * End-to-end TLS handshake tests for {@link MLSslContextFactory}.
 *
 * <p>{@link MLSslContextFactoryTest} verifies that an SSLContext is produced with the right shape.
 * This class proves the SSLContext actually works, by running complete TLS handshakes against a
 * peer that demands a client certificate and asserting on the certificate that peer received.
 *
 * <p>The handshakes are driven through {@link SSLEngine} buffers in memory rather than over a
 * socket. That keeps the test free of ports, timeouts and background threads - the usual sources of
 * CI flakiness - while exercising exactly the same TLS machinery. Crucially, the client engines set
 * {@code endpointIdentificationAlgorithm=HTTPS}, which is what {@code java.net.http.HttpClient}
 * does internally, so hostname verification behaviour is reproduced faithfully.
 */
public class MLSslContextFactoryTlsHandshakeTest {

    // The [^\r\n]* after each header tolerates trailing content on the header line, matching
    // CertificateProcessor's own patterns. The fixtures carry a "# checkers:disable ..." suppression
    // comment there so secret scanners do not flag these throwaway test keys.
    private static final Pattern CERT_PATTERN = Pattern
        .compile("-----BEGIN CERTIFICATE-----[^\\r\\n]*\\s*([A-Za-z0-9+/\\s=]+?)\\s*-----END CERTIFICATE-----", Pattern.DOTALL);
    private static final Pattern KEY_PATTERN = Pattern
        .compile("-----BEGIN PRIVATE KEY-----[^\\r\\n]*\\s*([A-Za-z0-9+/\\s=]+?)\\s*-----END PRIVATE KEY-----", Pattern.DOTALL);

    /** The host the client believes it is connecting to, for hostname verification purposes. */
    private static final String CLIENT_TARGET_HOST = "localhost";

    /**
     * Backstop so a driver defect can never hang CI: these handshakes complete in milliseconds, so
     * anything approaching this limit is a bug, and failing is far more useful than blocking a job.
     */
    @Rule
    public Timeout globalTimeout = Timeout.seconds(60);

    private CertificateProcessor certificateProcessor;

    @Before
    public void setUp() {
        certificateProcessor = new CertificateProcessor();
    }

    // ========== MUTUAL TLS ==========

    /**
     * The core proof for this feature: with mutual_tls_enabled the client presents its certificate,
     * and a server requiring client auth both completes the handshake and sees the expected identity.
     */
    @Test
    public void testMutualTls_ClientCertificateIsPresentedToServer() throws Exception {
        Map<String, String> credentials = new HashMap<>();
        credentials.put(CLIENT_CERT_PEM_FIELD, readFixture("mtls-client-cert.pem"));
        credentials.put(CLIENT_KEY_PEM_FIELD, readFixture("mtls-client-key.pem"));
        credentials.put(CA_CERT_PEM_FIELD, readFixture("mtls-ca-cert.pem"));

        ConnectorClientConfig config = ConnectorClientConfig.builder().mutualTlsEnabled(true).keystoreType("PEM").build();

        SSLContext sslContext = MLSslContextFactory.create(config, credentials, certificateProcessor);
        assertNotNull("Mutual TLS configuration must produce an SSLContext", sslContext);

        SSLEngine client = clientEngine(sslContext);
        SSLEngine server = serverEngine("mtls-server-cert.pem", "mtls-server-key.pem", "mtls-ca-cert.pem", true);

        handshake(client, server);

        X509Certificate presented = (X509Certificate) server.getSession().getPeerCertificates()[0];
        assertNotNull("Server must have received a client certificate", presented);
        assertTrue(
            "Server should see our test client identity, but saw: " + presented.getSubjectX500Principal().getName(),
            presented.getSubjectX500Principal().getName().contains("ml-commons-test-client")
        );
    }

    /**
     * The negative control for the test above. Without an SSLContext from the factory the JDK falls
     * back to its default, which holds no client key material, so a server demanding client auth
     * rejects the connection. Before this change an MCP connector behaved exactly this way even when
     * mutual TLS <em>was</em> configured, because the configuration never reached the transport.
     */
    @Test
    public void testMutualTls_WithoutClientCertificateHandshakeFails() throws Exception {
        // Trust the server, so the only possible reason for failure is the absent client certificate.
        SSLEngine client = clientEngine(trustOnlyContext());
        SSLEngine server = serverEngine("mtls-server-cert.pem", "mtls-server-key.pem", "mtls-ca-cert.pem", true);

        try {
            handshake(client, server);
            fail("Handshake must fail when no client certificate is presented to a server requiring client auth");
        } catch (SSLException expected) {
            assertRejectedByTls(expected);
        }
    }

    /**
     * Certificates alone are not enough - the server must also be trusted. Here the client is
     * configured for mutual TLS with a CA that did not issue the server's certificate, so the
     * handshake must fail rather than silently proceeding.
     */
    @Test
    public void testMutualTls_UntrustedServerIsRejected() throws Exception {
        Map<String, String> credentials = new HashMap<>();
        credentials.put(CLIENT_CERT_PEM_FIELD, readFixture("mtls-client-cert.pem"));
        credentials.put(CLIENT_KEY_PEM_FIELD, readFixture("mtls-client-key.pem"));
        credentials.put(CA_CERT_PEM_FIELD, readFixture("mtls-ca-cert.pem"));

        ConnectorClientConfig config = ConnectorClientConfig.builder().mutualTlsEnabled(true).keystoreType("PEM").build();
        SSLContext sslContext = MLSslContextFactory.create(config, credentials, certificateProcessor);

        SSLEngine client = clientEngine(sslContext);
        // Self-signed server certificate, not issued by the trusted CA.
        SSLEngine server = serverEngine("mtls-untrusted-server-cert.pem", "mtls-untrusted-server-key.pem", null, false);

        try {
            handshake(client, server);
            fail("A server certificate outside the configured CA must be rejected");
        } catch (SSLException expected) {
            assertRejectedByTls(expected);
        }
    }

    // ========== SKIP SSL VERIFICATION ==========

    /**
     * Proves skip_ssl_verification bypasses <em>both</em> chain validation and hostname verification.
     *
     * <p>The server presents a self-signed certificate issued for "wrong-host.invalid" while the
     * client believes it is talking to "localhost", so the connection fails both checks. It succeeds
     * only because the trust manager extends {@code X509ExtendedTrustManager}: the JDK performs the
     * hostname check inside the trust manager whenever endpoint identification is set to HTTPS, so a
     * plain {@code X509TrustManager} would be wrapped in a delegate that still enforces it, leaving
     * skip_ssl_verification only half applied. If that detail regresses, this test fails.
     */
    @Test
    public void testSkipSslVerification_AcceptsUntrustedAndHostnameMismatchedServer() throws Exception {
        ConnectorClientConfig config = ConnectorClientConfig.builder().skipSslVerification(true).build();
        SSLContext sslContext = MLSslContextFactory.create(config, new HashMap<>(), certificateProcessor);
        assertNotNull("skip_ssl_verification must produce an SSLContext", sslContext);

        SSLEngine client = clientEngine(sslContext);
        SSLEngine server = serverEngine("mtls-untrusted-server-cert.pem", "mtls-untrusted-server-key.pem", null, false);

        handshake(client, server);

        assertTrue("Handshake should have completed against the untrusted server", client.getSession().isValid());
        assertEquals(
            "The mismatched hostname must not have prevented the handshake",
            "wrong-host.invalid",
            commonName((X509Certificate) client.getSession().getPeerCertificates()[0])
        );
    }

    /**
     * The negative control: the same server is rejected by a normally-configured client, confirming
     * the fixture really is untrusted and hostname-mismatched, so the test above proves something.
     */
    @Test
    public void testUntrustedServerIsRejectedWithoutSkipSslVerification() throws Exception {
        SSLEngine client = clientEngine(SSLContext.getDefault());
        SSLEngine server = serverEngine("mtls-untrusted-server-cert.pem", "mtls-untrusted-server-key.pem", null, false);

        try {
            handshake(client, server);
            fail("An untrusted, hostname-mismatched server must be rejected by default");
        } catch (SSLException expected) {
            assertRejectedByTls(expected);
        }
    }

    /**
     * Isolates hostname verification from chain validation: the client trusts the CA that issued the
     * server certificate, so the chain is valid, but the certificate names a different host. Proves
     * the hostname check is genuinely active in this harness - without it, the skip_ssl_verification
     * test above would pass even if hostname verification were never bypassed.
     */
    @Test
    public void testHostnameMismatchIsRejectedEvenWhenChainIsTrusted() throws Exception {
        // The server certificate is issued by the trusted CA and is valid for "localhost", so the
        // chain checks out - but the client is pointed at a host the certificate does not cover.
        SSLEngine client = clientEngine(trustOnlyContext(), "not-the-right-host.example");
        SSLEngine server = serverEngine("mtls-server-cert.pem", "mtls-server-key.pem", "mtls-ca-cert.pem", false);

        try {
            handshake(client, server);
            fail("A trusted certificate for the wrong hostname must still be rejected");
        } catch (SSLException expected) {
            assertRejectedByTls(expected);
        }
    }

    // ========== ENGINE SETUP ==========

    private SSLEngine clientEngine(SSLContext sslContext) {
        return clientEngine(sslContext, CLIENT_TARGET_HOST);
    }

    /**
     * Builds a client engine configured the way {@code java.net.http.HttpClient} configures its own:
     * client mode, with endpoint identification set to HTTPS so hostname verification is performed
     * inside the trust manager.
     */
    private SSLEngine clientEngine(SSLContext sslContext, String peerHost) {
        SSLEngine engine = sslContext.createSSLEngine(peerHost, 443);
        engine.setUseClientMode(true);

        SSLParameters parameters = engine.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        engine.setSSLParameters(parameters);

        return engine;
    }

    private SSLEngine serverEngine(String certFixture, String keyFixture, String caFixture, boolean needClientAuth) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore
            .setKeyEntry(
                "server",
                parsePrivateKey(readFixture(keyFixture)),
                new char[0],
                new X509Certificate[] { parseCertificate(readFixture(certFixture)) }
            );

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);

        TrustManagerFactory tmf = null;
        if (caFixture != null) {
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("ca", parseCertificate(readFixture(caFixture)));
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
        }

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf != null ? tmf.getTrustManagers() : null, null);

        SSLEngine engine = context.createSSLEngine();
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(needClientAuth);
        return engine;
    }

    /** An SSLContext that trusts the test CA but presents no client certificate. */
    private SSLContext trustOnlyContext() throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", parseCertificate(readFixture("mtls-ca-cert.pem")));

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        return context;
    }

    // ========== IN-MEMORY HANDSHAKE ==========

    private static final ByteBuffer NO_APP_DATA = ByteBuffer.allocate(0);

    private static final String STALL_MESSAGE = "TLS handshake stalled";
    private static final String NO_CONVERGE_MESSAGE = "TLS handshake did not converge";

    /**
     * Asserts a handshake failed because TLS validation rejected it, not because this test harness
     * stalled or ran out of rounds. Without this guard a negative test would pass even if the
     * rejection never happened and the driver merely broke, which would make it worthless.
     */
    private static void assertRejectedByTls(SSLException exception) {
        String message = String.valueOf(exception.getMessage());
        assertTrue(
            "Handshake must fail through TLS validation, not a harness problem: " + message,
            !message.contains(STALL_MESSAGE) && !message.contains(NO_CONVERGE_MESSAGE)
        );
    }

    /**
     * Drives a complete TLS handshake between two engines by shuttling bytes through one persistent
     * buffer per direction.
     *
     * <p>The buffers must persist across rounds: {@code unwrap} legitimately returns OK having
     * consumed nothing when the receiving engine has to {@code wrap} a reply before it can accept
     * more input. Those undelivered bytes are retained by {@code compact()} and re-offered on the
     * next round. Any handshake failure - an untrusted chain, a hostname mismatch, or a missing
     * client certificate - surfaces from {@code wrap}/{@code unwrap} as an {@link SSLException},
     * which is what the negative tests assert on.
     */
    private static void handshake(SSLEngine client, SSLEngine server) throws SSLException {
        client.beginHandshake();
        server.beginHandshake();

        int packetSize = Math.max(client.getSession().getPacketBufferSize(), server.getSession().getPacketBufferSize());
        // Doubled so a flight can accumulate while the peer is still draining the previous one.
        ByteBuffer clientToServer = ByteBuffer.allocate(packetSize * 2);
        ByteBuffer serverToClient = ByteBuffer.allocate(packetSize * 2);

        for (int round = 0; round < 200; round++) {
            boolean progress = produce(client, clientToServer);
            progress |= produce(server, serverToClient);
            progress |= consume(server, clientToServer);
            progress |= consume(client, serverToClient);

            boolean drained = clientToServer.position() == 0 && serverToClient.position() == 0;
            if (isComplete(client) && isComplete(server) && drained) {
                return;
            }
            if (!progress) {
                throw new SSLException(
                    STALL_MESSAGE
                        + ": client="
                        + client.getHandshakeStatus()
                        + ", server="
                        + server.getHandshakeStatus()
                        + ", pending="
                        + clientToServer.position()
                        + "/"
                        + serverToClient.position()
                );
            }
        }
        throw new SSLException(NO_CONVERGE_MESSAGE + " within the expected number of rounds");
    }

    /**
     * Wraps everything the engine currently wants to send into the outbound buffer, which is kept in
     * write mode.
     *
     * @return true if any bytes were produced
     */
    private static boolean produce(SSLEngine from, ByteBuffer outbound) throws SSLException {
        boolean produced = false;
        runDelegatedTasks(from);

        while (from.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            SSLEngineResult result = from.wrap(NO_APP_DATA, outbound);
            runDelegatedTasks(from);

            if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new SSLException("Engine closed during handshake");
            }
            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                // Outbound buffer full - let the peer drain it before producing more.
                break;
            }
            if (result.bytesProduced() == 0) {
                break;
            }
            produced = true;
        }
        return produced;
    }

    /**
     * Offers the pending inbound bytes to the engine, retaining anything it could not yet consume.
     *
     * @return true if any bytes were consumed
     */
    private static boolean consume(SSLEngine to, ByteBuffer inbound) throws SSLException {
        if (inbound.position() == 0) {
            return false;
        }

        boolean consumed = false;
        ByteBuffer app = ByteBuffer.allocate(to.getSession().getApplicationBufferSize());
        inbound.flip();

        try {
            while (inbound.hasRemaining()) {
                int positionBefore = inbound.position();
                SSLEngineResult result = to.unwrap(inbound, app);
                runDelegatedTasks(to);

                if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    // Application buffer too small for the decoded record - grow it and retry.
                    app = ByteBuffer.allocate(app.capacity() * 2);
                    continue;
                }
                // BUFFER_UNDERFLOW: a partial record, needs more bytes from the peer.
                // CLOSED: engine is shutting down.
                // No progress: the engine must wrap a reply before it can accept more input.
                // In every case the remainder is preserved by compact() below.
                if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW
                    || result.getStatus() == SSLEngineResult.Status.CLOSED
                    || (inbound.position() == positionBefore && result.bytesProduced() == 0)) {
                    break;
                }
                consumed = true;
            }
        } finally {
            inbound.compact();
        }
        return consumed;
    }

    private static boolean isComplete(SSLEngine engine) {
        return engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING && engine.getSession().isValid();
    }

    /**
     * Drains all pending delegated tasks. Deliberately a single {@code if} rather than a loop: the
     * inner drain already exhausts the queue, and wrapping it in {@code while (status == NEED_TASK)}
     * would busy-wait forever if the engine ever reported NEED_TASK with no task available.
     */
    private static void runDelegatedTasks(SSLEngine engine) {
        if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
        }
    }

    // ========== FIXTURES ==========

    private static String readFixture(String filename) throws IOException {
        try (InputStream in = MLSslContextFactoryTlsHandshakeTest.class.getResourceAsStream("/certificates/" + filename)) {
            assertNotNull("Missing test fixture on classpath: /certificates/" + filename, in);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static X509Certificate parseCertificate(String pem) throws Exception {
        Matcher matcher = CERT_PATTERN.matcher(pem);
        assertTrue("Fixture does not contain a certificate block", matcher.find());
        byte[] der = Base64.getMimeDecoder().decode(matcher.group(1).replaceAll("\\s", ""));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    private static PrivateKey parsePrivateKey(String pem) throws Exception {
        Matcher matcher = KEY_PATTERN.matcher(pem);
        assertTrue("Fixture does not contain a PKCS#8 private key block", matcher.find());
        byte[] der = Base64.getMimeDecoder().decode(matcher.group(1).replaceAll("\\s", ""));
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static String commonName(X509Certificate certificate) {
        Matcher matcher = Pattern.compile("CN=([^,]+)").matcher(certificate.getSubjectX500Principal().getName());
        assertTrue("Certificate subject has no CN", matcher.find());
        return matcher.group(1);
    }
}
