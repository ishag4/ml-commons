/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.ml.engine.algorithms.remote;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.net.ssl.SSLContext;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.opensearch.ml.common.agent.MLToolSpec;
import org.opensearch.ml.common.connector.CertificateProcessor;
import org.opensearch.ml.common.connector.ConnectorClientConfig;
import org.opensearch.ml.common.connector.McpConnector;
import org.opensearch.ml.common.exception.MLValidationException;
import org.opensearch.ml.engine.MLStaticMockBase;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientSseClientTransport;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema;
import tools.jackson.databind.json.JsonMapper;

public class McpConnectorExecutorTest extends MLStaticMockBase {

    @Mock
    private McpConnector mockConnector;
    @Mock
    private McpSyncClient mcpClient;
    @Mock
    private McpClient.SyncSpec builder;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        Map<String, String> decryptedHeaders = Map.of("Authorization", "Bearer secret-token");

        when(mockConnector.getUrl()).thenReturn("http://random-url");
        when(mockConnector.getDecryptedHeaders()).thenReturn(decryptedHeaders);

        /* ---------- stub the fluent builder chain ------------------------ */
        when(builder.requestTimeout(any())).thenReturn(builder);
        when(builder.capabilities(any())).thenReturn(builder);
        when(builder.jsonSchemaValidator(any())).thenReturn(builder);
        when(builder.build()).thenReturn(mcpClient);
    }

    @Test
    public void getMcpToolSpecs_returnsExpectedSpecs() {

        String inputSchemaJSON =
            "{\"type\":\"object\",\"properties\":{\"state\":{\"title\":\"State\",\"type\":\"string\"}},\"required\":[\"state\"],\"additionalProperties\":false}";

        McpSchema.Tool tool = McpSchema.Tool
            .builder()
            .name("tool1")
            .description("desc1")
            .inputSchema(new JacksonMcpJsonMapper(JsonMapper.shared()), inputSchemaJSON)
            .build();
        McpSchema.ListToolsResult mockTools = new McpSchema.ListToolsResult(List.of(tool), null);

        when(mcpClient.listTools()).thenReturn(mockTools);
        when(mcpClient.initialize()).thenReturn(null);

        try (MockedStatic<McpClient> mocked = mockStatic(McpClient.class)) {
            mocked.when(() -> McpClient.sync(any(McpClientTransport.class))).thenReturn(builder);
            McpConnectorExecutor exec = new McpConnectorExecutor(mockConnector);
            List<MLToolSpec> specs = exec.getMcpToolSpecs();

            Assert.assertEquals(1, specs.size());
            MLToolSpec spec = specs.get(0);
            Assert.assertEquals("tool1", spec.getName());
            Assert.assertEquals("desc1", spec.getDescription());
            Assert.assertEquals(inputSchemaJSON, spec.getAttributes().get("input_schema"));
            Assert.assertSame(mcpClient, spec.getRuntimeResources().get("mcp_sync_client"));
            mocked.verify(() -> McpClient.sync(any(McpClientTransport.class)));
            verify(builder, times(1)).build();
            verify(mcpClient, times(1)).initialize();
            verify(mcpClient, times(1)).listTools();
        }
    }

    @Test
    public void getMcpToolSpecs_throwsOnInitError() {

        when(mcpClient.initialize()).thenThrow(new RuntimeException("Error initializing"));
        try (MockedStatic<McpClient> mocked = mockStatic(McpClient.class)) {
            mocked.when(() -> McpClient.sync(any(McpClientTransport.class))).thenReturn(builder);
            McpConnectorExecutor exec = new McpConnectorExecutor(mockConnector);

            assertThrows(RuntimeException.class, () -> exec.getMcpToolSpecs());
        }
    }

    @Test
    public void getMcpToolSpecs_throwsOnListToolsError() {
        when(mcpClient.initialize()).thenReturn(null);
        when(mcpClient.listTools()).thenThrow(new RuntimeException("Error listing tools"));
        try (MockedStatic<McpClient> mocked = mockStatic(McpClient.class)) {
            mocked.when(() -> McpClient.sync(any(McpClientTransport.class))).thenReturn(builder);
            McpConnectorExecutor exec = new McpConnectorExecutor(mockConnector);
            assertThrows(RuntimeException.class, () -> exec.getMcpToolSpecs());
        }
    }

    @Test
    public void testUnimplementedMethods_ThrowUnsupportedOperationException() {
        McpConnectorExecutor exec = new McpConnectorExecutor(mockConnector);

        assertThrows(UnsupportedOperationException.class, () -> exec.invokeRemoteService(null, null, null, null, null, null));
        assertThrows(UnsupportedOperationException.class, () -> exec.invokeRemoteServiceStream(null, null, null, null, null, null));
        assertThrows(UnsupportedOperationException.class, () -> exec.getScriptService());
        assertThrows(UnsupportedOperationException.class, () -> exec.getRateLimiter());
        assertThrows(UnsupportedOperationException.class, () -> exec.getMlGuard());
        assertThrows(UnsupportedOperationException.class, () -> exec.getUserRateLimiterMap());
    }

    private HttpClient.Builder captureClientCustomization() {
        HttpClient.Builder clientBuilder = mock(HttpClient.Builder.class);
        HttpClientSseClientTransport.Builder transportBuilder = mock(HttpClientSseClientTransport.Builder.class);

        when(transportBuilder.jsonMapper(any())).thenReturn(transportBuilder);
        when(transportBuilder.sseEndpoint(anyString())).thenReturn(transportBuilder);
        when(transportBuilder.connectTimeout(any())).thenReturn(transportBuilder);
        when(transportBuilder.customizeClient(any())).thenReturn(transportBuilder);
        when(transportBuilder.customizeRequest(any())).thenReturn(transportBuilder);
        when(transportBuilder.build()).thenReturn(mock(HttpClientSseClientTransport.class));

        when(mcpClient.initialize()).thenReturn(null);
        when(mcpClient.listTools()).thenReturn(new McpSchema.ListToolsResult(List.of(), null));

        try (
            MockedStatic<HttpClientSseClientTransport> mockedTransport = mockStatic(HttpClientSseClientTransport.class);
            MockedStatic<McpClient> mockedClient = mockStatic(McpClient.class)
        ) {
            mockedTransport.when(() -> HttpClientSseClientTransport.builder(anyString())).thenReturn(transportBuilder);
            mockedClient.when(() -> McpClient.sync(any(McpClientTransport.class))).thenReturn(builder);

            new McpConnectorExecutor(mockConnector).getMcpToolSpecs();
        }

        verify(transportBuilder).connectTimeout(any());
        verify(clientBuilder, never()).connectTimeout(any());

        ArgumentCaptor<Consumer<HttpClient.Builder>> captor = ArgumentCaptor.forClass(Consumer.class);
        verify(transportBuilder).customizeClient(captor.capture());
        captor.getValue().accept(clientBuilder);
        return clientBuilder;
    }

    @Test
    public void getMcpToolSpecs_defaultConfig_doesNotOverrideSslContext() {
        HttpClient.Builder clientBuilder = captureClientCustomization();

        verify(clientBuilder, never()).sslContext(any());
    }

    @Test
    public void getMcpToolSpecs_skipSslVerification_installsSslContext() {
        when(mockConnector.getConnectorClientConfig())
            .thenReturn(ConnectorClientConfig.builder().connectionTimeout(30).readTimeout(30).skipSslVerification(true).build());

        HttpClient.Builder clientBuilder = captureClientCustomization();

        verify(clientBuilder).sslContext(any(SSLContext.class));
    }

    @Test
    public void getMcpToolSpecs_validMutualTlsConfig_installsSslContext() throws IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put(CertificateProcessor.CLIENT_CERT_PEM_FIELD, readFixture("mtls-client-cert.pem"));
        credentials.put(CertificateProcessor.CLIENT_KEY_PEM_FIELD, readFixture("mtls-client-key.pem"));

        when(mockConnector.getDecryptedCredential()).thenReturn(credentials);
        when(mockConnector.getConnectorClientConfig())
            .thenReturn(
                ConnectorClientConfig.builder().connectionTimeout(30).readTimeout(30).mutualTlsEnabled(true).keystoreType("PEM").build()
            );

        HttpClient.Builder clientBuilder = captureClientCustomization();

        verify(clientBuilder).sslContext(any(SSLContext.class));
    }

    private String readFixture(String filename) throws IOException {
        try (InputStream in = getClass().getResourceAsStream("/certificates/" + filename)) {
            Assert.assertNotNull("Missing test fixture on classpath: /certificates/" + filename, in);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    public void getMcpToolSpecs_invalidMutualTlsConfig_throwsActionableValidationException() {
        when(mockConnector.getDecryptedCredential()).thenReturn(new HashMap<>());
        when(mockConnector.getConnectorClientConfig())
            .thenReturn(
                ConnectorClientConfig.builder().connectionTimeout(30).readTimeout(30).mutualTlsEnabled(true).keystoreType("PEM").build()
            );

        McpConnectorExecutor exec = new McpConnectorExecutor(mockConnector);

        MLValidationException exception = assertThrows(MLValidationException.class, exec::getMcpToolSpecs);
        Assert
            .assertFalse(
                "Validation detail must not be hidden behind the generic MCP error: " + exception.getMessage(),
                exception.getMessage().contains("Unexpected error while getting MCP tools")
            );
    }
}
