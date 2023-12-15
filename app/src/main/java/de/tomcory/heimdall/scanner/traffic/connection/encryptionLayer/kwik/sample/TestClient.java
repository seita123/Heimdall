package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.sample;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicClientConnection;
import net.luminis.tls.TlsConstants;

import java.io.IOException;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

public class TestClient {

    public static void main(String[] args) throws URISyntaxException, IOException {

        QuicClientConnection.Builder connectionBuilder = QuicClientConnection.newBuilder();

        // new: //142.250.181.202:443 || old: //172.217.16.74:443
        connectionBuilder.uri(new URI("//ham02s17-in-f10.1e100.net:443"));

        connectionBuilder.noServerCertificateCheck();

        connectionBuilder.applicationProtocol("h3");

        connectionBuilder.cipherSuite(TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256);

        QuicClientConnection quicConnection = connectionBuilder.build();

        quicConnection.connect();

        System.out.println(quicConnection);

    }
}
