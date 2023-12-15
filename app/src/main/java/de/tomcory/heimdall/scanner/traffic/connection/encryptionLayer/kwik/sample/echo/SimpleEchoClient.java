/*
 * Copyright © 2022, 2023 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.sample.echo;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicClientConnection;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicStream;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.SysOutLogger;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

/**
 * A sample echo client that runs a very simple echo protocol on top of QUIC.
 * The echo protocol is a request-response protocol, where the client sends one request on a new stream and the server
 * responds by echoing the data from the request in a response on the same stream. After sending the response, the
 * stream is closed.
 *
 * The main method requires one argument:
 * - port number of the server (server is assumed to run on localhost)
 */
public class SimpleEchoClient {

    private int serverPort;
    private QuicClientConnection connection;

    private URI uri;

    {
        try {
            uri = new URI("//172.217.16.74:443");
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException {
        SimpleEchoClient client = null;
        try {
            client = new SimpleEchoClient(Integer.parseInt(args[0]));
        }
        catch (Exception e) {
            System.err.println("Error: expected one argument: server-port-number");
            System.exit(1);
        }

        client.run();
    }

    public SimpleEchoClient(int serverPort) {
        this.serverPort = serverPort;
    }

    public void run() throws IOException {
        SysOutLogger log = new SysOutLogger();
        // log.logPackets(true);     // Set various log categories with log.logABC()

        connection = QuicClientConnection.newBuilder()
                .uri(uri)
                .applicationProtocol("echo")
                .logger(log)
                .noServerCertificateCheck()
                .build();

        connection.connect();

        echo("hello mate!");
        echo("look, a second request on a separate stream!");

        connection.closeAndWait();
    }

    private void echo(String payload) throws IOException {
        QuicStream quicStream = connection.createStream(true);
        byte[] requestData = payload.getBytes(StandardCharsets.US_ASCII);
        quicStream.getOutputStream().write(requestData);
        quicStream.getOutputStream().close();

        System.out.print("Response from server: ");
        quicStream.getInputStream().transferTo(System.out);
        System.out.println();
    }
}
