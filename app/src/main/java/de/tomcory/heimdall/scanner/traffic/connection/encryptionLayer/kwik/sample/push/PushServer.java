/*
 * Copyright © 2023 Peter Doornbosch
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
package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.sample.push;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicConnection;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicStream;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.Logger;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.SysOutLogger;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.core.Version;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server.ApplicationProtocolConnection;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server.ApplicationProtocolConnectionFactory;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server.ServerConnector;

import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;


/**
 * Sample demo server that implements a simple push protocol: when a client connects, the server opens a stream and sends
 * push messages.
 *
 *  The server's main method requires three arguments:
 * - certificate file (can be self-signed)
 * - key file with the private key of the certificate
 * - port number
 *
 * Set environment variable QLOGDIR to let the server create qlog files.
 */
public class PushServer {

    private static void usageAndExit() {
        System.err.println("Usage: cert file, cert key file, port number");
        System.exit(1);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3 || !Arrays.stream(args).limit(2).allMatch(a -> new File(a).exists())) {
            usageAndExit();
        }

        int port = -1;
        try {
            port = Integer.valueOf(args[2]);
        } catch (NumberFormatException noNumber) {
            usageAndExit();
        }

        Logger log = new SysOutLogger();
        log.timeFormat(Logger.TimeFormat.Long);
        log.logWarning(true);
        log.logInfo(true);

        ServerConnector serverConnector = new ServerConnector(port,
                new FileInputStream(args[0]), new FileInputStream(args[1]),
                List.of(Version.QUIC_version_1), false, log);

        registerProtocolHandler(serverConnector, log);

        serverConnector.start();

        log.info("Started (msg) push server on port " + port);
    }

    private static void registerProtocolHandler(ServerConnector serverConnector, Logger log) {
           serverConnector.registerApplicationProtocol("push", new ApplicationProtocolConnectionFactory() {

               @Override
               public ApplicationProtocolConnection createConnection(String protocol, QuicConnection quicConnection) {
                   return new PushProtocolConnection(quicConnection, log);
               }
           });
    }

    static class PushProtocolConnection implements ApplicationProtocolConnection {

        private Logger log;

        public PushProtocolConnection(QuicConnection quicConnection, Logger log) {
            this.log = log;
            System.out.println("New \"push protocol\" connection; will create (server initiated) stream to push messages to client.");
            QuicStream quicStream = quicConnection.createStream(false);
            new Thread(() -> generatePushMessages(quicStream), "pusher").start();
        }

        private void generatePushMessages(QuicStream quicStream) {
            OutputStream outputStream = quicStream.getOutputStream();
            try {
                while (true) {
                    String currentDateTime = Instant.now().toString();
                    System.out.println("Pushing message " + currentDateTime);
                    outputStream.write(currentDateTime.getBytes(StandardCharsets.US_ASCII));
                    outputStream.write("\n".getBytes(StandardCharsets.US_ASCII));
                    Thread.sleep(1000);
                }
            }
            catch (Exception e) {
                System.out.println("Pushing messages terminated with exception " + e);
            }
        }
    }
}
