/*
 * Copyright © 2020, 2021, 2022, 2023 Peter Doornbosch
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
package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.core.Version;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.Logger;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.packet.InitialPacket;
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection;

import net.luminis.tls.handshake.TlsServerEngineFactory;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.function.Consumer;


public class ServerConnectionFactory {

    private final int connectionIdLength;
    private final Logger log;
    private final TlsServerEngineFactory tlsServerEngineFactory;
    private final ApplicationProtocolRegistry applicationProtocolRegistry;
    private final TransportLayerConnection transportLayerConnection;
    private final int initalRtt;
    private final Consumer<ServerConnectionImpl> closeCallback;
    private final boolean requireRetry;
    private final ServerConnectionRegistry connectionRegistry;

    public ServerConnectionFactory(int connectionIdLength, TransportLayerConnection transportLayerConnection, TlsServerEngineFactory tlsServerEngineFactory,
                                   boolean requireRetry, ApplicationProtocolRegistry applicationProtocolRegistry, int initalRtt,
                                   ServerConnectionRegistry connectionRegistry, Consumer<ServerConnectionImpl> closeCallback, Logger log)
    {
        if (connectionIdLength > 20 || connectionIdLength < 0) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // "In QUIC version 1, this value MUST NOT exceed 20 bytes"
            throw new IllegalArgumentException();
        }
        this.tlsServerEngineFactory = tlsServerEngineFactory;
        this.requireRetry = requireRetry;
        this.applicationProtocolRegistry = applicationProtocolRegistry;
        this.connectionIdLength = connectionIdLength;
        this.connectionRegistry = connectionRegistry;
        this.closeCallback = closeCallback;
        this.log = log;
        this.transportLayerConnection = transportLayerConnection;
        this.initalRtt = initalRtt;
    }

    /**
     * Creates new server connection.
     * @param version  quic version used
     * @param clientAddress  the address of the client
     * @param scid  the source connection id used by the client
     * @param originalDcid  the original destination id used by the client
     * @return
     */
    public ServerConnectionImpl createNewConnection(Version version, InetSocketAddress clientAddress, byte[] scid, byte[] originalDcid) {
        return new ServerConnectionImpl(version, transportLayerConnection, clientAddress, scid, originalDcid, connectionIdLength,
                tlsServerEngineFactory, requireRetry, applicationProtocolRegistry, initalRtt, connectionRegistry, closeCallback, log);
    }

    public ServerConnectionProxy createServerConnectionProxy(ServerConnectionImpl connection, InitialPacket initialPacket, Instant packetReceived, ByteBuffer datagram) {
        return new ServerConnectionThread(connection, initialPacket, packetReceived, datagram);
    }
}
