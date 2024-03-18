/*
 * Copyright © 2021, 2022, 2023 Peter Doornbosch
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
package de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.server;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.agent15.util.ByteUtils;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.*;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.crypto.Aead;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.crypto.ConnectionSecrets;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.crypto.MissingKeysException;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.log.Logger;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.log.NullLogger;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.packet.InitialPacket;

/**
 * A server connection candidate: whether an initial packet causes a new server connection to be created cannot be
 * decided until the initial packet has been successfully parsed and decrypted (to avoid that corrupt packets change
 * server state).
 */
public class ServerConnectionCandidate implements ServerConnectionProxy {

    private final Version quicVersion;
    private final InetSocketAddress clientAddress;
    private final byte[] dcid;
    private final ServerConnectionFactory serverConnectionFactory;
    private final ServerConnectionRegistry connectionRegistry;
    private final Logger log;
    private volatile ServerConnectionProxy registeredConnection;
    private final ExecutorService executor;
    private final ScheduledExecutorService scheduledExecutor;


    public ServerConnectionCandidate(Context context, Version version, InetSocketAddress clientAddress, byte[] scid, byte[] dcid,
                                     ServerConnectionFactory serverConnectionFactory, ServerConnectionRegistry connectionRegistry, Logger log) {
        this.executor = context.getSharedServerExecutor();
        this.scheduledExecutor = context.getSharedScheduledExecutor();
        this.quicVersion = version;
        this.clientAddress = clientAddress;
        this.dcid = dcid;
        this.serverConnectionFactory = serverConnectionFactory;
        this.connectionRegistry = connectionRegistry;
        this.log = log;
    }

    @Override
    public byte[] getOriginalDestinationConnectionId() {
        return dcid;
    }

    @Override
    public void parsePackets(int datagramNumber, Instant timeReceived, ByteBuffer data, InetSocketAddress sourceAddress) {
        // Execute packet parsing on separate thread, to make this method return a.s.a.p.
        executor.submit(() -> {
            // Serialize processing (per connection candidate): duplicate initial packets might arrive faster than they are processed.
            synchronized (this) {
                // Because of possible queueing in the executor, a connection might already exist (i.e. when multiple
                // packets queued before the connection was registered).
                if (registeredConnection != null) {
                    registeredConnection.parsePackets(datagramNumber, timeReceived, data, sourceAddress);
                    return;
                }

                try {
                    InitialPacket initialPacket = parseInitialPacket(datagramNumber, timeReceived, data);

                    log.received(timeReceived, datagramNumber, initialPacket);
                    log.debug("Parsed packet with size " + data.position() + "; " + data.remaining() + " bytes left.");

                    // Packet is valid. This is the moment to create a real server connection and continue processing.
                    if (registeredConnection == null) {
                        data.rewind();
                        createAndRegisterServerConnection(initialPacket, timeReceived, data);
                    }
                }
                catch (InvalidPacketException | DecryptionException cannotParsePacket) {
                    // Drop packet without any action (i.e. do not send anything; do not change state; avoid unnecessary processing)
                    log.debug("Dropped invalid initial packet (no connection created)");
                    // But still the (now useless) candidate should be removed from the connection registry.
                    // To avoid race conditions with incoming duplicated first packets (possibly leading to scheduling
                    // a task for this candidate while it is not registered anymore), the removal of the candidate is
                    // delayed until connection setup is over.
                    // The delay should be longer then the maximum connection timeout clients (are likely to) use.
                    // It can be fairly large because the removal is only needed to avoid unused connection candidates pile up.
                    scheduledExecutor.schedule(() -> {
                                // But only if no connection is created in the meantime (which will do the cleanup)
                                if (registeredConnection == null) {
                                    connectionRegistry.deregisterConnection(this, dcid);
                                }
                            },
                            30, TimeUnit.SECONDS);
                }
                catch (Exception error) {
                    log.error("error while parsing or processing initial packet", error);
                }
            }
        });
    }

    private void createAndRegisterServerConnection(InitialPacket initialPacket, Instant timeReceived, ByteBuffer data) {
        Version quicVersion = initialPacket.getVersion();
        byte[] originalDcid = initialPacket.getDestinationConnectionId();
        ServerConnectionImpl connection = serverConnectionFactory.createNewConnection(quicVersion, clientAddress, initialPacket.getSourceConnectionId(), originalDcid);
        log.info("Creating new connection with version " + quicVersion + " for odcid " + ByteUtils.bytesToHex(originalDcid)
                + " with " + clientAddress.getAddress().getHostAddress() + ": " + ByteUtils.bytesToHex(connection.getInitialConnectionId()));

        // Pass the initial packet for processing, so it is processed on the server thread (enabling thread confinement concurrency strategy)
        registeredConnection = serverConnectionFactory.createServerConnectionProxy(connection, initialPacket, timeReceived, data);

        // Add filter to check client address.
        ClientAddressFilter wrappedConnection = new ClientAddressFilter(registeredConnection, clientAddress, log);
        // Register new connection with the new connection id (the one generated by the server)
        connectionRegistry.registerConnection(wrappedConnection, connection.getInitialConnectionId());
    }

    @Override
    public boolean isClosed() {
        return false;
    }

    @Override
    public void terminate() {
    }

    InitialPacket parseInitialPacket(int datagramNumber, Instant timeReceived, ByteBuffer data) throws InvalidPacketException, DecryptionException {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14.1
        // "A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller than
        //  the smallest allowedmaximum datagram size of 1200 bytes."
        if (data.limit() < 1200) {
            throw new InvalidPacketException("Initial packets is carried in a datagram that is smaller than 1200 (" + data.limit() + ")");
        }
        // Note that the caller already has extracted connection id's from the raw data, so checking for minimal length is not necessary here.
        int flags = data.get();
        data.rewind();

        if ((flags & 0x40) != 0x40) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-17.2
            // "Fixed Bit:  The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet.
            //  Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded."
            throw new InvalidPacketException();
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-17.2
        // "The most significant bit (0x80) of byte 0 (the first byte) is set to 1 for long headers."
        // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-17.2.2
        // "An Initial packet uses long headers with a type value of 0x0."
        if (InitialPacket.isInitial((flags & 0x30) >> 4, quicVersion)) {
            InitialPacket packet = new InitialPacket(quicVersion);
            ConnectionSecrets connectionSecrets = new ConnectionSecrets(new VersionHolder(quicVersion), Role.Server, null, new NullLogger());
            byte[] originalDcid = dcid;
            connectionSecrets.computeInitialKeys(originalDcid);
            try {
                Aead aead = connectionSecrets.getPeerAead(packet.getEncryptionLevel());
                packet.parse(data, aead, 0, new NullLogger(), 0);
                return packet;
            } catch (MissingKeysException e) {
                // Impossible, as initial keys have just been computed.
                throw new RuntimeException(e);
            }
        }
        throw new InvalidPacketException();
    }

    @Override
    public String toString() {
        return "ServerConnectionCandidate[" + ByteUtils.bytesToHex(dcid) + "]";
    }
}
