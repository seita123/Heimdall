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
package de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.server;

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Collectors;

import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.QuicConnection;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.agent15.handshake.TlsServerEngineFactory;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.agent15.util.ByteUtils;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.EncryptionLevel;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.Version;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.log.Logger;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.packet.InitialPacket;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.packet.VersionNegotiationPacket;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.receive.RawPacket;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.receive.Receiver;
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection;

/**
 * Listens for QUIC connections on a given port. Requires server certificate and corresponding private key.
 */
public class ServerConnector {

    private static final int MINIMUM_LONG_HEADER_LENGTH = 1 + 4 + 1 + 0 + 1 + 0;
    private static final int CONNECTION_ID_LENGTH = 4;

    public final Receiver receiver;
    private final Logger log;
    private final List<Version> supportedVersions;
    private final List<Integer> supportedVersionIds;
    private final boolean requireRetry;
    private Integer initalRtt = 100;
    private TlsServerEngineFactory tlsEngineFactory;
    private final ServerConnectionFactory serverConnectionFactory;
    private ApplicationProtocolRegistry applicationProtocolRegistry;
    private final ExecutorService sharedExecutor = Executors.newSingleThreadExecutor();
    private final ScheduledExecutorService sharedScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
    private Context context;
    private ServerConnectionRegistryImpl connectionRegistry;
    private TransportLayerConnection transportLayerConnection;

    private ServerConnectionImpl serverConnection;
    private QuicConnection heimdallQuicConnection;


    public ServerConnector(TransportLayerConnection transportLayerConnection, List<X509Certificate> certificateFile, PrivateKey certificateKeyFile, List<Version> supportedVersions, boolean requireRetry, Logger log, QuicConnection heimdallQuicConnection) throws Exception {
        this.supportedVersions = supportedVersions;
        this.requireRetry = requireRetry;
        this.log = Objects.requireNonNull(log);
        this.transportLayerConnection = transportLayerConnection;
        this.heimdallQuicConnection = heimdallQuicConnection;

//        String key = new String(InputStreamCompat.readAllBytes(certificateKeyFile), Charset.defaultCharset());
//        key = key.trim();
//        InputStream keyStream = new ByteArrayInputStream(key.getBytes(StandardCharsets.UTF_8));
        tlsEngineFactory = new TlsServerEngineFactory(certificateFile, certificateKeyFile);
        applicationProtocolRegistry = new ApplicationProtocolRegistry();
        connectionRegistry = new ServerConnectionRegistryImpl(log);
        serverConnectionFactory = new ServerConnectionFactory(CONNECTION_ID_LENGTH, this.transportLayerConnection, tlsEngineFactory,
                this.requireRetry, applicationProtocolRegistry, initalRtt, connectionRegistry, connectionRegistry::removeConnection, log);

        supportedVersionIds = supportedVersions.stream().map(version -> version.getId()).collect(Collectors.toList());
        receiver = new Receiver(log, exception -> System.exit(9));
        context = new ServerConnectorContext();
    }

    public void registerApplicationProtocol(String protocol, ApplicationProtocolConnectionFactory protocolConnectionFactory) {
        applicationProtocolRegistry.registerApplicationProtocol(protocol, protocolConnectionFactory);
    }

    public Set<String> getRegisteredApplicationProtocols() {
        return applicationProtocolRegistry.getRegisteredApplicationProtocols();
    }

    public void start() {
//        receiver.start();

        new Thread(this::receiveLoop, "server receive loop").start();
    }

    protected void receiveLoop() {
        while (true) {
            try {
                RawPacket rawPacket = receiver.get((int) Duration.ofDays(10 * 365).getSeconds());
                process(rawPacket);
            }
            catch (InterruptedException e) {
                log.error("receiver interrupted (ignoring)");
                break;
            }
            catch (Exception runtimeError) {
                log.error("Uncaught exception in server receive loop", runtimeError);
            }
        }
    }

    public void process(RawPacket rawPacket) {
        ByteBuffer data = rawPacket.getData();
        int flags = data.get();
        data.rewind();
        if ((flags & 0b1100_0000) == 0b1100_0000) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // "Header Form:  The most significant bit (0x80) of byte 0 (the first byte) is set to 1 for long headers."
            processLongHeaderPacket(new InetSocketAddress(rawPacket.getAddress(), rawPacket.getPort()), data);
        } else if ((flags & 0b1100_0000) == 0b0100_0000) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.3
            // "Header Form:  The most significant bit (0x80) of byte 0 is set to 0 for the short header.
           processShortHeaderPacket(new InetSocketAddress(rawPacket.getAddress(), rawPacket.getPort()), data);
        } else {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.3
            // "The next bit (0x40) of byte 0 is set to 1. Packets containing a zero value for this bit are not valid
            //  packets in this version and MUST be discarded."
            log.warn(String.format("Invalid Quic packet (flags: %02x) is discarded", flags));
        }
    }

    private void processLongHeaderPacket(InetSocketAddress clientAddress, ByteBuffer data) {
        if (data.remaining() >= MINIMUM_LONG_HEADER_LENGTH) {
            data.position(1);
            int version = data.getInt();

            data.position(5);
            int dcidLength = data.get() & 0xff;
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // "In QUIC version 1, this value MUST NOT exceed 20. Endpoints that receive a version 1 long header with a
            //  value larger than 20 MUST drop the packet. In order to properly form a Version Negotiation packet,
            //  servers SHOULD be able to read longer connection IDs from other QUIC versions."
            if (dcidLength > 20) {
                if (initialWithUnspportedVersion(data, version)) {
                    // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-6
                    // "A server sends a Version Negotiation packet in response to each packet that might initiate a new connection;"
                    sendVersionNegotiationPacket(clientAddress, data, dcidLength);
                }
                return;
            }
            if (data.remaining() >= dcidLength + 1) {  // after dcid at least one byte scid length
                byte[] dcid = new byte[dcidLength];
                data.get(dcid);
                int scidLength = data.get() & 0xff;
                if (data.remaining() >= scidLength) {
                    byte[] scid = new byte[scidLength];
                    data.get(scid);
                    data.rewind();

                    Optional<ServerConnectionProxy> connection = connectionRegistry.isExistingConnection(clientAddress, dcid);
                    if (!connection.isPresent()) {
                        synchronized (this) {
                            if (mightStartNewConnection(data, version, dcid) && !connectionRegistry.isExistingConnection(clientAddress, dcid).isPresent()) {
                                connection = Optional.of(createNewConnection(version, clientAddress, scid, dcid));
                            } else if (initialWithUnspportedVersion(data, version)) {
                                log.received(Instant.now(), 0, EncryptionLevel.Initial, dcid, scid);
                                // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-6
                                // "A server sends a Version Negotiation packet in response to each packet that might initiate a new connection;"
                                sendVersionNegotiationPacket(clientAddress, data, dcidLength);
                            }
                        }
                    }
                    connection.ifPresent(c -> c.parsePackets(0, Instant.now(), data, clientAddress));
                }
            }
        }
    }

    private void processShortHeaderPacket(InetSocketAddress clientAddress, ByteBuffer data) {
        byte[] dcid = new byte[CONNECTION_ID_LENGTH];
        data.position(1);
        data.get(dcid);
        data.rewind();
        Optional<ServerConnectionProxy> connection = connectionRegistry.isExistingConnection(clientAddress, dcid);
//        connection.ifPresentOrElse(c -> c.parsePackets(0, Instant.now(), data, clientAddress),
//                () -> log.warn("Discarding short header packet addressing non existent connection " + ByteUtils.bytesToHex(dcid)));

        if (connection.isPresent()){
            connection.get().parsePackets(0, Instant.now(), data, clientAddress);
        } else {
            log.warn("Discarding short header packet addressing non existent connection " + ByteUtils.bytesToHex(dcid));
        }
    }

    private boolean mightStartNewConnection(ByteBuffer packetBytes, int version, byte[] dcid) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-7.2
        // "This Destination Connection ID MUST be at least 8 bytes in length."
        if (dcid.length >= 8) {
            return supportedVersionIds.contains(version);
        } else {
            return false;
        }
    }

    private boolean initialWithUnspportedVersion(ByteBuffer packetBytes, int version) {
        packetBytes.rewind();
        int type = (packetBytes.get() & 0x30) >> 4;
        if (InitialPacket.isInitial(type, Version.parse(version))) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-14.1
            // "A server MUST discard an Initial packet that is carried in a UDP
            //   datagram with a payload that is smaller than the smallest allowed
            //   maximum datagram size of 1200 bytes. "
            if (packetBytes.limit() >= 1200) {
                return !supportedVersionIds.contains(version);
            }
        }
        return false;
    }

    private ServerConnectionProxy createNewConnection(int versionValue, InetSocketAddress clientAddress, byte[] scid, byte[] originalDcid) {
        Version version = Version.parse(versionValue);
        ServerConnectionProxy connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, originalDcid,
                serverConnectionFactory, connectionRegistry, log, heimdallQuicConnection);
        ServerConnectionCandidate serverConnectionCandidate = (ServerConnectionCandidate) connectionCandidate;
        serverConnection = serverConnectionCandidate.serverConnection;
        // Register new connection now with the original connection id, as retransmitted initial packets with the
        // same original dcid might be received (for example when the server response does not reach the client).
        // Such packets must _not_ lead to new connection candidate. Moreover, if it is an initial packet, it must be
        // passed to the connection, because (if valid) it will change the anti-amplification limit.
        connectionRegistry.registerConnection(new InitialPacketFilterProxy(connectionCandidate, version, log), originalDcid);

        return connectionCandidate;
    }

    private void sendVersionNegotiationPacket(InetSocketAddress clientAddress, ByteBuffer data, int dcidLength) {
        data.rewind();
        if (data.remaining() >= 1 + 4 + 1 + dcidLength + 1) {
            byte[] dcid = new byte[dcidLength];
            data.position(1 + 4 + 1);
            data.get(dcid);
            int scidLength = data.get() & 0xff;
            byte[] scid = new byte[scidLength];
            if (scidLength > 0) {
                data.get(scid);
            }
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.1
            // "The server MUST include the value from the Source Connection ID field of the packet it receives in the
            //  Destination Connection ID field. The value for Source Connection ID MUST be copied from the Destination
            //  Connection ID of the received packet, ..."
            VersionNegotiationPacket versionNegotiationPacket = new VersionNegotiationPacket(supportedVersions, dcid, scid);
            byte[] packetBytes = versionNegotiationPacket.generatePacketBytes(null);
            DatagramPacket datagram = new DatagramPacket(packetBytes, packetBytes.length, clientAddress.getAddress(), clientAddress.getPort());
            //                serverSocket.send(datagram);
            transportLayerConnection.wrapInbound(packetBytes); // Todo: check if this is really inbound
            log.sent(Instant.now(), versionNegotiationPacket);
        }
    }

    public ServerConnectionImpl getConnection(){
        return serverConnection;
    }

    private class ServerConnectorContext implements Context {

        @Override
        public ExecutorService getSharedServerExecutor() {
            return sharedExecutor;
        }

        @Override
        public ScheduledExecutorService getSharedScheduledExecutor() {
            return sharedScheduledExecutor;
        }
    }
}
