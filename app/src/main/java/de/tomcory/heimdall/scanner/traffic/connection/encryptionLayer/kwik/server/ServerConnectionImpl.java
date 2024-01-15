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

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicStream;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.ack.GlobalAckGenerator;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.cid.ConnectionIdManager;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.core.*;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.crypto.CryptoStream;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.crypto.MissingKeysException;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.frame.HandshakeDoneFrame;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.frame.NewConnectionIdFrame;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.frame.NewTokenFrame;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.frame.QuicFrame;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.frame.RetireConnectionIdFrame;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.LogProxy;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.Logger;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.packet.*;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.send.SenderImpl;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.stream.FlowControl;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.stream.StreamManager;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.tls.QuicTransportParametersExtension;
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection;

import net.luminis.tls.NewSessionTicket;
import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.alert.MissingExtensionAlert;
import net.luminis.tls.alert.NoApplicationProtocolAlert;
import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.*;
import net.luminis.tls.util.ByteUtils;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import static de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicConstants.TransportErrorCode.INVALID_TOKEN;
import static de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR;
import static de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.core.QuicConnectionImpl.Status.Connected;


public class ServerConnectionImpl extends QuicConnectionImpl implements ServerConnection, TlsStatusEventHandler {

    private static final int TOKEN_SIZE = 37;
    private final Random random;
    private final SenderImpl sender;
    private final Version originalVersion;
    private final InetSocketAddress initialClientAddress;
    private final boolean retryRequired;
    private final GlobalAckGenerator ackGenerator;
    private final TlsServerEngine tlsEngine;
    private final ApplicationProtocolRegistry applicationProtocolRegistry;
    private final Consumer<ServerConnectionImpl> closeCallback;
    private final StreamManager streamManager;
    private final int initialMaxStreamData;
    private final int maxOpenStreamsUni;
    private final int maxOpenStreamsBidi;
    private final byte[] token;
    private final ConnectionIdManager connectionIdManager;
    private volatile String negotiatedApplicationProtocol;
    private int maxIdleTimeoutInSeconds;
    private volatile long bytesReceived;
    private volatile boolean addressValidated;
    private boolean acceptEarlyData = true;
    private boolean acceptedEarlyData = false;
    private int allowedClientConnectionIds = 3;
    private long initialMaxData;


    /**
     * Creates a server connection implementation.
     * @param originalVersion  quic version used for this connection
     * @param transportLayerConnection  the Transportlayer instance that is being used for sending packets
     * @param initialClientAddress  the initial client address (after handshake, clients can move to different address)
     * @param peerCid  the connection id of the client
     * @param originalDcid  the original destination connection id used by the client
     * @param connectionIdLength  length of the connection id's generated and used by this connection (used as its source)
     * @param tlsServerEngineFactory  factory for creating tls engine
     * @param retryRequired  whether or not a retry is required for address validation
     * @param applicationProtocolRegistry  the registry for application protocols this server supports
     * @param initialRtt  the initial rtt
     * @param connectionRegistry
     * @param closeCallback  callback for notifying interested parties this connection is closed
     * @param log  logger
     */
    protected ServerConnectionImpl(Version originalVersion, TransportLayerConnection transportLayerConnection, InetSocketAddress initialClientAddress,
                                   byte[] peerCid, byte[] originalDcid, int connectionIdLength, TlsServerEngineFactory tlsServerEngineFactory,
                                   boolean retryRequired, ApplicationProtocolRegistry applicationProtocolRegistry,
                                   Integer initialRtt, ServerConnectionRegistry connectionRegistry, Consumer<ServerConnectionImpl> closeCallback, Logger log) {
        super(originalVersion, Role.Server, null, new LogProxy(log, originalDcid));
        this.originalVersion = originalVersion;
        this.initialClientAddress = initialClientAddress;
        this.retryRequired = retryRequired;
        this.applicationProtocolRegistry = applicationProtocolRegistry;
        this.closeCallback = closeCallback;

        tlsEngine = tlsServerEngineFactory.createServerEngine(new TlsMessageSender(), this);
        tlsEngine.addSupportedCiphers(List.of(
                TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256,
                TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384,
                TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256
                // TlsConstants.CipherSuite.TLS_AES_128_CCM_SHA256 not yet support by Kwik
                // TlsConstants.CipherSuite.TLS_AES_128_CCM_8_SHA256 not used in QUIC!
        ));

        idleTimer = new IdleTimer(this, log);
        sender = new SenderImpl(quicVersion, getMaxPacketSize(), transportLayerConnection, initialClientAddress,this, initialRtt, this.log, true);
        if (! retryRequired) {
            sender.setAntiAmplificationLimit(0);
        }
        idleTimer.setPtoSupplier(sender::getPto);

        BiConsumer<Integer, String> closeWithErrorFunction = (error, reason) -> {
            immediateCloseWithError(EncryptionLevel.App, error, reason);
        };
        connectionIdManager = new ConnectionIdManager(peerCid, originalDcid, connectionIdLength, allowedClientConnectionIds, connectionRegistry, sender, closeWithErrorFunction, log);

        ackGenerator = sender.getGlobalAckGenerator();

        if (retryRequired) {
            random = new SecureRandom();
            token = new byte[TOKEN_SIZE];
            random.nextBytes(token);
        }
        else {
            random = null;
            token = null;
        }
        connectionSecrets.computeInitialKeys(originalDcid);
        sender.start(connectionSecrets);

        maxIdleTimeoutInSeconds = 30;
        initialMaxStreamData = 1_000_000;
        initialMaxData = 10 * initialMaxStreamData;
        maxOpenStreamsUni = 10;
        maxOpenStreamsBidi = 100;
        streamManager = new StreamManager(this, Role.Server, log, maxOpenStreamsUni, maxOpenStreamsBidi, initialMaxData);

        this.log.getQLog().emitConnectionCreatedEvent(Instant.now());
    }

    @Override
    public void abortConnection(Throwable error) {
        log.error(this.toString() + " aborted due to internal error", error);
        closeCallback.accept(this);
    }

    @Override
    protected SenderImpl getSender() {
        return sender;
    }

    @Override
    protected TlsEngine getTlsEngine() {
        return tlsEngine;
    }

    @Override
    protected GlobalAckGenerator getAckGenerator() {
        return ackGenerator;
    }

    @Override
    protected StreamManager getStreamManager() {
        return streamManager;
    }

    @Override
    protected ConnectionIdManager getConnectionIdManager() {
        return connectionIdManager;
    }

    @Override
    public long getInitialMaxStreamData() {
        return initialMaxStreamData;
    }

    @Override
    public int getMaxShortHeaderPacketOverhead() {
        return 1  // flag byte
                + connectionIdManager.getCurrentPeerConnectionId().length
                + 4  // max packet number size, in practice this will be mostly 1
                + 16; // encryption overhead
    }

    @Override
    protected int getSourceConnectionIdLength() {
        return connectionIdManager.getInitialConnectionId().length;
    }

    @Override
    protected void cryptoProcessingErrorOcurred(TlsProtocolException exception) {
    }

    public byte[] getInitialConnectionId() {
        return connectionIdManager.getInitialConnectionId();
    }

    @Override
    public byte[] getSourceConnectionId() {
        return connectionIdManager.getInitialConnectionId();
    }

    @Override
    public byte[] getDestinationConnectionId() {
        return connectionIdManager.getCurrentPeerConnectionId();
    }

    @Override
    public void earlySecretsKnown() {
        // https://www.rfc-editor.org/rfc/rfc9369.html#name-compatible-negotiation-requ
        // "Servers can accept 0-RTT and then process 0-RTT packets from the original version."
        connectionSecrets.computeEarlySecrets(tlsEngine, tlsEngine.getSelectedCipher(), originalVersion);
    }

    @Override
    public void handshakeSecretsKnown() {
        connectionSecrets.computeHandshakeSecrets(tlsEngine, tlsEngine.getSelectedCipher());
    }

    @Override
    public void handshakeFinished() {
        connectionSecrets.computeApplicationSecrets(tlsEngine);
        sender.enableAppLevel();
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-discarding-handshake-keys
        // "An endpoint MUST discard its handshake keys when the TLS handshake is confirmed"
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-handshake-confirmed
        // "In this document, the TLS handshake is considered confirmed at the server when the handshake completes."
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-handshake-complete
        // "In this document, the TLS handshake is considered complete when the TLS stack has reported that the handshake
        //  is complete. This happens when the TLS stack has both sent a Finished message and verified the peer's Finished message."
        sender.discard(PnSpace.Handshake, "tls handshake confirmed");
        connectionSecrets.discardKeys(EncryptionLevel.Handshake);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-4.9.2
        // "The server MUST send a HANDSHAKE_DONE frame as soon as it completes the handshake."
        sendHandshakeDone(new HandshakeDoneFrame(quicVersion.getVersion()));
        connectionState = Connected;

        synchronized (handshakeStateLock) {
            if (handshakeState.transitionAllowed(HandshakeState.Confirmed)) {
                handshakeState = HandshakeState.Confirmed;
                handshakeStateListeners.forEach(l -> l.handshakeStateChangedEvent(handshakeState));
            }
            else {
                log.debug("Handshake state cannot be set to Confirmed");
            }
        }

        if (!acceptedEarlyData) {
            applicationProtocolRegistry.startApplicationProtocolConnection(negotiatedApplicationProtocol, this);
        }
        connectionIdManager.handshakeFinished();
    }

    private void sendHandshakeDone(QuicFrame frame) {
        send(frame, this::sendHandshakeDone);
    }

    @Override
    public void newSessionTicketReceived(NewSessionTicket ticket) {
    }

    @Override
    public void extensionsReceived(List<Extension> extensions) throws TlsProtocolException {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-8.1
        // "Unless another mechanism is used for agreeing on an application protocol, endpoints MUST use ALPN for this purpose."
        Optional<Extension> alpnExtension = extensions.stream()
                .filter(ext -> ext instanceof ApplicationLayerProtocolNegotiationExtension)
                .findFirst();
        if (alpnExtension.isEmpty()) {
            throw new MissingExtensionAlert("missing application layer protocol negotiation extension");
        }
        else {
            // "When using ALPN, endpoints MUST immediately close a connection (...) if an application protocol is not negotiated."
            List<String> requestedProtocols = ((ApplicationLayerProtocolNegotiationExtension) alpnExtension.get()).getProtocols();
            Optional<String> applicationProtocol = applicationProtocolRegistry.selectSupportedApplicationProtocol(requestedProtocols);
            applicationProtocol
                    .map(protocol -> {
                        // Add negotiated protocol to TLS response (Encrypted Extensions message)
                        tlsEngine.addServerExtensions(new ApplicationLayerProtocolNegotiationExtension(protocol));
                        return protocol; })
                    .map(selectedProtocol -> negotiatedApplicationProtocol = selectedProtocol)
                    .orElseThrow(() -> new NoApplicationProtocolAlert(requestedProtocols));
        }

        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-8.2
        // "endpoints that receive ClientHello or EncryptedExtensions messages without the quic_transport_parameters extension
        //  MUST close the connection with an error of type 0x16d (equivalent to a fatal TLS missing_extension alert"
        Optional<Extension> tpExtension = extensions.stream()
                .filter(ext -> ext instanceof QuicTransportParametersExtension)
                .findFirst();
        if (tpExtension.isEmpty()) {
            throw new MissingExtensionAlert("missing quic transport parameters extension");
        }
        else {
            try {
                validateAndProcess(((QuicTransportParametersExtension) tpExtension.get()).getTransportParameters());
            } catch (TransportError transportParameterError) {
                throw new TlsProtocolException("transport parameter error", transportParameterError);
            }
        }

        TransportParameters serverTransportParams = initTransportParameters();

        // https://www.rfc-editor.org/rfc/rfc9369.html#name-version-negotiation-conside
        // "Any QUIC endpoint that supports QUIC version 2 MUST send, process, and validate the version_information
        //  transport parameter specified in [QUIC-VN] to prevent version downgrade attacks."
        serverTransportParams.setVersionInformation(new TransportParameters.VersionInformation(quicVersion.getVersion(), List.of(Version.QUIC_version_1, Version.QUIC_version_2)));
        serverTransportParams.setActiveConnectionIdLimit(allowedClientConnectionIds);
        serverTransportParams.setDisableMigration(true);
        serverTransportParams.setInitialSourceConnectionId(connectionIdManager.getInitialConnectionId());
        serverTransportParams.setOriginalDestinationConnectionId(connectionIdManager.getOriginalDestinationConnectionId());
        if (retryRequired) {
            serverTransportParams.setRetrySourceConnectionId(connectionIdManager.getInitialConnectionId());
        }
        tlsEngine.setSelectedApplicationLayerProtocol(negotiatedApplicationProtocol);
        tlsEngine.addServerExtensions(new QuicTransportParametersExtension(quicVersion.getVersion(), serverTransportParams, Role.Server));
        tlsEngine.setSessionData(quicVersion.getVersion().getBytes());
        tlsEngine.setSessionDataVerificationCallback(this::acceptSessionResumption);
    }

    TransportParameters initTransportParameters() {
        TransportParameters parameters = new TransportParameters();
        parameters.setMaxIdleTimeout(maxIdleTimeoutInSeconds * 1000);
        parameters.setInitialMaxStreamData(initialMaxStreamData);
        parameters.setInitialMaxData(initialMaxData);
        parameters.setInitialMaxStreamsBidi(maxOpenStreamsBidi);
        parameters.setInitialMaxStreamsUni(maxOpenStreamsUni);
        return parameters;
    }

    boolean acceptSessionResumption(ByteBuffer storedSessionData) {
        // https://www.rfc-editor.org/rfc/rfc9369.html#name-tls-resumption-and-new_toke
        // "Servers MUST validate the originating version of any session ticket or token and not accept one issued from
        //  a different version."
        if (quicVersion.getVersion().equals(Version.parse(storedSessionData.getInt()))) {
            return true;
        }
        else {
            log.warn("Resumed session denied because quic versions don't match");
            return false;
        }
    }
    @Override
    public boolean isEarlyDataAccepted() {
        if (acceptEarlyData) {
            // Remember that server connection actually accepted early data
            acceptedEarlyData = true;
            applicationProtocolRegistry.startApplicationProtocolConnection(negotiatedApplicationProtocol, this);

            log.info("Server accepted early data");
            return true;
        }
        else {
            return false;
        }
    }

    @Override
    protected QuicPacket parsePacket(ByteBuffer data) throws MissingKeysException, DecryptionException, InvalidPacketException {
        try {
            return super.parsePacket(data);
        }
        catch (DecryptionException decryptionException) {
            Version connectionVersion = quicVersion.getVersion();
            if (retryRequired
                    && LongHeaderPacket.isLongHeaderPacket(data.get(0), connectionVersion)
                    && InitialPacket.isInitial((data.get(0) & 0x30) >> 4, connectionVersion)) {
                // If retry packet has been sent, but lost, client will send another initial with keys based on odcid
                try {
                    data.rewind();
                    connectionSecrets.computeInitialKeys(connectionIdManager.getOriginalDestinationConnectionId());
                    return super.parsePacket(data);
                }
                finally {
                    connectionSecrets.computeInitialKeys(connectionIdManager.getInitialConnectionId());
                }
            }
            else {
                throw decryptionException;
            }
        }
    }

    @Override
    public void parseAndProcessPackets(int datagram, Instant timeReceived, ByteBuffer data, QuicPacket parsedPacket) {
        if (InitialPacket.isInitial(data) && data.limit() < 1200) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14.1
            // "A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller
            //  than the smallest allowed maximum datagram size of 1200 bytes."
            return;
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-8
        // "Therefore, after receiving packets from an address that is not yet validated, an endpoint MUST limit the
        //  amount of data it sends to the unvalidated address to three times the amount of data received from that address."
        // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-8.1
        // "For the purposes of avoiding amplification prior to address validation, servers MUST count all of the
        //  payload bytes received in datagrams that are uniquely attributed to a single connection. This includes
        //  datagrams that contain packets that are successfully processed and datagrams that contain packets that
        //  are all discarded."
        bytesReceived += data.remaining();
        if (! addressValidated) {
            sender.setAntiAmplificationLimit(3 * (int) bytesReceived);
        }

        super.parseAndProcessPackets(datagram, timeReceived, data, parsedPacket);
    }

    @Override
    protected boolean checkDestinationConnectionId(QuicPacket packet) {
        byte[] cid = packet.getDestinationConnectionId();
        if ((packet instanceof InitialPacket || packet instanceof ZeroRttPacket) && Arrays.equals(cid, getOriginalDestinationConnectionId())) {
            return true;
        }
        else {
            return super.checkDestinationConnectionId(packet);
        }
    }

    @Override
    public ProcessResult process(InitialPacket packet, Instant time) {
        assert(Arrays.equals(packet.getDestinationConnectionId(), connectionIdManager.getInitialConnectionId()) || Arrays.equals(packet.getDestinationConnectionId(), connectionIdManager.getOriginalDestinationConnectionId()));

        if (retryRequired) {
            if (packet.getToken() == null) {
                sendRetry();
                connectionSecrets.computeInitialKeys(connectionIdManager.getInitialConnectionId());
                return ProcessResult.Abort;  // No further packet processing (e.g. ack generation).
            }
            else if (!Arrays.equals(packet.getToken(), token)) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-33#section-8.1.2
                // "If a server receives a client Initial that can be unprotected but contains an invalid Retry token,
                // (...), the server SHOULD immediately close (Section 10.2) the connection with an INVALID_TOKEN error."
                immediateCloseWithError(EncryptionLevel.Initial, INVALID_TOKEN.value, null);
                return ProcessResult.Abort;
            }
            else {
                // Receiving a valid token implies address is validated.
                addressValidated = true;
                sender.unsetAntiAmplificationLimit();
                // Valid token, proceed as usual.
                processFrames(packet, time);
                return ProcessResult.Continue;
            }
        }
        else {
            processFrames(packet, time);
            return ProcessResult.Continue;
        }
    }

    private void sendRetry() {
        RetryPacket retry = new RetryPacket(quicVersion.getVersion(), connectionIdManager.getInitialConnectionId(), getDestinationConnectionId(), getOriginalDestinationConnectionId(), token);
        sender.send(retry);
    }

    @Override
    public ProcessResult process(ShortHeaderPacket packet, Instant time) {
        connectionIdManager.registerConnectionIdInUse(packet.getDestinationConnectionId());
        processFrames(packet, time);
        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(VersionNegotiationPacket packet, Instant time) {
        // Intentionally discarding packet without any action (clients should not send Version Negotiation packets).
        return ProcessResult.Abort;
    }

    @Override
    public ProcessResult process(HandshakePacket packet, Instant time) {
        if (! addressValidated) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-8.1
            // "In particular, receipt of a packet protected with Handshake keys confirms that the peer successfully processed
            //  an Initial packet. Once an endpoint has successfully processed a Handshake packet from the peer, it can consider
            //  the peer address to have been validated."
            addressValidated = true;
            sender.unsetAntiAmplificationLimit();
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.2.1
        // "A server stops sending and processing Initial packets when it receives its first Handshake packet. "
        sender.discard(PnSpace.Initial, "first handshake packet received");  // Only discards when not yet done.
        processFrames(packet, time);
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-discarding-initial-keys
        // "a server MUST discard Initial keys when it first successfully processes a Handshake packet"
        connectionSecrets.discardKeys(EncryptionLevel.Initial);

        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(RetryPacket packet, Instant time) {
        // Intentionally discarding packet without any action (clients should not send Retry packets).
        return ProcessResult.Abort;
    }

    @Override
    public ProcessResult process(ZeroRttPacket packet, Instant time) {
       if (acceptedEarlyData) {
            processFrames(packet, time);
        }
        else {
            log.warn("Ignoring 0-RTT packet because server connection does not accept early data.");
        }
        return ProcessResult.Continue;
    }

    @Override
    public void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived) {
    }

    @Override
    public void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        connectionIdManager.process(newConnectionIdFrame);
    }

    @Override
    public void process(NewTokenFrame newTokenFrame, QuicPacket packet, Instant timeReceived) {
    }

    @Override
    public void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        connectionIdManager.process(retireConnectionIdFrame, packet.getDestinationConnectionId());
    }

    @Override
    protected void terminate() {
        super.terminate(() -> {
            String statsSummary = getStats().toString().replace("\n", "    ");
            log.info(String.format("Stats for connection %s: %s", ByteUtils.bytesToHex(connectionIdManager.getInitialConnectionId()), statsSummary));
        });
        log.getQLog().emitConnectionTerminatedEvent();
        closeCallback.accept(this);
    }

    private void validateAndProcess(TransportParameters transportParameters) throws TransportError {
        TransportParameters.VersionInformation versionInformation = transportParameters.getVersionInformation();
        if (versionInformation != null) {
            Optional<Version> clientPreferred = versionInformation.getOtherVersions().stream()
                    // Filter out versions reserved to exercise version negotiation (0x?a?a?a?a) and unknown versions.
                    .filter(version -> version.isV1V2()).findFirst();
            if (!clientPreferred.equals(Optional.of(quicVersion.getVersion()))) {
                log.info(String.format("Switching from initial version %s to client's preferred version %s.", quicVersion, clientPreferred));
                versionNegotiationStatus = VersionNegotiationStatus.VersionChangeUnconfirmed;
                quicVersion.setVersion(clientPreferred.get());
                connectionSecrets.recomputeInitialKeys();
            }
        }
        if (transportParameters.getInitialMaxStreamsBidi() > 0x1000000000000000l) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (transportParameters.getMaxUdpPayloadSize() < 1200) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (transportParameters.getAckDelayExponent() > 20) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (transportParameters.getMaxAckDelay() > 16384) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (transportParameters.getActiveConnectionIdLimit() < 2) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (!connectionIdManager.validateInitialPeerConnectionId(transportParameters.getInitialSourceConnectionId())) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-7.3
            // "An endpoint MUST treat absence of the initial_source_connection_id transport parameter from either
            //  endpoint (...) as a connection error of type TRANSPORT_PARAMETER_ERROR."
            // "An endpoint MUST treat the following as a connection error of type TRANSPORT_PARAMETER_ERROR or
            //  PROTOCOL_VIOLATION: a mismatch between values received from a peer in these transport parameters and the
            //  value sent in the corresponding Destination or Source Connection ID fields of Initial packets."
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
        // "A client MUST NOT include any server-only transport parameter: original_destination_connection_id,
        //  preferred_address, retry_source_connection_id, or stateless_reset_token. A server MUST treat receipt of any
        //  of these transport parameters as a connection error of type TRANSPORT_PARAMETER_ERROR."
        if (transportParameters.getOriginalDestinationConnectionId() != null || transportParameters.getPreferredAddress() != null
                || transportParameters.getRetrySourceConnectionId() != null || transportParameters.getStatelessResetToken() != null) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }

        determineIdleTimeout(maxIdleTimeoutInSeconds * 1000, transportParameters.getMaxIdleTimeout());

        connectionIdManager.registerPeerCidLimit(transportParameters.getActiveConnectionIdLimit());

        flowController = new FlowControl(Role.Server, transportParameters.getInitialMaxData(),
                transportParameters.getInitialMaxStreamDataBidiLocal(), transportParameters.getInitialMaxStreamDataBidiRemote(),
                transportParameters.getInitialMaxStreamDataUni(), log);
        streamManager.setFlowController(flowController);

        streamManager.setInitialMaxStreamsBidi(transportParameters.getInitialMaxStreamsBidi());
        streamManager.setInitialMaxStreamsUni(transportParameters.getInitialMaxStreamsUni());

        peerAckDelayExponent = transportParameters.getAckDelayExponent();

        sender.setReceiverMaxAckDelay(transportParameters.getMaxAckDelay());

        sender.registerMaxUdpPayloadSize(transportParameters.getMaxUdpPayloadSize());
    }

    @Override
    public InetAddress getInitialClientAddress() {
        return initialClientAddress.getAddress();
    }

    private class TlsMessageSender implements ServerMessageSender {
        @Override
        public void send(ServerHello sh) {
            CryptoStream cryptoStream = getCryptoStream(EncryptionLevel.Initial);
            cryptoStream.write(sh, false);
            log.sentPacketInfo(cryptoStream.toStringSent());
        }

        @Override
        public void send(EncryptedExtensions ee) {
            getCryptoStream(EncryptionLevel.Handshake).write(ee, false);
        }

        @Override
        public void send(CertificateMessage cm) throws IOException {
            getCryptoStream(EncryptionLevel.Handshake).write(cm, false);
        }

        @Override
        public void send(CertificateVerifyMessage cv) throws IOException {
            getCryptoStream(EncryptionLevel.Handshake).write(cv, false);
        }

        @Override
        public void send(FinishedMessage finished) throws IOException {
            CryptoStream cryptoStream = getCryptoStream(EncryptionLevel.Handshake);
            cryptoStream.write(finished, false);
            log.sentPacketInfo(cryptoStream.toStringSent());
        }

        @Override
        public void send(NewSessionTicketMessage newSessionTicket) throws IOException {
            CryptoStream cryptoStream = getCryptoStream(EncryptionLevel.App);
            cryptoStream.write(newSessionTicket, true);
        }
    }

    public boolean isClosed() {
        return connectionState == Status.Closed;
    }

    public byte[] getOriginalDestinationConnectionId() {
        return connectionIdManager.getOriginalDestinationConnectionId();
    }

    public List<byte[]> getActiveConnectionIds() {
        return connectionIdManager.getActiveConnectionIds();
    }

    @Override
    public void setMaxAllowedBidirectionalStreams(int max) {
    }

    @Override
    public void setMaxAllowedUnidirectionalStreams(int max) {
    }

    @Override
    public void setDefaultStreamReceiveBufferSize(long size) {
    }

    @Override
    public void setPeerInitiatedStreamCallback(Consumer<QuicStream> streamConsumer) {
        streamManager.setPeerInitiatedStreamCallback(streamConsumer);
    }

    @Override
    public String toString() {
        return "ServerConnection[" + ByteUtils.bytesToHex(connectionIdManager.getOriginalDestinationConnectionId()) + "]";
    }
}
