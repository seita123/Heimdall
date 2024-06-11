package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.appLayer.AppLayerConnection
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.agent15.env.PlatformMapping
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.QuicClientConnection
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.QuicStream
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.EncryptionLevel
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.Version
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.AckFrame
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.ConnectionCloseFrame
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.CryptoFrame
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.HandshakeDoneFrame
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.QuicFrame
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.StreamFrame
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.StreamType
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.log.Logger
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.log.SysOutLogger
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.server.ApplicationProtocolConnection
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.server.ApplicationProtocolConnectionFactory
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.server.ServerConnectionImpl
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.server.ServerConnector
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetAddress
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.util.Base64
import kotlin.time.Duration
import kotlin.time.TimeSource.Monotonic
import kotlin.time.TimeSource.Monotonic.markNow


class QuicConnection(
    id: Int,
    transportLayer: TransportLayerConnection,
    componentManager: ComponentManager
) : EncryptionLayerConnection(
    id,
    transportLayer,
    componentManager
) {

    init {
        if(id > 0) {
            Timber.d("quic$id Creating QUIC connection to ${transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${transportLayer.remotePort} (${transportLayer.remoteHost})")
        }
    }

    override val protocol = "QUIC"

    private var connectionState: ConnectionState = ConnectionState.NEW

    private var hostname: String = transportLayer.remoteHost ?: transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: ""

    private var serverFacingQuicConnection: QuicClientConnection? = null
    private var clientFacingQuicConnection: ServerConnectionImpl? = null
    private var serverConnector: ServerConnector? = null

    private var serverCertificate: X509Certificate? = null

    private var originalClientHello: ByteArray? = null

    private var isFirstPacket: Boolean = true

    private var mark: Monotonic.ValueTimeMark? = null
    private var timestamps: MutableList<Duration>? = mutableListOf()
    private var isFirstConnectionCloseFrame = true
    private var isFirstStreamFrameForwarded = true

    private var savedFrames: MutableList<QuicFrame> = mutableListOf()

    private val appLayerConnections = mutableMapOf<Int, AppLayerConnection>()

    private var isFirstServerResponse: Boolean = true
    private var savedServerResponse: ByteArray? = null

    private var isV1 = true

    ////////////////////////////////////////////////////////////////////////
    ///// Inherited methods ///////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    override fun unwrapOutbound(payload: ByteArray) { // Not in use at the moment

        //TODO: implement
    }

    override fun unwrapOutbound(packet: Packet) { // This one is being used
        if (isFirstPacket){
            mark = markNow()
            isFirstPacket = false
            println("quic$id Elapsed time - Step 0 - First Outbound Packet received")
        }
        val recordType = parseRecordType(packet.rawData)

        // The client starts sending application data, therefore the handshake has been completed
        if (recordType == RecordType.APP && connectionState == ConnectionState.CLIENT_HANDSHAKE){
            connectionState = ConnectionState.CLIENT_ESTABLISHED
            val elapsed_step2 = mark?.elapsedNow()
            timestamps?.add(elapsed_step2!!)
            Timber.d("quic$id Server facing Quic connection established")
            println("quic$id Elapsed time - Step 2 - Kwik server established: $elapsed_step2")
        }

        if (!isV1){
            passOutboundToAppLayer(packet)
        } else {
            when (connectionState) {
                ConnectionState.NEW -> initiateKwikSetup(packet.rawData, recordType)
                ConnectionState.CLIENT_HANDSHAKE, ConnectionState.CLIENT_ESTABLISHED -> serverConnector?.receiver?.receive(
                    packet.rawData,
                    transportLayer.ipPacketBuilder.localAddress.hostAddress,
                    transportLayer.localPort
                )

                else -> {
                    println("Unexpected Message from client while in connection state $connectionState")
                }
            }
        }
    }

    override fun unwrapInbound(payload: ByteArray) {

        if (isFirstServerResponse){
            savedServerResponse = payload
            isFirstServerResponse = false
        }

        if (!isV1){
            passInboundToAppLayer(payload)
        } else {
            serverFacingQuicConnection?.receiver?.receive(
                payload,
                hostname,
                transportLayer.remotePort
            )
        }
    }

    override fun wrapOutbound(payload: ByteArray) {
        transportLayer.wrapOutbound(payload)
    }

    override fun wrapInbound(payload: ByteArray) {
        transportLayer.wrapInbound(payload)
    }

    ////////////////////////////////////////////////////////////////////////
    ///// Traffic handler methods /////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Wraps and processes the outbound QUIC frames to be sent by the kwik client.
     *
     * @param framesToSend The list of QUIC frames that were received.
     * @param isShortHeader A boolean indicating whether the received packet has a short header (Applevel packet).
     *
     * This function processes each frame in the given list of frames. If the frame is not of type
     * HandshakeDoneFrame, AckFrame, or CryptoFrame, it forwards the frame using the `serverFacingQuicConnection`.
     * Additionally, if the frame is a `StreamFrame` of type ClientInitiatedBidirectional, it is
     * passed to the application layer. The function also tracks and prints the elapsed time when
     * the first ClientInitiatedBidirectional stream frame is forwarded.
     */
    fun wrapOutbound(framesToSend: List<QuicFrame>, isShortHeader: Boolean){ // frames the kwik server received, now being forwarded by the kwik client
        for (frame: QuicFrame in framesToSend){
            if (isShortHeader) {
                if (frame !is HandshakeDoneFrame && frame !is AckFrame && frame !is CryptoFrame) {
                    serverFacingQuicConnection?.sender?.send(frame, EncryptionLevel.App, null)

                    // mark when the first CIB stream frame from the client is received and forwarded
                    if (frame is StreamFrame) {
                        // cast to Streamframe and then check if its CIB
                        val streamFrame: StreamFrame = frame
                        if (streamFrame.streamType == StreamType.ClientInitiatedBidirectional){
                            passOutboundToAppLayer(streamFrame)

                            // mark when the first CIB frame is received
                            if (isFirstStreamFrameForwarded) {
                                val elapsed_step3 = mark?.elapsedNow()
                                timestamps?.add(elapsed_step3!!)
                                println("quic$id Elapsed time - Step 3 - First CIB-StreamFrame forwarded to the Server: $elapsed_step3")
                                isFirstStreamFrameForwarded = false
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Wraps and processes the inbound QUIC frames to be sent by the kwik server.
     *
     * @param framesToSend The list of QUIC frames to be sent.
     * @param isShortHeader A boolean indicating whether the received packet has a short header (Applevel packet).
     *
     * This function processes each frame in the given list of frames. If the frame is not of type AckFrame,
     * HandshakeDoneFrame, or CryptoFrame, it either saves the frame or forwards it using the
     * `clientFacingQuicConnection` if the connection is already available. Additionally, if the
     * frame is a `StreamFrame` of type ClientInitiatedBidirectional, it is passed to the application layer.
     */
    fun wrapInbound(framesToSend: List<QuicFrame>, isShortHeader: Boolean){ // frames the kwik client received, now being forwarded by the kwik server
        for (frame: QuicFrame in framesToSend){
            if (!isShortHeader && frame is ConnectionCloseFrame){
                wrapInbound(savedServerResponse!!)
            }
            if (isShortHeader) {
                if (frame !is AckFrame && frame !is HandshakeDoneFrame && frame !is CryptoFrame) {
                    if (clientFacingQuicConnection == null){
                        savedFrames.add(frame)
                    } else {
                        clientFacingQuicConnection?.send(frame, EncryptionLevel.App, null, true)
                    }

                    if (frame is StreamFrame){
                        val streamFrame: StreamFrame = frame
                        if (streamFrame.streamType == StreamType.ClientInitiatedBidirectional) {
                            passInboundToAppLayer(streamFrame)
                        }
                    }
                }
            }
        }
    }

    /**
     * Sets the server connection for the QUIC client and processes any saved frames.
     *
     * @param serverConnectionImpl The server connection implementation to be set.
     *
     * This function assigns the given `ServerConnectionImpl` to the `clientFacingQuicConnection` property.
     * It then processes any frames that were saved prior to the server connection being established,
     * sending each frame using the new server connection.
     */
    fun setServerConnection(serverConnectionImpl: ServerConnectionImpl){
        this.clientFacingQuicConnection = serverConnectionImpl
        for (frame: QuicFrame in savedFrames){
            serverConnectionImpl.send(frame, EncryptionLevel.App, null, true)
        }
    }

    /**
     * Passes the outbound stream frame to the application layer.
     *
     * @param streamFrame The stream frame to pass.
     *
     * This function checks if there is an existing `AppLayerConnection` for the given stream ID. If not, it creates a new
     * `AppLayerConnection` instance. The function then serializes the `StreamFrame` into a byte array and passes this data
     * to the application layer's `unwrapOutbound` method for further processing.
     */
    private fun passOutboundToAppLayer(streamFrame: StreamFrame) {

        var appLayer = appLayerConnections[streamFrame.streamId]

        if(appLayer == null) {
            appLayer = AppLayerConnection.getInstance(streamFrame.streamData, id, this, componentManager, false, streamFrame.streamId)
        }
        appLayerConnections[streamFrame.streamId] = appLayer

        var frameBytes = ByteArray(1500)
        val buffer: ByteBuffer = ByteBuffer.wrap(frameBytes)
        streamFrame.serialize(buffer)
        frameBytes = frameBytes.sliceArray(IntRange(0, buffer.position() - 1))

        appLayer.unwrapOutbound(frameBytes)
    }

    /**
     * Passes the inbound stream frame to the application layer.
     *
     * @param streamFrame The stream frame to pass.
     *
     * This function checks if there is an existing `AppLayerConnection` for the given stream ID. If not, it creates a new
     * `AppLayerConnection` instance. The function then serializes the `StreamFrame` into a byte array and passes this data
     * to the application layer's `unwrapInbound` method for further processing.
     */
    private fun passInboundToAppLayer(streamFrame: StreamFrame) {

        var appLayer = appLayerConnections[streamFrame.streamId]

        if(appLayer == null) {
            appLayer = AppLayerConnection.getInstance(streamFrame.streamData, id, this, componentManager, false, streamFrame.streamId)
        }

        var frameBytes = ByteArray(1500)
        val buffer: ByteBuffer = ByteBuffer.wrap(frameBytes)
        streamFrame.serialize(buffer)
        frameBytes = frameBytes.sliceArray(IntRange(0, buffer.position() - 1))
        appLayer.unwrapInbound(frameBytes)
    }

    ////////////////////////////////////////////////////////////////////////
    ///// kwik setup methods //////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Initiates the setup process for the QUIC connection using the given record.
     *
     * @param record The byte array representing the QUIC record.
     * @param recordType The type of the QUIC record.
     *
     * This function checks the version of QUIC being used by analyzing the given record. If the version is not V1,
     * it passes the record to the application layer, and sets `isV1` to false. If the record is of type INITIAL,
     * it saves the record as the original client hello and proceeds to create a QUIC client using the record.
     */
    private fun initiateKwikSetup(record: ByteArray, recordType: RecordType) {

        // check which Version of QUIC is being used
        val quicVersion = record[1].toUByte().toInt() shl 32 or record[2].toUByte().toInt() shl 16 or record[3].toUByte().toInt() shl 8 or record[4].toUByte().toInt()

        // MitM will first only be implemented for QUIC version 1 (RFC 9000)
        if (quicVersion != 0x00000001){
            Timber.d("quic$id The received packet is not version 1")
            passOutboundToAppLayer(record)
            isV1 = false
        } else {
            if (record.isNotEmpty()){
                when(recordType){
                    RecordType.INITIAL -> {
                        originalClientHello = record
                        createQUICClient(record)
                    }
                    else -> Timber.w("quic$id Unexpected non-initial RecordType at the beginning of a connection: $recordType")
                }
            }
        }
    }

    /**
     * Creates and establishes a QUIC client connection using the given record.
     *
     * @param record The byte array representing the QUIC record.
     *
     * This function initializes the QUIC client setup. It configures the connection
     * parameters, including the URI, logging settings, and application protocol.
     * The function then attempts to establish the server-facing QUIC connection, performing
     * the handshake process and logging the elapsed time for the connection establishment.
     * If the connection is successfully established, it updates the connection state and retrieves
     * the server certificate. Finally, it calls `createQuicServer` to set up the QUIC server.
     */
    private fun createQUICClient(record: ByteArray){
        println("Creating QUIC Client")

        // Enables the use of KWIK for Android
        PlatformMapping.usePlatformMapping(PlatformMapping.Platform.Android)

        // Establish and adjust the QuicClientConnection Builder
        val connectionBuilder = QuicClientConnection.newBuilder()
        val addr = InetAddress.getByName(hostname)
        val host = addr.hostName
        val address = "//" + host + ":" + transportLayer.remotePort
        val uri = URI(address)

        val log = SysOutLogger("Quic$id kwik client: ")
        log.logPackets(true)
        log.logInfo(false)
        log.logDebug(false)
        log.logWarning(true)

        connectionBuilder.uri(uri)
        connectionBuilder.noServerCertificateCheck()
        connectionBuilder.applicationProtocol("h3")
        connectionBuilder.transportLayerConnection(transportLayer)
        connectionBuilder.heimdallQuicConnection(this)
        connectionBuilder.logger(log)
        connectionBuilder.maxOpenPeerInitiatedUnidirectionalStreams(3)
        connectionBuilder.maxOpenPeerInitiatedBidirectionalStreams(0)

        // build the server facing QUIC connection
        serverFacingQuicConnection = connectionBuilder.build()

        // does the handshake process
        try {
            serverFacingQuicConnection?.connect()

            Timber.d("quic$id Server facing QUIC connection established.")
            connectionState = ConnectionState.SERVER_ESTABLISHED

            val elapsed_step1 = mark?.elapsedNow()
            timestamps?.add(elapsed_step1!!)
            println("quic$id Elapsed time - Step 1 - Kwik client connection established: $elapsed_step1")

            serverCertificate = serverFacingQuicConnection?.serverCertificateChain?.get(0)

        } catch (e: Exception){
            Timber.e("quic$id Error while establishing the server facing QUIC connection")
            Timber.e(e)
        } finally {
            createQuicServer()
        }
    }

    /**
     * Creates and establishes a client-facing QUIC server connection.
     *
     * This function generates a fake server certificate using the `mitmManager`, configures the
     * `ServerConnector` with the necessary parameters including supported QUIC versions, logging,
     * and application protocol, and starts the server connector. It also begins the handshake
     * process by receiving the original client hello message.
     */
    private fun createQuicServer(){

        try {
            val fakeCertData = serverCertificate?.let { componentManager.mitmManager.createQuicServerCertificate(it) }

            val fakeCert = fakeCertData?.certificate
            val certs: MutableList<X509Certificate> = java.util.ArrayList()
            if (fakeCert != null) {
                certs.add(fakeCert)
            }

            val prvcert: String = Base64.getEncoder().encodeToString(fakeCert?.encoded)
            val certStream: InputStream = ByteArrayInputStream(prvcert.toByteArray(StandardCharsets.UTF_8))

            val fakeKey = fakeCertData?.privateKey
            val prvkey: String = Base64.getEncoder().encodeToString(fakeKey?.encoded)
            val keyStream: InputStream = ByteArrayInputStream(prvkey.toByteArray(StandardCharsets.UTF_8))

            val supportedVersions: MutableList<Version> = ArrayList()
            supportedVersions.add(Version.QUIC_version_1)
            val log: Logger = SysOutLogger("Quic$id kwik server")
            log.timeFormat(Logger.TimeFormat.Long)
            log.logWarning(true)
            log.logInfo(false)
            log.logPackets(true)
            val requireRetry = false

            serverConnector = ServerConnector(
                transportLayer,
                certs,
                fakeKey,
                supportedVersions,
                requireRetry,
                log,
                this
            )

            serverConnector!!.registerApplicationProtocol(
                "h3",
                object : ApplicationProtocolConnectionFactory {
                    override fun createConnection(
                        protocol: String?,
                        quicConnection: de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.QuicConnection?
                    ): ApplicationProtocolConnection {
                        return BasicConnection(id)
                    }
                })


            serverConnector!!.start()

            serverConnector!!.receiver?.receive(originalClientHello, transportLayer.ipPacketBuilder.localAddress.hostAddress, transportLayer.localPort)

            Timber.d("quic$id Client facing Kwik Server Connector created an handshake process started.")
            connectionState = ConnectionState.CLIENT_HANDSHAKE

        } catch (e: Exception){
            Timber.e("quic$id Error while establishing the client facing QUIC connection")
            Timber.e(e)
        }

    }

    ////////////////////////////////////////////////////////////////////////
    ///// Kwik helper methods /////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////



    ////////////////////////////////////////////////////////////////////////
    ///// Utility methods /////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    /**
     * Determines if the QUIC packet has a short or long header and, if it has a long header, identifies the packet type.
     *
     * @param record The byte array representing the QUIC packet.
     * @return The determined `RecordType` of the QUIC packet.
     *
     * This function examines the first byte of the given QUIC packet to determine if it has a short or long header.
     * For long header packets, it further analyzes the packet type and returns the corresponding `RecordType`.
     * If the header is short, it returns `RecordType.APP`.
     */
    private fun parseRecordType(record: ByteArray): RecordType {
        // get the bits from the first byte
        val firstByte = record[0]

        return if(firstByte.toInt() and 0x80 == 0x80) {
            // Long header packet
            val type: Int = firstByte.toInt() and 0x30 shr 4
            when(type){
                0 -> RecordType.INITIAL
                1 -> RecordType.ZERO_RTT
                2 -> RecordType.HANDSHAKE
                3 -> RecordType.RETRY
                else -> {RecordType.INVALID}
            }
        } else {
            // Short header packet
            RecordType.APP
        }
    }
}


////////////////////////////////////////////////////////////////////////
///// Internal enums //////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////

/**
 * Enum representing the different types of QUIC records.
 */
private enum class RecordType {
    /**
     * Initial packet type used for the first packets of a new connection.
     */
    INITIAL,

    /**
     * Zero Round-Trip Time (0-RTT) packet type used for early data transmission.
     */
    ZERO_RTT,

    /**
     * Handshake packet type used during the handshake phase of the connection.
     */
    HANDSHAKE,

    /**
     * Retry packet type used to indicate that the client should retry the connection attempt.
     */
    RETRY,

    /**
     * Application data packet type used for regular application data transmission.
     */
    APP,

    /**
     * Invalid packet type used to indicate an unrecognized or malformed packet.
     */
    INVALID,
}

private enum class ConnectionState {
    /**
     * Fresh connection, where neither kwik connections is initialised.
     */
    NEW,

    /**
     * Server-facing Kwik-Client initialised and handshake in progress.
     */
    SERVER_HANDSHAKE,

    /**
     * Server-facing QUIC handshake complete and session established.
     */
    SERVER_ESTABLISHED,

    /**
     * Client-facing Kwik-Server initialised and handshake in progress.
     */
    CLIENT_HANDSHAKE,

    /**
     * Client-facing QUIC handshake complete, connection is ready for application data.
     */
    CLIENT_ESTABLISHED,
}

/**
 * Basic implementation of the `ApplicationProtocolConnection` interface.
 *
 * This class serves as a requirement to establish the `ServerConnector`.
 * It does not contain any specific functionality for the application layer,
 * as the application layer functionality is handled by forwarding the received frames.
 *
 * @param id The connection ID.
 */
class BasicConnection(id: Int): ApplicationProtocolConnection{}