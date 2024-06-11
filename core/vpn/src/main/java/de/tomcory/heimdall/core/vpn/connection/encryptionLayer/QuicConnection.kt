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
     * @param isShortHeader A boolean indicating whether the received packet was a short header (Applevel packet).
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

    fun setServerConnection(serverConnectionImpl: ServerConnectionImpl){
        this.clientFacingQuicConnection = serverConnectionImpl
        for (frame: QuicFrame in savedFrames){
            serverConnectionImpl.send(frame, EncryptionLevel.App, null, true)
        }
    }

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
                    else -> println("Not an initial RecordType: $recordType") // Platzhalter bis ich mich darum kümmere was ich mit anderen Records mache.
                }
            }
        }
    }

    private fun createQUICClient(record: ByteArray){
        println("Creating QUIC Client")

        // Enables the use of KWIK for Android
        PlatformMapping.usePlatformMapping(PlatformMapping.Platform.Android)

        // Establish and adjust the QuicClientConnection Builder
        val connectionBuilder = QuicClientConnection.newBuilder()
        val addr = InetAddress.getByName(hostname)
        val host = addr.hostName
//        val url = URL(host)
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

    // determine if short or long header and if long header which packet type
    private fun parseRecordType(record: ByteArray): RecordType {
        // Todo: this is one for QUIC Version 1 --> Adapt for V2

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

    fun OutputStream.writeCsv(times: MutableList<Duration>) {
        val writer = bufferedWriter()
//        writer.write(""""Year", "Score", "Title"""")
//        writer.newLine()
        times.forEach {
            writer.write("${it}\"")
            writer.newLine()
        }
        writer.flush()
    }
}


////////////////////////////////////////////////////////////////////////
///// Internal enums //////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////

private enum class RecordType {
    INITIAL,
    ZERO_RTT,
    HANDSHAKE,
    RETRY,
    APP,
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

class BasicConnection(id: Int): ApplicationProtocolConnection{

    private var quicid = -1

    init {
        quicid = id
    }
    override fun acceptPeerInitiatedStream(quicStream: QuicStream) {
//        Thread { handleIncomingRequest(quicStream) }.start()
//        handleIncomingRequest(quicStream)
    }

    private fun handleIncomingRequest(quicStream: QuicStream) {

        val inputStream = BufferedReader(InputStreamReader(quicStream.getInputStream(), "UTF-8"))
//        val streamData = inputStream.readText()
//        println("Stream Data as Text?: " + streamData)
        var i = 0
        try {
            while (i<5) {
                val line = inputStream.readLine()
                println("quic$quicid Received $line")
                i += 1
            }

            // zweite Variante Versuch
            val bytesRead = quicStream.inputStream.readBytes()
            println("quic$quicid Read echo request with " + bytesRead.size + " bytes of data. The Bytes read: " + bytesRead)

        } catch (e: java.lang.Exception) {
            // Done
        }
    }
}