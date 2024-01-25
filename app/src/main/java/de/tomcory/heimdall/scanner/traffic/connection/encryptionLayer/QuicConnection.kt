package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer

//import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicClientConnection

import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.env.PlatformMapping
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicClientConnection
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.core.Version
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.Logger
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.SysOutLogger
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server.ApplicationProtocolConnection
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server.ApplicationProtocolConnectionFactory
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server.ServerConnectionImpl
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server.ServerConnector
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.util.Base64


class QuicConnection(
    id: Long,
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
        // doMitm = false
    }

    private var connectionState: ConnectionState = ConnectionState.NEW;

    private var hostname: String = transportLayer.remoteHost ?: transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: ""

    // Used to derive the initial secret, is fixed to this value for V1 QUIC
    private var initialSaltV1 = byteArrayOf(0x38, 0x76, 0x2c, 0xf7.toByte(), 0xf5.toByte(), 0x59, 0x34,
        0xb3.toByte(), 0x4d, 0x17, 0x9a.toByte(), 0xe6.toByte(), 0xa4.toByte(), 0xc8.toByte(), 0x0c,
        0xad.toByte(), 0xcc.toByte(), 0xbb.toByte(), 0x7f, 0x0a )      // 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a

    // Secrets for initial encryption
    private var initialSecret: ByteArray? = null

    private var serverFacingQuicConnection: QuicClientConnection? = null
    private var clientFacingQuicConnection: ServerConnectionImpl? = null

    private var serverCertificate: X509Certificate? = null

    private val outboundCache = mutableListOf<ByteArray>()
    private var remainingOutboundBytes = 0

    private val inboundCache = mutableListOf<ByteArray>()
    private var remainingInboundBytes = 0

    private var outboundSnippet: ByteArray? = null

    private var inboundSnippet: ByteArray? = null

    private var originalClientHello: ByteArray? = null

    private var serverConnector: ServerConnector? = null


    ////////////////////////////////////////////////////////////////////////
    ///// Inherited methods ///////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    override fun unwrapOutbound(payload: ByteArray) { // Not in use at the moment

        //TODO: implement
//        passOutboundToAppLayer(payload)
    }

    override fun unwrapOutbound(packet: Packet) { // This one is being used
        //TODO: implement
        val recordType = parseRecordType(packet.rawData)
        println("unwrapOutbound $id + RecordType $recordType + ConnectionState: $connectionState")

        // The client starts sending application data, therefore the handshake has been completed
        if (recordType == RecordType.APP){
            connectionState = ConnectionState.CLIENT_ESTABLISHED
        }
        var id = id // just to see in Debug without watch
        when(connectionState){
            ConnectionState.NEW -> initiateKwikSetup(packet.rawData, recordType)
            ConnectionState.CLIENT_HANDSHAKE, ConnectionState.CLIENT_ESTABLISHED -> serverConnector?.receiver?.receive(packet.rawData, transportLayer.ipPacketBuilder.localAddress.hostAddress, transportLayer.localPort)
            else -> {
                println("Unexpected Message from client while in connection state $connectionState")}
        }

//        passOutboundToAppLayer(packet)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        val recordType = parseRecordType(payload)
        println("unwrapInbound $id + RecordType $recordType")


        serverFacingQuicConnection?.receiver?.receive(payload, hostname, transportLayer.remotePort)
//        passInboundToAppLayer(payload)
    }

    override fun wrapOutbound(payload: ByteArray) {
        //TODO: implement
        println("wrapOutbound $id")
        transportLayer.wrapOutbound(payload)
    }

    override fun wrapInbound(payload: ByteArray) {
        //TODO: implement
        println("wrapInbound $id")
        transportLayer.wrapInbound(payload)
    }

    ////////////////////////////////////////////////////////////////////////
    ///// Traffic handler methods /////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////


    @OptIn(ExperimentalUnsignedTypes::class)
    private fun handleOutboundRecord(record: ByteArray, recordType: RecordType){
        // update the doMitm flag if the connection is marked for passthroughs
        doMitm = doMitm && !(transportLayer.appId?.let { componentManager.tlsPassthroughCache.get(it, hostname) } ?: false) //Todo: anpassen auf QUIC!

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if (!doMitm) {
            passOutboundToAppLayer(record)
            return
        }

        if(connectionState == ConnectionState.NEW){
            when(recordType){
                RecordType.INITIAL -> {
                    originalClientHello = record
                    createQUICClient(record)
                }
                else -> println("Not an initial RecordType: $recordType") // Platzhalter bis ich mich darum kümmere was ich mit anderen Records mache.
            }
        }

    }


    private fun handleInboundRecord(record: ByteArray, recordType: RecordType){

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if (!doMitm) {
            passOutboundToAppLayer(record)
            return
        }

    }

    ////////////////////////////////////////////////////////////////////////
    ///// kwik setup methods //////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    private fun createQUICClient(record: ByteArray){
        println("Creating QUIC Client")
        // Enables the use of KWIK for Android
        PlatformMapping.usePlatformMapping(PlatformMapping.Platform.Android);

        // Establish and adjust the QuicClientConnection Builder
        val connectionBuilder = QuicClientConnection.newBuilder()
        val addr = InetAddress.getByName(hostname)
        val host = addr.hostName
//        val url = URL(host)
        val address = "//" + host + ":" + transportLayer.remotePort
        val uri = URI(address)

        connectionBuilder.uri(uri)
        connectionBuilder.noServerCertificateCheck()
        connectionBuilder.applicationProtocol("h3")
        connectionBuilder.transportLayerConnection(transportLayer)

        // build the server facing QUIC connection
        serverFacingQuicConnection = connectionBuilder.build()

        // does the handshake process
        try {
            serverFacingQuicConnection?.connect()

            Timber.d("quic$id Server facing QUIC connection established.")
            connectionState = ConnectionState.SERVER_ESTABLISHED

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
//            val certBytes: ByteArray? = fakeCert?.encoded
//            val certificateInputStream = ByteArrayInputStream(certBytes)
            val prvcert: String = Base64.getEncoder().encodeToString(fakeCert?.encoded)
            val certStream: InputStream = ByteArrayInputStream(prvcert.toByteArray(StandardCharsets.UTF_8))


            val fakeKey = fakeCertData?.privateKey
//            val keyBytes: ByteArray? = fakeKey?.encoded
//            val keyInputStream = ByteArrayInputStream(keyBytes)
            val prvkey: String = Base64.getEncoder().encodeToString(fakeKey?.encoded)
            val keyStream: InputStream = ByteArrayInputStream(prvkey.toByteArray(StandardCharsets.UTF_8))

            val supportedVersions: MutableList<Version> = ArrayList<Version>()
            supportedVersions.add(Version.QUIC_version_1)
            val log: Logger = SysOutLogger()
            val requireRetry = false

            serverConnector = ServerConnector(
                transportLayer,
                certStream,
                keyStream,
                supportedVersions,
                requireRetry,
                log
            )

//            serverConnector!!.registerApplicationProtocol("h3", ApplicationProtocolConnectionFactory(){
//                @Override
//                fun createConnection(protocol: String, quicConnection: QuicConnection): ApplicationProtocolConnection {
//                    return BasicConnection()
//                }
//            });

            serverConnector!!.registerApplicationProtocol(
                "h3",
                object : ApplicationProtocolConnectionFactory {
                    override fun createConnection(
                        protocol: String?,
                        quicConnection: de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.QuicConnection?
                    ): ApplicationProtocolConnection {
                        return BasicConnection()
                    }
                })


            serverConnector!!.start()
            var test = transportLayer.ipPacketBuilder.localAddress.hostAddress
            // Probably different hostname + port needed?
            serverConnector!!.receiver?.receive(originalClientHello, transportLayer.ipPacketBuilder.localAddress.hostAddress, transportLayer.localPort)

            Timber.d("quic$id Client facing QUIC connection established.")
            connectionState = ConnectionState.CLIENT_HANDSHAKE

        } catch (e: Exception){
            Timber.e("quic$id Error while establishing the client facing QUIC connection")
            Timber.e(e)
        }

    }

    ////////////////////////////////////////////////////////////////////////
    ///// TLS record handler, parser, and assembly methods ////////////////
    //////////////////////////////////////////////////////////////////////

    private fun initiateKwikSetup(record: ByteArray, recordType: RecordType) {

        // check which Version of QUIC is being used
        val quicVersion = record[1].toUByte().toInt() shl 32 or record[2].toUByte().toInt() shl 16 or record[3].toUByte().toInt() shl 8 or record[4].toUByte().toInt()

        // MitM will first only be implemented for QUIC version 1 (RFC 9000)
        if (quicVersion != 0x00000001){
            passOutboundToAppLayer(record)
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

    // determine if short or long header and if long header which packet type
    private fun parseRecordType(record: ByteArray): RecordType {
        // Todo: this is one for QUIC Version 1 --> Adapt for V2

        // get the bits from the first byte
        val firstByte = record[0]

        if (firstByte.toInt() and 0x80 == 0x80) {
            // Long header packet
            val type: Int = firstByte.toInt() and 0x30 shr 4
            return when(type){
                0 -> RecordType.INITIAL
                1 -> RecordType.ZERO_RTT
                2 -> RecordType.HANDSHAKE
                3 -> RecordType.RETRY
                else -> {RecordType.INVALID}
            }
        } else {
            // Short header packet
            return RecordType.APP
        }

//        return when(firstByte[0]){
//            '0' -> RecordType.ONE_RTT
//            '1' -> {
//                when(firstByte[4]){     // only like this for version 1 QUIC
//                    '0' -> RecordType.INITIAL
//                    '1' -> RecordType.ZERO_RTT
//                    '2' -> RecordType.HANDSHAKE
//                    '3' -> RecordType.RETRY
//                    else -> RecordType.INVALID
//                }
//            }
//            else -> RecordType.INVALID
//        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// Utility methods /////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////







}


////////////////////////////////////////////////////////////////////////
///// Internal enums //////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////

private enum class RecordType {
    INITIAL,
    ZERO_RTT,
    HANDSHAKE,
    RETRY,
    VERSION_NEGOTIATION, // Todo: implement Version Negotiation
    APP,
    INVALID,
    INDETERMINATE
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

    /**
     * Connection is closed, either because of a close notification sent by a peer or due to an internal error.
     */
    CLOSED
}

class BasicConnection(): ApplicationProtocolConnection;