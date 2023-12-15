package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer

import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.UdpConnection
import de.tomcory.heimdall.scanner.traffic.mitm.SubjectAlternativeNameHolder
import de.tomcory.heimdall.util.ByteUtils
import net.luminis.quic.DatagramSocketFactory
import net.luminis.quic.QuicClientConnection
import net.luminis.quic.server.ServerConnectionImpl
import net.luminis.tls.env.PlatformMapping
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.URI
import java.security.cert.X509Certificate


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

    private var hostname: String = transportLayer.remoteHost ?: transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: ""

    // Used to derive the initial secret, is fixed to this value for V1 QUIC
    private var initialSaltV1 = byteArrayOf(0x38, 0x76, 0x2c, 0xf7.toByte(), 0xf5.toByte(), 0x59, 0x34,
        0xb3.toByte(), 0x4d, 0x17, 0x9a.toByte(), 0xe6.toByte(), 0xa4.toByte(), 0xc8.toByte(), 0x0c,
        0xad.toByte(), 0xcc.toByte(), 0xbb.toByte(), 0x7f, 0x0a )      // 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a

    // Secrets for initial encryption
    private var initialSecret: ByteArray? = null

    private var serverFacingQuicConnection: QuicClientConnection? = null
    private var clientFacingQuicConnection: ServerConnectionImpl? = null

    var serverCertificate: X509Certificate? = null

    private val outboundCache = mutableListOf<ByteArray>()
    private var remainingOutboundBytes = 0

    private val inboundCache = mutableListOf<ByteArray>()
    private var remainingInboundBytes = 0

    private var outboundSnippet: ByteArray? = null

    private var inboundSnippet: ByteArray? = null

    private var socketFactory: SocketFactoryImpl? = null

    ////////////////////////////////////////////////////////////////////////
    ///// Inherited methods ///////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    override fun unwrapOutbound(payload: ByteArray) { // Not in use at the moment

        processRecord(payload, doMitm)

        //TODO: implement
        passOutboundToAppLayer(payload)
    }

    override fun unwrapOutbound(packet: Packet) { // This one is being used
        //TODO: implement
        processRecord(packet.rawData, true)

        passOutboundToAppLayer(packet)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        passInboundToAppLayer(payload)
    }

    override fun wrapOutbound(payload: ByteArray) {
        //TODO: implement
        transportLayer.wrapOutbound(payload)
    }

    override fun wrapInbound(payload: ByteArray) {
        //TODO: implement
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

        when(recordType){
            RecordType.INITIAL -> {
                // createInitialSecrets(record)
                createQUICClient(record)
//                createServerTlsEngine(record)
            }
            else -> println("Not an initial RecordType: $recordType") // Platzhalter bis ich mich darum kümmere was ich mit anderen Records mache.
        }

    }


    private fun handleInboundRecord(record: ByteArray, recordType: RecordType){

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if (!doMitm) {
            passOutboundToAppLayer(record)
            return
        }

        when(recordType){
            RecordType.INITIAL -> {
                createQuicServer(record)
            }
            else -> println("Not an initial RecordType: $recordType") // Platzhalter bis ich mich darum kümmere was ich mit anderen Records mache.
        }
    }

    ////////////////////////////////////////////////////////////////////////
    ///// SSLEngine setup methods /////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////

    private fun createInitialSecrets(record: ByteArray){
        // get Destination ID for generating the pseudorandom key (PRK) with the initial salt
        val destIDlength = record[5].toUByte().toInt()
        val destIDRange = IntRange(6, 6 + destIDlength - 1)
        // val destId = record.slice(destIDRange).toByteArray() // check if this works!

        // destIdBytes.forEach { destID.plus(it.toUByte().toString()) }

        // val destID = destIdBytes.joinToString("") { it.toString(radix = 16).padStart(2, '0') }

//        val hkdf = HKDF.fromHmacSha256()
//
//        initialSecret = hkdf.extract(initialSaltV1, destId)

    }

    private fun createQUICClient(record: ByteArray){

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

//        socketFactory = SocketFactoryImpl(transportLayer)
//        connectionBuilder.socketFactory(socketFactory)

        // build the server facing QUIC connection
        serverFacingQuicConnection = connectionBuilder.build()

        // does the handshake process
        try {
            serverFacingQuicConnection?.connect()

            Timber.d("quic$id Server facing QUIC connection established.")
            serverCertificate = serverFacingQuicConnection?.serverCertificateChain?.get(0)

        }catch (e: Exception){
            Timber.e("quic$id Error while establishing the server facing QUIC connection")
            Timber.e(e)
        }


    }



    private fun createQuicServer(record: ByteArray){

        val commonName = serverCertificate?.let { componentManager.mitmManager.getCommonName(it) }
        val san = SubjectAlternativeNameHolder()
        san.addAll(serverCertificate?.subjectAlternativeNames)

//        val ks = CertificateHelper.createServerCertificate(
//            commonName,
//            san,
//            authority,
//            caCert,
//            caPrivateKey
//        )
    }

    ////////////////////////////////////////////////////////////////////////
    ///// TLS record handler, parser, and assembly methods ////////////////
    //////////////////////////////////////////////////////////////////////

    private fun processRecord(record: ByteArray, isOutbound: Boolean) {

        // check which Version of QUIC is being used
        val quicVersion = record[1].toUByte().toInt() shl 32 or record[2].toUByte().toInt() shl 16 or record[3].toUByte().toInt() shl 8 or record[4].toUByte().toInt()

        // MitM will first only be implemented for QUIC version 1 (RFC 9000)
        if (quicVersion != 0x00000001){
            passOutboundToAppLayer(record)
        }

        if(record.isNotEmpty()) {

            val recordType = parseRecordType(record)

            if(isOutbound) {
                handleOutboundRecord(record, recordType)
            } else {
                handleInboundRecord(record, recordType)
            }
        }

    }

    private fun prepareRecords(payload: ByteArray, isOutbound: Boolean){

        var remainingBytes = if(isOutbound) remainingOutboundBytes else remainingInboundBytes
        val cache = if(isOutbound) outboundCache else inboundCache

        if(remainingBytes > 0) {
            // the payload is added to the overflow

            var attachedPayloadStart = 0
            // check whether there are additional records appended to the current payload and split them off (we'll handle them separately below)
            val currentPayload = if(remainingBytes < payload.size) {
                attachedPayloadStart = remainingBytes
                payload.slice(0 until attachedPayloadStart).toByteArray()
            } else {
                payload
            }

            // add the payload to the cache
            cache.add(currentPayload)
            remainingBytes -= currentPayload.size

            if(isOutbound)
                remainingOutboundBytes = remainingBytes
            else
                remainingInboundBytes = remainingBytes

            // if there are still overflow bytes remaining, do nothing and await the next payload
            if(remainingBytes > 0) {
                return
            }

            // otherwise combine the cached parts into one record and clear the cache
            val combinedRecord = cache.reduce { acc, x -> acc + x }
            cache.clear()

            // process the reassembled record
            processRecord(combinedRecord, isOutbound)

            // if there are additional payloads attached, process them as well
            if(payload.size > currentPayload.size) {
                val attachedPayload = payload.slice(attachedPayloadStart until payload.size).toByteArray()
                //Timber.d("%s Processing attached payload", id)
                prepareRecords(attachedPayload, isOutbound)
            }

        } else {
            // make sure that we have a valid TLS record...
            val recordType = parseRecordType(payload)

            if(recordType == RecordType.INVALID) {
                Timber.e("tls$id Invalid QUIC record type: ${recordType}")
                Timber.e("tls$id ${ByteUtils.bytesToHex(payload)}")
                return
            }

            // ... which must at least comprise a TLS header with 5 bytes
            if(payload.size < 5) {
                //Timber.w("tls$id Got a tiny snippet of a TLS record (${payload.size} bytes), stashing it and awaiting the rest")
                if(isOutbound) {
                    outboundSnippet = payload
                } else {
                    inboundSnippet = payload
                }
                return
            }

            val statedLength = payload[3].toUByte().toInt() shl 8 or payload[4].toUByte().toInt()
            val actualLength = payload.size - 5

            // if the stated record length is larger than the payload length, we go into overflow mode and cache the payload
            if(statedLength > actualLength) {
                cache.add(payload)
                remainingBytes = statedLength - actualLength

                if(isOutbound) {
                    remainingOutboundBytes = remainingBytes
                } else {
                    remainingInboundBytes = remainingBytes
                }

            } else if(statedLength < actualLength) {
                val currentRecord = payload.slice(0 until statedLength + 5).toByteArray()
                val attachedPayload = payload.slice(statedLength + 5 until payload.size).toByteArray()

                // process the extracted record...
                processRecord(currentRecord, isOutbound)

                // ...and when that is done, handle the remaining attached payload
                prepareRecords(attachedPayload, isOutbound)

            } else {
                // if the stated record length matches the payload length, we can just handle the record as-is
                processRecord(payload, isOutbound)
            }
        }

    }

    // determine if short or long header and if long header which packet type
    private fun parseRecordType(record: ByteArray): RecordType {

        // get the bits from the first byte
        val firstByte = record[0].toUByte().toString(2)

        return when(firstByte[0]){
            '0' -> RecordType.ONE_RTT
            '1' -> {
                when(firstByte[4]){     // only like this for version 1 QUIC
                    '0' -> RecordType.INITIAL
                    '1' -> RecordType.ZERO_RTT
                    '2' -> RecordType.HANDSHAKE
                    '3' -> RecordType.RETRY
                    else -> RecordType.INVALID
                }
            }
            else -> RecordType.INVALID
        }
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
    ONE_RTT,
    INVALID,
    INDETERMINATE
}

private enum class FrameType {
    PADDING,
    PING,
    ACK,
    RESET_STREAM,
    STOP_SENDING,
    CRYPTO,
    NEW_TOKEN,
    STREAM,
    MAX_DATA,
    MAX_STREAM_DATA,
    MAX_STREAMS,
    DATA_BLOCKED,
    STREAM_DATA_BLOCKED,
    STREAMS_BLOCKED,
    NEW_CONNECTION_ID,
    RETIRE_CONNECTION_ID,
    PATH_CHALLENGE,
    PATH_RESPONSE,
    CONNECTION_CLOSE,
    HANDSHAKE_DONE,
    EXTENSION       // TODO: read up on that one. Maybe denial the use of extension frames.
}


////////////////////////////////////////////////////////////////////////
///// Socket Factory Implementation ///////////////////////////////////
//////////////////////////////////////////////////////////////////////


class SocketFactoryImpl(transportLayer: TransportLayerConnection) : DatagramSocketFactory{

    var transportLayerUDP: UdpConnection? = transportLayer as? UdpConnection
    override fun createSocket(destination: InetAddress?): DatagramSocket? {
        TODO()
    }

}