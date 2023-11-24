package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer

import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import net.luminis.quic.QuicClientConnection
import net.luminis.quic.core.QuicClientConnectionImpl
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.net.InetAddress
import java.net.URL


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



    override fun unwrapOutbound(payload: ByteArray) { // Not in use at the moment

        processPackets(payload, doMitm)

        //TODO: implement
        passOutboundToAppLayer(payload)
    }

    override fun unwrapOutbound(packet: Packet) { // This one is being used
        //TODO: implement
        processPackets(packet.rawData, true)

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

    private fun processPackets(record: ByteArray, isOutbound: Boolean) {

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
                // handleInboundRecord(record, recordType)
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

    @OptIn(ExperimentalUnsignedTypes::class)
    private fun handleOutboundRecord(record: ByteArray, recordType: RecordType){
        // update the doMitm flag if the connection is marked for passthroughs
        doMitm = doMitm && !(transportLayer.appId?.let { componentManager.tlsPassthroughCache.get(it, hostname) } ?: false)

        // if we don't want to MITM, we can hand the unprocessed record straight to the application layer
        if (!doMitm) {
            passOutboundToAppLayer(record)
            return
        }

        when(recordType){
            RecordType.INITIAL -> {
                createInitialSecrets(record)
                createQUICClient(record)
            }
            else -> println("Not an initial RecordType")
        }


    }

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

        // Try über Builder - wäre nice aber ich komm nicht auf die URI von der IP
        val connectionBuilder = QuicClientConnection.newBuilder()
        val addr = InetAddress.getByName(hostname)
        val host = addr.hostName
        val url = URL(host)
        connectionBuilder.uri(url.toURI())

        // Versuch direkt die Klasse QuicClientConnectionImpl zu instantiieren
        // var clientConnection = QuicClientConnectionImpl(hostname, transportLayer.remotePort, "h3", 10000, )

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