package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.StreamFrame
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.generic.VariableLengthInteger
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.log.NullLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import net.luminis.qpack.Decoder
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStreamReader
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.zip.GZIPInputStream


class Http3Connection(
    id: Int,
    encryptionLayer: EncryptionLayerConnection,
    componentManager: ComponentManager,
    streamId: Int
) : AppLayerConnection(
    id,
    encryptionLayer,
    componentManager
) {
    /**
     * Caches payloads if they don't contain the end of the headers. Once the end of the headers is found (double CRLF), the message is handled normally (chunked, overflowing, or persisted).
     */
    private var previousPayload: ByteArray = ByteArray(0)

    private val qpackDecoder: Decoder = Decoder()

    private var overflowing: Boolean = false

    private var endOfFrame: Boolean = false

    var outboundHeaders: MutableMap<String, String> = mutableMapOf()
    var inboundHeaders: MutableMap<String, String> = mutableMapOf()

    private var outboundBody: String = ""
    private var inboundBody: String = ""

    private val maximumMessageSize = 1024 * 1024 // 1 MB

    private var previousType: Int = -1
    private var previousLength: Int = -1

    private var outboundFrames: MutableList<StreamFrame> = mutableListOf()
    private var inboundFrames: MutableList<StreamFrame> = mutableListOf()


    /**
     * Channel for passing the request ID from the HTTP request insertion coroutine to the HTTP response insertion coroutine.
     */
    private val requestIdChannel = Channel<Int>()

    init {
        if(id > 0) {
            Timber.d("http$id Creating HTTP/3 connection to ${encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${encryptionLayer.transportLayer.remotePort} (${encryptionLayer.transportLayer.remoteHost})")
        }
    }
    override fun unwrapOutbound(payload: ByteArray) {
        val buffer = ByteBuffer.wrap(payload)
        val streamFrame: StreamFrame = StreamFrame().parse(buffer, NullLogger())
//        parseHttpData(streamFrame.streamData, true)
        outboundFrames.add(streamFrame)
        if (streamFrame.isFinal){
            println("unsorted outbound frames: " + outboundFrames)
            outboundFrames.sortedBy { t -> t.offset }
            println("sorted outbound frames: " + outboundFrames)

            var streamData = byteArrayOf()
            val it = outboundFrames.listIterator()
            for (frame in it){
                streamData += frame.streamData
            }

            parseHttpData2(streamData, true)
        }
    }

    override fun unwrapOutbound(packet: Packet) {
        TODO("Not yet implemented")
    }

    override fun unwrapInbound(payload: ByteArray) {
        val buffer = ByteBuffer.wrap(payload)
        val streamFrame: StreamFrame = StreamFrame().parse(buffer, NullLogger())
//        parseHttpData(streamFrame.streamData, false)

        inboundFrames.add(streamFrame)
        if (streamFrame.isFinal){
            println("unsorted inbound frames: " + inboundFrames)
            inboundFrames.sortedBy { t -> t.offset }
            println("sorted inbound frames: " + inboundFrames)

            var streamData = byteArrayOf()
            for (frame: StreamFrame in inboundFrames){
                streamData += frame.streamData
            }

            parseHttpData2(streamData, false)
        }
    }

    private fun parseHttpData2(payload: ByteArray, isOutbound: Boolean){
        try {
            val buffer = ByteBuffer.wrap(payload)

            val frameType = VariableLengthInteger.parse(buffer)
            val frameLength = VariableLengthInteger.parse(buffer)

            val frameData = payload.sliceArray(IntRange(buffer.position(), frameLength + buffer.position() - 1))

            when (frameType) {
//                0 -> if (isOutbound) outboundBody += frameData.toString(Charsets.UTF_8) else inboundBody += frameData.toString(Charsets.UTF_8)
                0 -> if (isOutbound) outboundBody += unzip(frameData) else inboundBody += unzip(frameData)
                1 -> parseHeader(frameData, isOutbound)
                else -> Timber.w("http$id: Unexpected HTTP frame (not header or data frame)")
            }

            val remainingPayload = payload.sliceArray(IntRange(buffer.position() + frameLength, payload.size - 1))

            if (remainingPayload.isNotEmpty()){
                parseHttpData2(remainingPayload, isOutbound)
            }

            persistMessage(isOutbound)

        } catch (e: Exception){
            return
        }
    }

    private fun parseHttpData(streamFrameData: ByteArray, isOutbound: Boolean) {

        val assembledPayload: ByteArray
        if (overflowing) {
            assembledPayload = previousPayload + streamFrameData
            previousPayload = byteArrayOf()
        } else {
            assembledPayload = streamFrameData
        }

        val buffer = ByteBuffer.wrap(assembledPayload)

        try {

            val frameType = VariableLengthInteger.parse(buffer)
            val payloadLength = VariableLengthInteger.parse(buffer)

            println("quic$id debug: frame type: $frameType, payload length: $payloadLength, streamframe length: ${streamFrameData.size}")

            if (payloadLength > assembledPayload.size - buffer.position()) {
                Timber.w("http$id incomplete headers or message")
                overflowing = true
                previousType = frameType
                previousLength = payloadLength
                previousPayload += assembledPayload
                return
            } else {
                if (overflowing) {
                    Timber.w("http$id incomplete headers resolved (header length: )")
                    overflowing = false
                }
                val frameData = assembledPayload.sliceArray(
                    IntRange(
                        buffer.position(),
                        payloadLength + buffer.position() - 1
                    )
                )
                when (frameType) {
                    0 -> if (isOutbound) outboundBody += unzip(frameData) else inboundBody += unzip(frameData)
                    1 -> parseHeader(frameData, isOutbound)
                    else -> Timber.w("http$id: Unexpected HTTP frame (not header or data frame)")
                }

                if (payloadLength < assembledPayload.size - buffer.position()) {
                    val nextFrameData = assembledPayload.sliceArray(
                        IntRange(
                            buffer.position() + payloadLength,
                            assembledPayload.size - 1
                        )
                    )
                    parseHttpData(nextFrameData, isOutbound)
                } else {
                    persistMessage(isOutbound)
                }
            }

        } catch (e: Exception){
            return
        }
    }

    private fun parseHeader(headerData: ByteArray, isOutbound: Boolean) {
//        println("trying to parse header frame")
        try {
            val headersList: List<Map.Entry<String, String>> = qpackDecoder.decodeStream(
                ByteArrayInputStream(headerData)
            )
            for (header: Map.Entry<String, String> in headersList) {
                println("http$id: is Outbound: $isOutbound headers: $header")
                if (isOutbound){
                    outboundHeaders[header.key] = header.value
                } else{
                    inboundHeaders[header.key] = header.value
                }
            }
        } catch (e: Exception){
            Timber.d("http$id Error while decoding the http headers")
        }

    }

    private fun unzip(compressed: ByteArray?): String {
        if (compressed == null || compressed.isEmpty()){
            return ""
        }
        if (!isZipped(compressed)) {
            return String(compressed)
        }
        try {
            ByteArrayInputStream(compressed).use { byteArrayInputStream ->
                GZIPInputStream(byteArrayInputStream).use { gzipInputStream ->
                    InputStreamReader(gzipInputStream, StandardCharsets.UTF_8)
                        .use { inputStreamReader ->
                            BufferedReader(inputStreamReader).use { bufferedReader ->
                                val output = StringBuilder()
                                var line: String?
                                while (bufferedReader.readLine().also { line = it } != null) {
                                    output.append(line)
                                }
                                return output.toString()
                            }
                        }
                }
            }
        } catch (e: IOException) {
            return String(compressed)
        }
    }

    private fun isZipped(compressed: ByteArray): Boolean {
        return compressed[0] == GZIPInputStream.GZIP_MAGIC.toByte() && compressed[1] == (GZIPInputStream.GZIP_MAGIC shr 8).toByte()
    }

    private fun persistMessage(isOutbound: Boolean) {

        CoroutineScope(Dispatchers.IO).launch {
            if(isOutbound) {
                val requestId = componentManager.databaseConnector.persistHttpRequest(
                    connectionId = id,
                    timestamp = System.currentTimeMillis(),
                    headers = outboundHeaders,
                    content = if(outboundBody.length > maximumMessageSize) "<too large: ${outboundBody.length} bytes>" else outboundBody,
                    contentLength = outboundBody.length,
                    method = "",            // statusLine?.get(0) ?: "",
                    remoteHost = encryptionLayer.transportLayer.remoteHost ?: "",
                    remotePath = "",        //statusLine?.get(1) ?: "",
                    remoteIp = encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: "",
                    remotePort = encryptionLayer.transportLayer.remotePort,
                    localIp = encryptionLayer.transportLayer.ipPacketBuilder.localAddress.hostAddress ?: "",
                    localPort = encryptionLayer.transportLayer.localPort,
                    initiatorId = encryptionLayer.transportLayer.appId ?: 0,
                    initiatorPkg = encryptionLayer.transportLayer.appPackage ?: ""
                )
                Timber.d("http$id persisting request with ID $requestId")
                requestIdChannel.send(requestId)
            } else {
                val requestId = requestIdChannel.receive()
                Timber.d("http$id persisting response to request with ID $requestId")
                componentManager.databaseConnector.persistHttpResponse(
                    connectionId = id,
                    requestId = requestId,
                    timestamp = System.currentTimeMillis(),
                    headers = inboundHeaders,
                    content = if(outboundBody.length > maximumMessageSize) "<too large: ${outboundBody.length} bytes>" else outboundBody,
                    contentLength = outboundBody.length,
                    statusCode = 0,           // statusLine?.get(1)?.toIntOrNull() ?: 0,
                    statusMsg =  "",            // statusLine?.get(2) ?: "",
                    remoteHost = encryptionLayer.transportLayer.remoteHost ?: "",
                    remoteIp = encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: "",
                    remotePort = encryptionLayer.transportLayer.remotePort,
                    localIp = encryptionLayer.transportLayer.ipPacketBuilder.localAddress.hostAddress ?: "",
                    localPort = encryptionLayer.transportLayer.localPort,
                    initiatorId = encryptionLayer.transportLayer.appId ?: 0,
                    initiatorPkg = encryptionLayer.transportLayer.appPackage ?: ""
                )
            }
        }

//        if (isOutbound){
//            outboundFrames.clear()
//            outboundHeaders.clear()
//            outboundBody = ""
//        } else {
//            inboundFrames.clear()
//            inboundHeaders.clear()
//            inboundBody = ""
//        }
    }
}