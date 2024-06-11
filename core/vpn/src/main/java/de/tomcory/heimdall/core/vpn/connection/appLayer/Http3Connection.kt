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
    private val qpackDecoder: Decoder = Decoder()

    private var outboundHeaders: MutableMap<String, String> = mutableMapOf()
    private var inboundHeaders: MutableMap<String, String> = mutableMapOf()

    private var outboundBody: String = ""
    private var inboundBody: String = ""

    private val maximumMessageSize = 1024 * 1024 // 1 MB

    private var outboundFrames: MutableList<StreamFrame> = mutableListOf()
    private var inboundFrames: MutableList<StreamFrame> = mutableListOf()

    /**
     * Channel for passing the request ID from the HTTP request insertion coroutine to the HTTP response insertion coroutine.
     */
    private val requestIdChannel = Channel<Int>()

    init {
        if(id > 0) {
            Timber.d("http$streamId for quic$id Creating HTTP/3 connection to ${encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${encryptionLayer.transportLayer.remotePort} (${encryptionLayer.transportLayer.remoteHost})")
        }
    }

    /**
     * Processes and unwraps the outbound payload, handling the QUIC stream frames.
     *
     * @param payload The outbound payload as a byte array.
     *
     * This function wraps the payload in a ByteBuffer and parses it into a `StreamFrame`.
     * The parsed stream frame is added to the list of outbound frames. If the stream frame
     * is marked as final, the function sorts the frames by offset, concatenates their data,
     * and then calls `parseHttpData` to process the HTTP data.
     */
    override fun unwrapOutbound(payload: ByteArray) {
        val buffer = ByteBuffer.wrap(payload)
        val streamFrame: StreamFrame = StreamFrame().parse(buffer, NullLogger())

        outboundFrames.add(streamFrame)
        if (streamFrame.isFinal){
            outboundFrames.sortedBy { t -> t.offset }

            var streamData = byteArrayOf()
            val it = outboundFrames.listIterator()
            for (frame in it){
                streamData += frame.streamData
            }

            parseHttpData(streamData, true)
        }
    }

    override fun unwrapOutbound(packet: Packet) {
        // Not needed in this implementation.
    }

    /**
     * Processes and unwraps the inbound payload, handling the QUIC stream frames.
     *
     * @param payload The inbound payload as a byte array.
     *
     * This function wraps the payload in a ByteBuffer and parses it into a `StreamFrame`.
     * The parsed stream frame is added to the list of inbound frames. If the stream frame
     * is marked as final, the function sorts the frames by offset, concatenates their data,
     * and then calls `parseHttpData` to process the HTTP data.
     */
    override fun unwrapInbound(payload: ByteArray) {
        val buffer = ByteBuffer.wrap(payload)
        val streamFrame: StreamFrame = StreamFrame().parse(buffer, NullLogger())

        inboundFrames.add(streamFrame)
        if (streamFrame.isFinal){
            inboundFrames.sortedBy { t -> t.offset }

            var streamData = byteArrayOf()
            for (frame: StreamFrame in inboundFrames){
                streamData += frame.streamData
            }
            parseHttpData(streamData, false)
        }
    }

    /**
     * Parses the HTTP data from the given payload, handling different HTTP frame types.
     *
     * @param payload The HTTP data payload as a byte array.
     * @param isOutbound A boolean indicating whether the data is outbound or inbound.
     *
     * This function wraps the payload in a ByteBuffer and parses the frame type and length
     * using `VariableLengthInteger`. It extracts the frame data and processes it based on
     * the frame type. For data frames (type 0), it decompresses and appends the data to
     * either the outbound or inbound body. For header frames (type 1), it calls `parseHeader`.
     * If the payload contains additional data, the function recursively processes the remaining
     * payload. Once all data is processed, it calls `persistMessage` to persist the message.
     *
     * If an exception occurs during parsing, it logs the error and returns.
     */
    private fun parseHttpData(payload: ByteArray, isOutbound: Boolean){
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
                parseHttpData(remainingPayload, isOutbound)
            } else {
                persistMessage(isOutbound)
            }

        } catch (e: Exception){
            Timber.e("Http3$id Error while parsing http frames: $e")
            return
        }
    }

    /**
     * Parses the HTTP headers from the given header data.
     *
     * @param headerData The byte array containing the HTTP header data.
     * @param isOutbound A boolean indicating whether the headers are for outbound or inbound data.
     *
     * This function decodes the header data using a `qpackDecoder` and retrieves a list of headers.
     * Each header is then added to either the outbound or inbound headers map, depending on the value of `isOutbound`.
     */
    private fun parseHeader(headerData: ByteArray, isOutbound: Boolean) {
        try {
            val headersList: List<Map.Entry<String, String>> = qpackDecoder.decodeStream(
                ByteArrayInputStream(headerData)
            )
            for (header: Map.Entry<String, String> in headersList) {
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

    /**
     * Unzips the given compressed byte array and returns the decompressed string.
     *
     * @param compressed The byte array containing the compressed data.
     * @return The decompressed string, or the original byte array as a string if decompression fails or the data is not compressed.
     *
     * This function checks if the given byte array is null or empty and returns an empty string in such cases.
     * If the data is not compressed, it returns the data as a string. If the data is compressed, it attempts to
     * decompress it using a `GZIPInputStream` and returns the decompressed string. If an `IOException` occurs
     * during decompression, it returns the original byte array as a string.
     */
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

    /**
     * Checks if the given byte array is in GZIP compressed format.
     *
     * @param compressed The byte array to check.
     * @return `true` if the byte array is GZIP compressed, `false` otherwise.
     *
     * This function checks the first two bytes of the given byte array against the GZIP magic number to determine
     * if the data is compressed using GZIP.
     */
    private fun isZipped(compressed: ByteArray): Boolean {
        return compressed[0] == GZIPInputStream.GZIP_MAGIC.toByte() && compressed[1] == (GZIPInputStream.GZIP_MAGIC shr 8).toByte()
    }

    /**
     * Persists the HTTP request or response message to the database.
     *
     * @param isOutbound A boolean indicating whether the message is outbound (request) or inbound (response).
     *
     * This function launches a coroutine to persist the HTTP request or response message to the database. For outbound messages,
     * it creates a new HTTP request record in the database and sends the request ID to a channel. For inbound messages, it receives
     * the request ID from the channel and creates a new HTTP response record associated with that request ID. It handles large message
     * content by storing a placeholder if the content exceeds a predefined maximum size. After persisting the message, it clears the
     * corresponding frames, headers, and body data to save memory.
     */
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
                    content = if(inboundBody.length > maximumMessageSize) "<too large: ${inboundBody.length} bytes>" else inboundBody,
                    contentLength = inboundBody.length,
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

            // clear the saved data to save memory
            if (isOutbound){
                outboundFrames.clear()
                outboundHeaders.clear()
                outboundBody = ""
            } else {
                inboundFrames.clear()
                inboundHeaders.clear()
                inboundBody = ""
            }
        }

    }
}