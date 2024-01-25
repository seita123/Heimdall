package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer

import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.appLayer.AppLayerConnection
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.UdpConnection
import org.pcap4j.packet.Packet
import timber.log.Timber

abstract class EncryptionLayerConnection(
    val id: Long,
    val transportLayer: TransportLayerConnection,
    val componentManager: ComponentManager
) {

    /**
     * Reference to the connection's application layer handler.
     */
    private var appLayer: AppLayerConnection? = null

    var doMitm = componentManager.doMitm

    fun passOutboundToAppLayer(payload: ByteArray) {
        if(appLayer == null) {
            appLayer = AppLayerConnection.getInstance(payload, id, this, componentManager)
        }
        appLayer?.unwrapOutbound(payload)
    }

        fun passOutboundToAppLayer(packet: Packet) {
        if(appLayer == null) {
            appLayer = AppLayerConnection.getInstance(packet, id, this, componentManager)
        }
        appLayer?.unwrapOutbound(packet)
    }

    fun passInboundToAppLayer(payload: ByteArray) {
        if(appLayer == null) {
            Timber.e("$id Inbound data without an application layer instance!")
            throw java.lang.IllegalStateException("Inbound data without an application layer instance!")
        } else {
            appLayer?.unwrapInbound(payload)
        }
    }

    /**
     * Receives an outbound payload from the transport layer, processes it and passes it up to the application layer.
     */
    abstract fun unwrapOutbound(payload: ByteArray)

    abstract fun unwrapOutbound(packet: Packet)

    /**
     * Receives an inbound payload from the transport layer, processes it and passes it up to the application layer.
     */
    abstract fun unwrapInbound(payload: ByteArray)

    /**
     * Receives an outbound payload from the application layer, processes it and passes it down to the transport layer.
     */
    abstract fun wrapOutbound(payload: ByteArray)

    /**
     * Receives an inbound payload from the application layer, processes it and passes it down to the transport layer.
     */
    abstract fun wrapInbound(payload: ByteArray)

    companion object {

        /**
         * Creates an [EncryptionLayerConnection] instance based on the protocol of the supplied payload (must be the very first transport-layer payload of the connection).
         * You still need to call [unwrapOutbound] to actually process the payload once the instance is created.
         *
         * @param id
         * @param transportLayer
         * @param componentManager The ComponentManager responsible for the VPN session.
         * @param rawPayload The connection's first raw transport-layer payload.
         */
        fun getInstance(id: Long, transportLayer: TransportLayerConnection, componentManager: ComponentManager, rawPayload: ByteArray): EncryptionLayerConnection {
            return if (detectTls(rawPayload)) {
//                TlsConnection(id, transportLayer, componentManager) // todo: replace when done
                PlaintextConnection(id, transportLayer, componentManager)
            } else if(detectQuic(rawPayload, transportLayer)) {
                QuicConnection(id, transportLayer, componentManager)
            } else {
                PlaintextConnection(id, transportLayer, componentManager)
            }
        }

        fun getInstance(id: Long, transportLayer: TransportLayerConnection, componentManager: ComponentManager, packet: Packet): EncryptionLayerConnection {
            return getInstance(id, transportLayer, componentManager, packet.rawData)
        }

        private fun detectTls(rawPayload: ByteArray): Boolean {
            return rawPayload[0].toInt() == 0x16
                    && rawPayload.size > 6
                    && rawPayload[5].toInt() == 1
        }

        private fun detectQuic(rawPayload: ByteArray, transportLayer: TransportLayerConnection): Boolean {
            if(rawPayload.isNotEmpty() and (transportLayer is UdpConnection) and (transportLayer.remotePort == 443)) {
                val firstByte = rawPayload[0].toUByte().toInt()
//                if ((firstByte and 0x20) != 0 && rawPayload.size >= 5){
                if (rawPayload.size >= 5){
                    return true
                }
            }
            return false
        }
    }
}