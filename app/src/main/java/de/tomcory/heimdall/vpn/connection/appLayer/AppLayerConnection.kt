package de.tomcory.heimdall.vpn.connection.appLayer

import de.tomcory.heimdall.vpn.connection.encryptionLayer.EncryptionLayerConnection

abstract class AppLayerConnection(val id: Int, val encryptionLayer: EncryptionLayerConnection) {

    /**
     * Receives an outbound payload from the encryption layer, processes it and passes it back down to the encryption layer by calling its wrapOutbound() method.
     */
    abstract fun unwrapOutbound(payload: ByteArray)

    /**
     * Receives an inbound payload from the encryption layer, processes it and passes it back down to the encryption layer by calling its wrapInbound() method.
     */
    abstract fun unwrapInbound(payload: ByteArray)

    companion object {
        private val HTTP_METHODS = arrayOf("GET", "POST", "CONNECT", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH")

        /**
         * Creates an [AppLayerConnection] instance based on the application protocol of the supplied payload (must be the very first application-layer payload of the connection).
         * You still need to call [unwrapOutbound] to actually process the payload once the instance is created.
         * @param payload The raw application-layer payload.
         */
        fun getInstance(payload: ByteArray, id: Int, encryptionLayer: EncryptionLayerConnection): AppLayerConnection {
            //TODO: add DnsConnection
            return try {
                if(payload.size > 7 && HTTP_METHODS.contains(payload.sliceArray(1..10).toString().substringBefore(' '))) {
                    HttpConnection(id, encryptionLayer)
                } else {
                    RawConnection(id, encryptionLayer)
                }
            } catch (e: Exception) {
                RawConnection(id, encryptionLayer)
            }
        }
    }
}