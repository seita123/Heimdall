package de.tomcory.heimdall.core.vpn.connection.encryptionLayer.agent15.handshake;

import java.nio.ByteBuffer;

import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.agent15.TlsConstants;

public class MessageHash extends HandshakeMessage{

    private byte[] raw;

    public MessageHash(byte[] hash) {
        raw = new byte[1 + 3 + hash.length];
        ByteBuffer buffer = ByteBuffer.wrap(raw);

        buffer.putInt(hash.length | 0xFE000000);
        buffer.put(hash);
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.message_hash;
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }
}
