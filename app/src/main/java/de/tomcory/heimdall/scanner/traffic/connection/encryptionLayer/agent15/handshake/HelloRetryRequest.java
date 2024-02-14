package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.handshake;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.TlsConstants;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.extension.Extension;

public class HelloRetryRequest extends ServerHello{

    private final byte[] random = new byte[] {
            (byte) 0xCF, (byte) 0x21, (byte) 0xAD, (byte) 0x74, (byte) 0xE5, (byte) 0x9A, (byte) 0x61, (byte) 0x11,
            (byte) 0xBE, (byte) 0x1D, (byte) 0x8C, (byte) 0x02, (byte) 0x1E, (byte) 0x65, (byte) 0xB8, (byte) 0x91,
            (byte) 0xC2, (byte) 0xA2, (byte) 0x11, (byte) 0x16, (byte) 0x7A, (byte) 0xBB, (byte) 0x8C, (byte) 0x5E,
            (byte) 0x07, (byte) 0x9E, (byte) 0x09, (byte) 0xE2, (byte) 0xC8, (byte) 0xA8, (byte) 0x33, (byte) 0x9C
    };

    private byte[] raw;
    private TlsConstants.CipherSuite cipherSuite;
    private List<Extension> extensions = Collections.emptyList();


    public HelloRetryRequest(TlsConstants.CipherSuite cipher, List<Extension> extensions) {
        this.extensions = extensions;
        cipherSuite = cipher;

        int extensionsSize = extensions.stream().mapToInt(extension -> extension.getBytes().length).sum();
        raw = new byte[1 + 3 + 2 + 32 + 1 + 2 + 1 + 2 + extensionsSize];
        ByteBuffer buffer = ByteBuffer.wrap(raw);
        // https://tools.ietf.org/html/rfc8446#section-4
        // "uint24 length;             /* remaining bytes in message */"
        buffer.putInt((raw.length - 4) | 0x02000000);
        buffer.putShort((short) 0x0303);
        buffer.put(random);
        buffer.put((byte) 0);
        buffer.putShort(cipher.value);
        buffer.put((byte) 0);
        buffer.putShort((short) extensionsSize);
        extensions.stream().forEach(extension -> buffer.put(extension.getBytes()));
    }

    public byte[] getBytes() {
        return raw;
    }
}
