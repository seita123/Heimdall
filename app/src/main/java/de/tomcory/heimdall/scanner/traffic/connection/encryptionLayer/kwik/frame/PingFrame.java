/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.frame;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.Logger;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.core.Version;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Represents a ping frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-ping-frames
 */
public class PingFrame extends QuicFrame {

    public PingFrame() {
    }

    public PingFrame(Version quicVersion) {
    }

    public PingFrame parse(ByteBuffer buffer, Logger log) {
        buffer.get();
        return this;
    }

    @Override
    public int getFrameLength() {
        return 1;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x01);
    }

    @Override
    public String toString() {
        return "PingFrame[]";
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
