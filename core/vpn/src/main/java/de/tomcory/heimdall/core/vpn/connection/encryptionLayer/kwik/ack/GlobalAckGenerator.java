/*
 * Copyright © 2020, 2021, 2022, 2023 Peter Doornbosch
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
package de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.ack;

import java.time.Instant;
import java.util.Arrays;

import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.FrameReceivedListener;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.PnSpace;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.AckFrame;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.packet.QuicPacket;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.send.NullAckGenerator;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.send.Sender;

public class GlobalAckGenerator implements FrameReceivedListener<AckFrame> {

    private AckGenerator[] ackGenerators;

    public GlobalAckGenerator(Sender sender) {
        ackGenerators = new AckGenerator[PnSpace.values().length];
        Arrays.stream(PnSpace.values()).forEach(pnSpace -> ackGenerators[pnSpace.ordinal()] = new AckGenerator(pnSpace, sender));
    }

    public void packetReceived(QuicPacket packet) {
        if (packet.canBeAcked()) {
            ackGenerators[packet.getPnSpace().ordinal()].packetReceived(packet);
        }
    }

    @Override
    public void received(AckFrame frame, PnSpace pnSpace, Instant timeReceived) {
        ackGenerators[pnSpace.ordinal()].process(frame);
    }

    public AckGenerator getAckGenerator(PnSpace pnSpace) {
        return ackGenerators[pnSpace.ordinal()];
    }

    public void discard(PnSpace pnSpace) {
        // Discard existing ackgenerator for given space, but install a no-op ack generator to catch calls for received
        // packets in that space. This is necessary because even the space is discarded, packets for that space might
        // be received and processed (until its keys are discarded).
        ackGenerators[pnSpace.ordinal()] = new NullAckGenerator();
    }
}
