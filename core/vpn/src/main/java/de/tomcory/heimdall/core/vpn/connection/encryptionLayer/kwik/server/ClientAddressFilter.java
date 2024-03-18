/*
 * Copyright © 2023 Peter Doornbosch
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
package de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.server;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.log.Logger;

public class ClientAddressFilter implements ServerConnectionProxy {

    private final ServerConnectionProxy connectionCandidate;
    private final InetSocketAddress clientAddress;
    private final Logger log;

    public ClientAddressFilter(ServerConnectionProxy connectionCandidate, InetSocketAddress clientAddress, Logger log) {
        this.connectionCandidate = connectionCandidate;
        this.clientAddress = clientAddress;
        this.log = log;
    }

    @Override
    public byte[] getOriginalDestinationConnectionId() {
        return connectionCandidate.getOriginalDestinationConnectionId();
    }

    @Override
    public void parsePackets(int datagramNumber, Instant timeReceived, ByteBuffer data, InetSocketAddress sourceAddress) {
        if (sourceAddress.equals(clientAddress)) {
            connectionCandidate.parsePackets(datagramNumber, timeReceived, data, sourceAddress);
        }
        else {
            log.warn(String.format("Dropping packet with unmatched source address %s (expected %s).", sourceAddress, clientAddress));
        }
    }

    @Override
    public boolean isClosed() {
        return connectionCandidate.isClosed();
    }

    @Override
    public void terminate() {
        connectionCandidate.terminate();
    }
}
