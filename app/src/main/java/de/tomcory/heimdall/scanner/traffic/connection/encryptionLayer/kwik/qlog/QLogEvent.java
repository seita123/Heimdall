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
package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.qlog;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.qlog.event.QLogEventProcessor;

import java.time.Instant;


public abstract class QLogEvent {

    private final byte[] cid;
    private final Instant time;


    public QLogEvent(byte[] cid, Instant time) {
        if (cid == null) {
            throw new IllegalArgumentException();
        }
        if (time == null) {
            throw new IllegalArgumentException();
        }
        this.cid = cid;
        this.time = time;
    }

    public abstract void accept(QLogEventProcessor processor);

    public byte[] getCid() {
        return cid;
    }

    public Instant getTime() {
        return time;
    }
}
