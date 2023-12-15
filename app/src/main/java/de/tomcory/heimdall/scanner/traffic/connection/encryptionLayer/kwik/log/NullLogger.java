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
package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.core.EncryptionLevel;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.packet.QuicPacket;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.qlog.NullQLog;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.qlog.QLog;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;

public class NullLogger implements Logger {

    @Override
    public void logDebug(boolean enabled) {
    }

    @Override
    public void logRaw(boolean enabled) {
    }

    @Override
    public void logDecrypted(boolean enabled) {
    }

    @Override
    public void logSecrets(boolean enabled) {
    }

    @Override
    public void logPackets(boolean enabled) {
    }

    @Override
    public void logInfo(boolean enabled) {
    }

    @Override
    public void logWarning(boolean enabled) {
    }

    @Override
    public void logStats(boolean enabled) {
    }

    @Override
    public void logRecovery(boolean enabled) {
    }

    @Override
    public boolean logRecovery() {
        return false;
    }

    @Override
    public void logCongestionControl(boolean enabled) {
    }

    @Override
    public boolean logFlowControl() {
        return false;
    }

    @Override
    public void logFlowControl(boolean enabled) {

    }

    @Override
    public void useRelativeTime(boolean enabled) {
    }

    @Override
    public void timeFormat(TimeFormat aLong) {

    }

    @Override
    public void debug(String message) {
    }

    @Override
    public void debug(String message, Exception error) {
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data) {
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data, int length) {
    }

    @Override
    public void debug(String message, byte[] data) {
    }

    @Override
    public void info(String message) {
    }

    @Override
    public void warn(String message) {
    }

    @Override
    public void info(String message, byte[] data) {
    }

    @Override
    public void received(Instant timeReceived, int datagram, QuicPacket packet) {
    }

    @Override
    public void received(Instant timeReceived, int datagram, EncryptionLevel encryptionLevel, byte[] dcid, byte[] scid) {
    }

    @Override
    public void sent(Instant sent, QuicPacket packet) {
    }

    @Override
    public void sent(Instant sent, List<QuicPacket> packets) {
    }

    @Override
    public void secret(String message, byte[] secret) {
    }

    @Override
    public void raw(String message, byte[] data) {
    }

    @Override
    public void raw(String message, ByteBuffer data, int offset, int length) {
    }

    @Override
    public void raw(String message, byte[] data, int length) {
    }

    @Override
    public void decrypted(String message, byte[] data) {
    }

    @Override
    public void decrypted(String message, byte[] data, int length) {
    }

    @Override
    public void decrypted(String message) {
    }

    @Override
    public void encrypted(String message, byte[] data) {
    }

    @Override
    public void error(String message) {
    }

    @Override
    public void error(String message, Throwable error) {
    }

    @Override
    public void stats(String message) {
    }

    @Override
    public void recovery(String message) {
    }

    @Override
    public void recovery(String format, Instant lossTime) {
    }

    @Override
    public void cc(String message) {
    }

    @Override
    public void fc(String message) {
    }

    @Override
    public void receivedPacketInfo(String toString) {
    }

    @Override
    public void sentPacketInfo(String info) {
    }

    @Override
    public QLog getQLog() {
        return new NullQLog();
    }
}

