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
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.util.ByteUtils;

import java.nio.ByteBuffer;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.List;


public abstract class BaseLogger implements Logger {

    public static final String TIME_FORMAT_SHORT = "mm:ss.SSS";
    private static final String TIME_FORMAT_LONG = "yy-MM-dd'T'HH:mm:ss.SSS";

    private volatile boolean logDebug = false;
    private volatile boolean logRawBytes = false;
    private volatile boolean logDecrypted = false;
    private volatile boolean logSecrets = false;
    private volatile boolean logPackets = false;
    private volatile boolean logInfo = false;
    private volatile boolean logWarning = false;
    private volatile boolean logStats = false;
    private volatile boolean logRecovery = false;
    private volatile boolean logCongestionControl = false;
    private volatile boolean logFlowControl = false;
    private volatile boolean useRelativeTime = false;
    private volatile DateTimeFormatter timeFormatter;
    private Instant start;


    public BaseLogger() {
        timeFormatter = DateTimeFormatter.ofPattern(TIME_FORMAT_SHORT);
    }

    @Override
    public void logDebug(boolean enabled) {
        logDebug = enabled;
    }

    @Override
    public void logRaw(boolean enabled) {
        logRawBytes = enabled;
    }

    @Override
    public void logDecrypted(boolean enabled) {
        logDecrypted = enabled;
    }

    @Override
    public void logSecrets(boolean enabled) {
        logSecrets = enabled;
    }

    @Override
    public void logPackets(boolean enabled) {
        logPackets = enabled;
    }

    @Override
    public void logInfo(boolean enabled) {
        logInfo = enabled;
    }

    @Override
    public void logWarning(boolean enabled) {
        logWarning = enabled;
    }

    @Override
    public void logStats(boolean enabled) {
        logStats = enabled;
    }

    @Override
    public void logRecovery(boolean enabled) {
        logRecovery = enabled;
    }

    @Override
    public boolean logRecovery() {
        return logRecovery;
    }

    @Override
    public void logCongestionControl(boolean enabled) {
        logCongestionControl = enabled;
    }

    @Override
    public boolean logFlowControl() {
        return logFlowControl;
    }

    @Override
    public void logFlowControl(boolean enabled) {
        logFlowControl = enabled;
    }

    @Override
    public void useRelativeTime(boolean enabled) {
        useRelativeTime = enabled;
    }

    @Override
    public void timeFormat(TimeFormat format) {
        switch (format) {
            case Short:
                timeFormatter = DateTimeFormatter.ofPattern(TIME_FORMAT_SHORT);
                break;
            case Long:
                timeFormatter = DateTimeFormatter.ofPattern(TIME_FORMAT_LONG);
                break;
        }
    }

    @Override
    public void debug(String message) {
        if (logDebug) {
            log(message);
        }
    }

    @Override
    public void debug(String message, Exception error) {
        if (logDebug) {
            log(message, error);
        }
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data) {
        if (logDebug) {
            logWithHexDump(message + " (" + data.length + "): ", data, data.length);
        }
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data, int length) {
        if (logDebug) {
            logWithHexDump(message + " (" + data.length + "): ", data, length);
        }
    }

    @Override
    public void debug(String message, byte[] data) {
        if (logDebug) {
            log(message + " (" + data.length + "): " + byteToHex(data));
        }
    }

    @Override
    public void warn(String message) {
        if (logWarning) {
            log(formatTime() + " " + message);
        }
    }

    @Override
    public void info(String message) {
        if (logInfo) {
            log(formatTime() + " " + message);
        }
    }

    @Override
    public void info(String message, byte[] data) {
        if (logInfo) {
            log(formatTime() + " " + message + " (" + data.length + "): " + ByteUtils.bytesToHex(data));
        }
    }

    @Override
    public void received(Instant timeReceived, int datagram, QuicPacket packet) {
        if (logPackets) {
            log(formatTime(timeReceived) + " <- (" + datagram + ") " + packet);
        }
    }

    @Override
    public void received(Instant timeReceived, int datagram, EncryptionLevel encryptionLevel, byte[] dcid, byte[] scid) {
        if (logPackets) {
            log(formatTime(timeReceived) + " <- (" + datagram + ") "
                    + "Packet "
                    + encryptionLevel.name().charAt(0) + "|"
                    + "." + "|"
                    + "L" + "|"
                    + ByteUtils.bytesToHex(dcid) + "|"
                    + ByteUtils.bytesToHex(scid));
        }
    }

    @Override
    public void receivedPacketInfo(String info) {
        if (logPackets) {
            int indent = formatTime(Instant.now()).length();
            log(" ".repeat(indent) + " -< " + info);
        }
    }

    @Override
    public void sentPacketInfo(String info) {
        if (logPackets) {
            int indent = formatTime(Instant.now()).length();
            log(" ".repeat(indent) + " >- " + info);
        }
    }

    @Override
    public void sent(Instant sent, QuicPacket packet) {
        synchronized (this) {
            if (useRelativeTime) {
                if (start == null) {
                    start = sent;
                }
            }
        }
        if (logPackets) {
            log(formatTime(sent) + " -> " + packet);
        }
    }

    @Override
    public void sent(Instant sent, List<QuicPacket> packets) {
        synchronized (this) {
            if (useRelativeTime) {
                if (start == null) {
                    start = sent;
                }
            }
        }
        if (logPackets) {
            if (packets.size() == 1) {
                log(formatTime(sent) + " -> " + packets.get(0));
            }
            else {
                log(formatTime(sent) + " -> " + packets);
            }
        }
    }

    @Override
    public void secret(String message, byte[] secret) {
        if (logSecrets) {
            log(message + ": " + byteToHex(secret));
        }
    }

    @Override
    public void raw(String message, byte[] data) {
        if (logRawBytes) {
            logWithHexDump(message + " (" + data.length + "): ", data, data.length);
        }
    }

    @Override
    public void raw(String message, ByteBuffer data, int offset, int length) {
        if (logRawBytes) {
            logWithHexDump(message + " (" + length + "): ", data, offset, length);
        }
    }

    @Override
    public void raw(String message, byte[] data, int length) {
        if (logRawBytes) {
            logWithHexDump(message + " (" + data.length + "): ", data, length);
        }
    }

    @Override
    public void decrypted(String message, byte[] data) {
        if (logDecrypted) {
            logWithHexDump(message + " (" + data.length + "): ", data, data.length);
        }
    }

    @Override
    public void decrypted(String message, byte[] data, int length) {
        if (logDecrypted) {
            logWithHexDump(message + " (" + data.length + "): ", data, length);
        }
    }

    @Override
    public void decrypted(String message) {
        if (logDecrypted) {
            log(message);
        }
    }

    @Override
    public void encrypted(String message, byte[] data) {
        // For debugging encryption/decryption code only.
    }

    @Override
    public void error(String message) {
        log(formatTime() + " " + "Error: " + message);
    }

    @Override
    public void error(String message, Throwable error) {
        log(formatTime() + " " + "Error: " + message + ": " + error, error);
    }

    @Override
    public void recovery(String message) {
        if (logRecovery) {
            log(formatTime() + " " + message);
        }
    }

    @Override
    public void recovery(String message, Instant time) {
        if (logRecovery) {
            log(String.format(message, formatTime(time)));
        }
    }

    @Override
    public void cc(String message) {
        if (logCongestionControl) {
            log(formatTime(Instant.now()) + " " + message);
        }
    }

    @Override
    public void fc(String message) {
        if (logFlowControl) {
            log(formatTime(Instant.now()) + " " + message);
        }
    }

    @Override
    public void stats(String message) {
        if (logStats) {
            log(message);
        }
    }

    protected String byteToHex(byte[] data) {
        String result = "";
        for (int i = 0; i < data.length; i++) {
            result += (String.format("%02x ", data[i]));
        }
        return result;
    }

    protected String byteToHexBlock(byte[] data, int length) {
        String result = "";
        for (int i = 0; i < length; ) {
            result += (String.format("%02x ", data[i]));
            i++;
            if (i < data.length)
                if (i % 16 == 0)
                    result += "\n";
                else if (i % 8 == 0)
                    result += " ";
        }
        return result;
    }

    protected String byteToHexBlock(ByteBuffer data, int offset, int length) {
        data.rewind();
        String result = "";
        for (int i = 0; i < length; ) {
            result += String.format("%02x ", data.get(offset + i));
            i++;
            if (i < length)
                if (i % 16 == 0)
                    result += "\n";
                else if (i % 8 == 0)
                    result += " ";
        }
        return result;
    }

    protected String formatTime() {
        return formatTime(Instant.now());
    }

    protected String formatTime(Instant time) {
        if (useRelativeTime) {
            if (start == null) {
                start = time;
            }
            Duration relativeTime = Duration.between(start, time);
            return String.format("%.3f", ((double) relativeTime.toNanos()) / 1000000000);  // Use nano's to get correct rounding to millis
        }
        else {
            LocalDateTime localTimeNow = LocalDateTime.from(time.atZone(ZoneId.systemDefault()));
            return timeFormatter.format(localTimeNow);
        }
    }

    @Override
    public QLog getQLog() {
        return new NullQLog();
    }

    abstract protected void log(String message);

    abstract protected void log(String message, Throwable ex);

    abstract protected void logWithHexDump(String message, byte[] data, int length);

    abstract protected void logWithHexDump(String message, ByteBuffer data, int offset, int length);
}
