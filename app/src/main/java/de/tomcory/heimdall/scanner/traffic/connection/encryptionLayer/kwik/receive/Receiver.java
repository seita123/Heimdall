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
package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.receive;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Receives UDP datagrams on separate thread and queues them for asynchronous processing.
 */
public class Receiver {

    public static final int MAX_DATAGRAM_SIZE = 1500;
    private final Logger log;
    private final Consumer<Throwable> abortCallback;
    private final Predicate<DatagramPacket> packetFilter;
//    private final Thread receiverThread;
    private final BlockingQueue<RawPacket> receivedPacketsQueue;
    private volatile boolean isClosing = false;
    private volatile boolean changing = false;
    private int counter = 0;

    public Receiver(Logger log, Consumer<Throwable> abortCallback) {
        this(log, abortCallback, d -> true);
    }

    public Receiver(Logger log, Consumer<Throwable> abortCallback, Predicate<DatagramPacket> packetFilter) {
        this.log = Objects.requireNonNull(log);
        this.abortCallback = Objects.requireNonNull(abortCallback);
        this.packetFilter = Objects.requireNonNull(packetFilter);

        receivedPacketsQueue = new LinkedBlockingQueue<>();
    }

    public RawPacket get() throws InterruptedException {
        return receivedPacketsQueue.take();
    }

    public boolean hasMore() {
        return !receivedPacketsQueue.isEmpty();
    }

    /**
     * Retrieves a received packet from the queue.
     * @param timeout    the wait timeout in seconds
     * @return
     * @throws InterruptedException
     */
    public RawPacket get(int timeout) throws InterruptedException {
        return receivedPacketsQueue.poll(timeout, TimeUnit.SECONDS);
    }

    public void receive(byte[] receivedPacket, String hostname, int remotePort){
        Instant timeReceived = Instant.now();
        InetSocketAddress address = new InetSocketAddress(hostname, remotePort);
        DatagramPacket receivedDatagram = new DatagramPacket(receivedPacket, receivedPacket.length, address.getAddress(), address.getPort());

        RawPacket rawPacket = new RawPacket(receivedDatagram, timeReceived, counter++);
        receivedPacketsQueue.add(rawPacket);
    }

    public void changeAddress(DatagramSocket newSocket) {
        // Todo: find something useful here
    }
}
