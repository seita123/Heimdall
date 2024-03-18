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
package de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.stream;

import static de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.QuicConstants.TransportErrorCode.FLOW_CONTROL_ERROR;
import static de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.EncryptionLevel.App;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.QuicStream;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.EncryptionLevel;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.QuicConnectionImpl;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.TransportError;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.core.Version;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame.*;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.log.Logger;
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.log.NullLogger;


public class QuicStreamImpl extends BaseStream implements QuicStream {

    protected static long waitForNextFrameTimeout = Long.MAX_VALUE;
    protected static final float receiverMaxDataIncrementFactor = 0.10f;

    private Object addMonitor = new Object();
    protected final Version quicVersion;
    protected final int streamId;
    protected final QuicConnectionImpl connection;
    private final StreamManager streamManager;
    protected final FlowControl flowController;
    protected final Logger log;
    private final StreamInputStream inputStream;
    private final StreamOutputStream outputStream;
    private volatile boolean aborted;
    private long receiverFlowControlLimit;
    private long lastCommunicatedMaxData;
    private final long receiverMaxDataIncrement;
    private volatile long lastOffset = -1;
    private int sendBufferSize = 50 * 1024;
    private long largestOffsetReceived;

    
    public QuicStreamImpl(int streamId, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController) {
        this(Version.getDefault(), streamId, connection, streamManager, flowController, new NullLogger());
    }

    public QuicStreamImpl(int streamId, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log) {
        this(Version.getDefault(), streamId, connection, streamManager, flowController, log);
    }

    public QuicStreamImpl(Version quicVersion, int streamId, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log) {
        this(quicVersion, streamId, connection, streamManager, flowController, log, null);
    }

    QuicStreamImpl(Version quicVersion, int streamId, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log, Integer sendBufferSize) {
        this.quicVersion = quicVersion;
        this.streamId = streamId;
        this.connection = connection;
        this.streamManager = streamManager;
        this.flowController = flowController;
        if (sendBufferSize != null && sendBufferSize > 0) {
            this.sendBufferSize = sendBufferSize;
        }
        this.log = log;

        inputStream = new StreamInputStream();
        outputStream = createStreamOutputStream();

        flowController.streamOpened(this);
        receiverFlowControlLimit = connection.getInitialMaxStreamData();
        lastCommunicatedMaxData = receiverFlowControlLimit;
        receiverMaxDataIncrement = (long) (receiverFlowControlLimit * receiverMaxDataIncrementFactor);
    }

    @Override
    public InputStream getInputStream() {
        return inputStream;
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    /**
     * Adds a newly received frame to the stream.
     *
     * This method is intentionally package-protected, as it should only be called by the (Stream)Packet processor.
     * @param frame
     */
    void add(StreamFrame frame) throws TransportError {
        synchronized (addMonitor) {
            if (frame.getUpToOffset() > receiverFlowControlLimit) {
                throw new TransportError(FLOW_CONTROL_ERROR);
            }
            super.add(frame);
            largestOffsetReceived = Long.max(largestOffsetReceived, frame.getUpToOffset());
            if (frame.isFinal()) {
                lastOffset = frame.getUpToOffset();
            }
            addMonitor.notifyAll();
        }
    }

    /**
     * This method is intentionally package-protected, as it should only be called by the (Stream)Packet processor.
     * @return  largest offset received so far
     */
    long getCurrentReceiveOffset() {
        return largestOffsetReceived;
    }

    @Override
    protected boolean isStreamEnd(long offset) {
        return lastOffset >= 0 && offset >= lastOffset;
    }

    @Override
    public int getStreamId() {
        return streamId;
    }

    @Override
    public boolean isUnidirectional() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-2.1
        // "The second least significant bit (0x2) of the stream ID distinguishes
        //   between bidirectional streams (with the bit set to 0) and
        //   unidirectional streams (with the bit set to 1)."
        return (streamId & 0x0002) == 0x0002;
    }

    @Override
    public boolean isClientInitiatedBidirectional() {
        // "Client-initiated streams have even-numbered stream IDs (with the bit set to 0)"
        return (streamId & 0x0003) == 0x0000;
    }

    @Override
    public boolean isServerInitiatedBidirectional() {
        // "server-initiated streams have odd-numbered stream IDs"
        return (streamId & 0x0003) == 0x0001;
    }

    @Override
    public void closeInput(long applicationProtocolErrorCode) {
        inputStream.stopInput(applicationProtocolErrorCode);
    }

    @Override
    public void resetStream(long errorCode) {
        outputStream.reset(errorCode);
    }

    @Override
    public String toString() {
        return "Stream " + streamId;
    }

    protected StreamOutputStream createStreamOutputStream() {
        return new StreamOutputStream();
    }

    /**
     * Terminates the receiving input stream (abruptly). Is called when peer sends a RESET_STREAM frame
     *
     * This method is intentionally package-protected, as it should only be called by the StreamManager class.
     *
     * @param errorCode
     * @param finalSize
     */
    void terminateStream(long errorCode, long finalSize) {
        inputStream.terminate(errorCode, finalSize);
    }

    // TODO: QuicStream should have a close method that closes both input and output stream and releases all resources and marks itself as terminated.

    /**
     * Input stream for reading data received by the QUIC stream.
     */
    protected class StreamInputStream extends InputStream {

        private volatile boolean closed;
        private volatile boolean reset;
        private volatile Thread blockingReaderThread;

        @Override
        public int available() throws IOException {
            return Integer.max(0, QuicStreamImpl.this.bytesAvailable());
        }

        // InputStream.read() contract:
        // - The value byte is returned as an int in the range 0 to 255.
        // - If no byte is available because the end of the stream has been reached, the value -1 is returned.
        // - This method blocks until input data is available, the end of the stream is detected, or an exception is thrown.
        @Override
        public int read() throws IOException {
            byte[] data = new byte[1];
            int bytesRead = read(data, 0, 1);
            if (bytesRead == 1) {
                return data[0] & 0xff;
            }
            else if (bytesRead < 0) {
                // End of stream
                return -1;
            }
            else {
                // Impossible
                throw new RuntimeException();
            }
        }

        // InputStream.read() contract:
        // - An attempt is made to read the requested number of bytes, but a smaller number may be read.
        // - This method blocks until input data is available, end of file is detected, or an exception is thrown.
        // - If requested number of bytes is greater than zero, an attempt is done to read at least one byte.
        // - If no byte is available because the stream is at end of file, the value -1 is returned;
        //   otherwise, at least one byte is read and stored into the given byte array.
        @Override
        public int read(byte[] buffer, int offset, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            Instant readAttemptStarted = Instant.now();
            long waitPeriod = waitForNextFrameTimeout;
            while (true) {
                if (aborted || closed || reset) {
                    throw new IOException(aborted? "Connection closed": closed? "Stream closed": "Stream reset by peer");
                }

                synchronized (addMonitor) {
                    try {
                        blockingReaderThread = Thread.currentThread();

                        int bytesRead = QuicStreamImpl.this.read(ByteBuffer.wrap(buffer, offset, len));
                        if (bytesRead > 0) {
                            updateAllowedFlowControl(bytesRead);
                            return bytesRead;
                        } else if (bytesRead < 0) {
                            // End of stream
                            return -1;
                        }

                        // Nothing read: block until bytes can be read, read timeout or abort
                        try {
                            addMonitor.wait(waitPeriod);
                        }
                        catch (InterruptedException e) {
                            // Nothing to do here: read will be abort in next loop iteration with IOException
                        }
                    }
                    finally {
                         blockingReaderThread = null;
                    }
                }

                if (bytesAvailable() <= 0) {
                    long waited = Duration.between(readAttemptStarted, Instant.now()).toMillis();
                    if (waited > waitForNextFrameTimeout) {
                        throw new SocketTimeoutException("Read timeout on stream " + streamId + "; read up to " + readOffset());
                    } else {
                        waitPeriod = Long.max(1, waitForNextFrameTimeout - waited);
                    }
                }
            }
        }

        @Override
        public void close() throws IOException {
            // Note that QUIC specification does not define application protocol error codes.
            // By absence of an application specified error code, the arbitrary code 0 is used.
            stopInput(0);
        }

        private void stopInput(long errorCode) {
            if (! allDataReceived()) {
                connection.send(new StopSendingFrame(quicVersion, streamId, errorCode), this::retransmitStopInput, true);
            }
            closed = true;
            Thread blockingReader = blockingReaderThread;
            if (blockingReader != null) {
                blockingReader.interrupt();
            }
        }

        private void retransmitStopInput(QuicFrame lostFrame) {
            assert(lostFrame instanceof StopSendingFrame);

            if (! allDataReceived()) {
                connection.send(lostFrame, this::retransmitStopInput);
            }
        }

        private void updateAllowedFlowControl(int bytesRead) {
            // Slide flow control window forward (with as many bytes as are read)
            receiverFlowControlLimit += bytesRead;
            streamManager.updateConnectionFlowControl(bytesRead);
            // Avoid sending flow control updates with every single read; check diff with last send max data
            if (receiverFlowControlLimit - lastCommunicatedMaxData > receiverMaxDataIncrement) {
                connection.send(new MaxStreamDataFrame(streamId, receiverFlowControlLimit), this::retransmitMaxData, true);
                lastCommunicatedMaxData = receiverFlowControlLimit;
            }
        }

        private void retransmitMaxData(QuicFrame lostFrame) {
            connection.send(new MaxStreamDataFrame(streamId, receiverFlowControlLimit), this::retransmitMaxData);
            log.recovery("Retransmitted max stream data, because lost frame " + lostFrame);
        }

        void terminate(long errorCode, long finalSize) {
            if (!aborted && !closed && !reset) {
                reset = true;
                Thread blockingReader = blockingReaderThread;
                if (blockingReader != null) {
                    blockingReader.interrupt();
                }
            }
        }

        void interruptBlockingThread() {
            Thread readerBlocking = blockingReaderThread;
            if (readerBlocking != null) {
                readerBlocking.interrupt();
            }
        }
    }

    protected class StreamOutputStream extends OutputStream implements FlowControlUpdateListener {

        // Minimum stream frame size: frame type (1), stream id (1..8), offset (1..8), length (1..2), data (1...)
        // Note that in practice stream id and offset will seldom / never occupy 8 bytes, so the minimum leaves more room for data.
        private static final int MIN_FRAME_SIZE = 1 + 8 + 8 + 2 + 1;

        private final ByteBuffer END_OF_STREAM_MARKER = ByteBuffer.allocate(0);
        private final Object lock = new Object();

        // Send queue contains stream bytes to send in order. The position of the first byte buffer in the queue determines the next byte(s) to send.
        private Queue<ByteBuffer> sendQueue = new ConcurrentLinkedDeque<>();
        private final int maxBufferSize;
        private final AtomicInteger bufferedBytes;
        private final ReentrantLock bufferLock;
        private final Condition notFull;
        // Current offset is the offset of the next byte in the stream that will be sent.
        // Thread safety: only used by sender thread, so no synchronization needed.
        private long currentOffset;
        // Closed indicates whether the OutputStream is closed, meaning that no more bytes can be written by caller.
        // Thread safety: only use by caller
        private boolean closed;
        // Send request queued indicates whether a request to send a stream frame is queued with the sender. Is used to avoid multiple requests being queued.
        // Thread safety: read/set by caller and by sender thread, so must be synchronized; guarded by lock
        private volatile boolean sendRequestQueued;
        // Reset indicates whether the OutputStream has been reset.
        private volatile boolean reset;
        private volatile long resetErrorCode;
        // Stream offset at which the stream was last blocked, for detecting the first time stream is blocked at a certain offset.
        private long blockedOffset;
        private volatile Thread blockingWriterThread;

        StreamOutputStream() {
            maxBufferSize = sendBufferSize;
            bufferedBytes = new AtomicInteger();
            bufferLock = new ReentrantLock();
            notFull = bufferLock.newCondition();

            flowController.register(QuicStreamImpl.this, this);
        }

        @Override
        public void write(byte[] data) throws IOException {
            write(data, 0, data.length);
        }

        @Override
        public void write(byte[] data, int off, int len) throws IOException {
            checkState();
            if (len > maxBufferSize) {
                // Buffering all would break the contract (because this method copies _all_ data) but splitting and
                // writing smaller chunks (and waiting for each individual chunk to be buffered successfully) does not.
                int halfBuffersize = maxBufferSize / 2;
                int times = len / halfBuffersize;
                for (int i = 0; i < times; i++) {
                    // Each individual write will probably block, but by splitting the writes in half buffer sizes
                    // avoids that the buffer needs to be emptied completely before a new block can be added (which
                    // could have severed negative impact on performance as the sender might have to wait for the caller
                    // to fill the buffer again).
                    write(data, off + i * halfBuffersize, halfBuffersize);
                }
                int rest = len % halfBuffersize;
                if (rest > 0) {
                    write(data, off + times * halfBuffersize, rest);
                }
                return;
            }

            int availableBufferSpace = maxBufferSize - bufferedBytes.get();
            if (len > availableBufferSpace) {
                // Wait for enough buffer space to become available
                bufferLock.lock();
                blockingWriterThread = Thread.currentThread();
                try {
                    while (maxBufferSize - bufferedBytes.get() < len) {
                        checkState();
                        try {
                            notFull.await();
                        } catch (InterruptedException e) {
                            throw new InterruptedIOException(aborted? "output aborted because connection is closed": "");
                        }
                    }
                }
                finally {
                    blockingWriterThread = null;
                    bufferLock.unlock();
                }
            }

            sendQueue.add(ByteBuffer.wrap(Arrays.copyOfRange(data, off, off + len)));
            bufferedBytes.getAndAdd(len);
            synchronized (lock) {
                if (! sendRequestQueued) {
                    sendRequestQueued = true;
                    connection.send(this::sendFrame, MIN_FRAME_SIZE, getEncryptionLevel(), this::retransmitStreamFrame, true);
                }
            }
        }

        @Override
        public void write(int dataByte) throws IOException {
            // Terrible for performance of course, but that is calling this method anyway.
            byte[] data = new byte[] { (byte) dataByte };
            write(data, 0, 1);
        }

        @Override
        public void flush() throws IOException {
            checkState();
            // No-op, this implementation sends data as soon as possible.
        }

        @Override
        public void close() throws IOException {
            if (!closed && !reset) {
                sendQueue.add(END_OF_STREAM_MARKER);
                closed = true;
                synchronized (lock) {
                    if (! sendRequestQueued) {
                        sendRequestQueued = true;
                        connection.send(this::sendFrame, MIN_FRAME_SIZE, getEncryptionLevel(), this::retransmitStreamFrame, true);
                    }
                }
            }
        }

        private void checkState() throws IOException {
            if (closed || reset) {
                throw new IOException("output stream " + (closed? "already closed": "is reset"));
            }
            if (aborted) {
                throw new IOException("output aborted because connection is closed");
            }
        }

        QuicFrame sendFrame(int maxFrameSize) {
            if (reset) {
                return null;
            }
            synchronized (lock) {
                sendRequestQueued = false;
            }

            if (!sendQueue.isEmpty()) {
                long flowControlLimit = flowController.getFlowControlLimit(QuicStreamImpl.this);
                assert (flowControlLimit >= currentOffset);

                int maxBytesToSend = bufferedBytes.get();
                if (flowControlLimit > currentOffset || maxBytesToSend == 0) {
                    int nrOfBytes = 0;
                    StreamFrame dummy = new StreamFrame(quicVersion, streamId, currentOffset, new byte[0], false);
                    maxBytesToSend = Integer.min(maxBytesToSend, maxFrameSize - dummy.getFrameLength() - 1);  // Take one byte extra for length field var int
                    int maxAllowedByFlowControl = (int) (flowController.increaseFlowControlLimit(QuicStreamImpl.this, currentOffset + maxBytesToSend) - currentOffset);
                    maxBytesToSend = Integer.min(maxAllowedByFlowControl, maxBytesToSend);

                    byte[] dataToSend = new byte[maxBytesToSend];
                    boolean finalFrame = false;
                    while (nrOfBytes < maxBytesToSend && !sendQueue.isEmpty()) {
                        ByteBuffer buffer = sendQueue.peek();
                        int position = nrOfBytes;
                        if (buffer.remaining() <= maxBytesToSend - nrOfBytes) {
                            // All bytes remaining in buffer will fit in stream frame
                            nrOfBytes += buffer.remaining();
                            buffer.get(dataToSend, position, buffer.remaining());
                            sendQueue.poll();
                        }
                        else {
                            // Just part of the buffer will fit in (and will fill up) the stream frame
                            buffer.get(dataToSend, position, maxBytesToSend - nrOfBytes);
                            nrOfBytes = maxBytesToSend;  // Short form of: nrOfBytes += (maxBytesToSend - nrOfBytes)
                        }
                    }
                    if (!sendQueue.isEmpty() && sendQueue.peek() == END_OF_STREAM_MARKER) {
                        finalFrame = true;
                        sendQueue.poll();
                    }
                    if (nrOfBytes == 0 && !finalFrame) {
                        // Nothing to send really
                        return null;
                    }

                    bufferedBytes.getAndAdd(-1 * nrOfBytes);
                    bufferLock.lock();
                    try {
                        notFull.signal();
                    } finally {
                        bufferLock.unlock();
                    }

                    if (nrOfBytes < maxBytesToSend) {
                        // This can happen when not enough data is buffer to fill a stream frame, or length field is 1 byte (instead of 2 that was counted for)
                        dataToSend = Arrays.copyOfRange(dataToSend, 0, nrOfBytes);
                    }
                    StreamFrame streamFrame = new StreamFrame(quicVersion, streamId, currentOffset, dataToSend, finalFrame);
                    currentOffset += nrOfBytes;

                    if (!sendQueue.isEmpty()) {
                        synchronized (lock) {
                            sendRequestQueued = true;
                        }
                        // There is more to send, so queue a new send request.
                        connection.send(this::sendFrame, MIN_FRAME_SIZE, getEncryptionLevel(), this::retransmitStreamFrame, true);
                    }

                    if (streamFrame.isFinal()) {
                        finalFrameSent();
                    }
                    return streamFrame;
                }
                else {
                    // So flowControlLimit <= currentOffset
                    // Check if this condition hasn't been handled before
                    if (currentOffset != blockedOffset) {
                        // Not handled before, remember this offset, so this isn't executed twice for the same offset
                        blockedOffset = currentOffset;
                        // And let peer know
                        // https://www.rfc-editor.org/rfc/rfc9000.html#name-data-flow-control
                        // "A sender SHOULD send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver
                        //  that it has data to write but is blocked by flow control limits."
                        connection.send(this::sendBlockReason, StreamDataBlockedFrame.getMaxSize(streamId), App, this::retransmitSendBlockReason, true);
                    }
                }
            }
            return null;
        }

        protected void finalFrameSent() {
            stopFlowControl();
        }

        @Override
        public void streamNotBlocked(int streamId) {
            // Stream might have been blocked (or it might have filled the flow control window exactly), queue send request
            // and let sendFrame method determine whether there is more to send or not.
            connection.send(this::sendFrame, MIN_FRAME_SIZE, getEncryptionLevel(), this::retransmitStreamFrame, false);  // No need to flush, as this is called while processing received message
        }

        void interruptBlockingThread() {
            Thread blocking = blockingWriterThread;
            if (blocking != null) {
                blocking.interrupt();
            }
        }

        /**
         * Sends StreamDataBlockedFrame or DataBlockedFrame to the peer, provided the blocked condition is still true.
         * @param maxFrameSize
         * @return
         */
        private QuicFrame sendBlockReason(int maxFrameSize) {
            // Retrieve actual block reason; could be "none" when an update has been received in the meantime.
            BlockReason blockReason = flowController.getFlowControlBlockReason(QuicStreamImpl.this);
            QuicFrame frame = null;
            switch (blockReason) {
                case STREAM_DATA_BLOCKED:
                    frame = new StreamDataBlockedFrame(quicVersion, streamId, currentOffset);
                    break;
                case DATA_BLOCKED:
                    frame = new DataBlockedFrame(flowController.getConnectionDataLimit());
                    break;
            }
            return frame;
        }

        private void retransmitSendBlockReason(QuicFrame quicFrame) {
            connection.send(this::sendBlockReason, StreamDataBlockedFrame.getMaxSize(streamId), App, this::retransmitSendBlockReason, true);
        }

        private void retransmitStreamFrame(QuicFrame frame) {
            assert(frame instanceof StreamFrame);
            if (! reset) {
                connection.send(frame, this::retransmitStreamFrame);
                log.recovery("Retransmitted lost stream frame " + frame);
            }
        }

        protected EncryptionLevel getEncryptionLevel() {
            return App;
        }

        private void restart() {
            currentOffset = 0;
            sendQueue.clear();
            sendRequestQueued = false;
        }

        /**
         * https://www.rfc-editor.org/rfc/rfc9000.html#name-operations-on-streams
         * "reset the stream (abrupt termination), resulting in a RESET_STREAM frame (Section 19.4) if the stream was
         *  not already in a terminal state."
         * @param errorCode
         */
        protected void reset(long errorCode) {
            if (!closed && !reset) {
                reset = true;
                resetErrorCode = errorCode;
                // Use sender callback to ensure current offset used in reset frame is accessed by sender thread.
                connection.send(this::createResetFrame, ResetStreamFrame.getMaximumFrameSize(streamId, errorCode), App, this::retransmitResetFrame, true);
                // Ensure write is not blocked because of full write buffer
                bufferLock.lock();
                try {
                    notFull.signal();
                }
                finally {
                    bufferLock.unlock();
                }
            }
        }

        private QuicFrame createResetFrame(int maxFrameSize) {
            assert(reset == true);
            return new ResetStreamFrame(streamId, resetErrorCode, currentOffset);
        }

        private void retransmitResetFrame(QuicFrame frame) {
            assert(frame instanceof ResetStreamFrame);
            connection.send(frame, this::retransmitResetFrame);
        }
    }

    /**
     * Resets the output stream so data can again be send from the start of the stream (offset 0). Note that in such
     * cases the caller must (again) provide the data to be sent.
     */
    protected void resetOutputStream() {
        outputStream.closed = false;
        // TODO: this is currently not thread safe, see comment in EarlyDataStream how to fix.
        outputStream.restart();
    }

    protected void stopFlowControl() {
        // Done! Retransmissions may follow, but don't need flow control.
        flowController.unregister(QuicStreamImpl.this);
        flowController.streamClosed(QuicStreamImpl.this);
    }

    void abort() {
        aborted = true;
        inputStream.interruptBlockingThread();
        outputStream.interruptBlockingThread();
    }
}
