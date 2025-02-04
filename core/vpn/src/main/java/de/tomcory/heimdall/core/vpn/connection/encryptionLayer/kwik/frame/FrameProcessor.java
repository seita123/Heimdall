package de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.frame;

import java.time.Instant;

import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.kwik.packet.QuicPacket;

/**
 * Processor that is able to process all frame types.
 */
public interface FrameProcessor {

    void process(AckFrame ackFrame, QuicPacket packet, Instant timeReceived);

    void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, Instant timeReceived);

    void process(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived);

    void process(DataBlockedFrame dataBlockedFrame, QuicPacket packet, Instant timeReceived);

    void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived);

    void process(MaxDataFrame maxDataFrame, QuicPacket packet, Instant timeReceived);

    void process(MaxStreamDataFrame maxStreamDataFrame, QuicPacket packet, Instant timeReceived);

    void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, Instant timeReceived);

    void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, Instant timeReceived);

    void process(NewTokenFrame newTokenFrame, QuicPacket packet, Instant timeReceived);

    void process(Padding paddingFrame, QuicPacket packet, Instant timeReceived);

    void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, Instant timeReceived);

    void process(PathResponseFrame pathResponseFrame, QuicPacket packet, Instant timeReceived);

    void process(PingFrame pingFrame, QuicPacket packet, Instant timeReceived);

    void process(ResetStreamFrame resetStreamFrame, QuicPacket packet, Instant timeReceived);

    void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived);

    void process(StopSendingFrame stopSendingFrame, QuicPacket packet, Instant timeReceived);

    void process(StreamFrame streamFrame, QuicPacket packet, Instant timeReceived);

    void process(StreamDataBlockedFrame streamDataBlockedFrame, QuicPacket packet, Instant timeReceived);

    void process(StreamsBlockedFrame streamsBlockedFrame, QuicPacket packet, Instant timeReceived);
}
