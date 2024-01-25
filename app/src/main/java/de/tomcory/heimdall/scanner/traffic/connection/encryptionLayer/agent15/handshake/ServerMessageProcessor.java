/*
 * Copyright © 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.handshake;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.ProtectionKeysType;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.TlsProtocolException;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.handshake.CertificateMessage;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.handshake.CertificateRequestMessage;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.handshake.CertificateVerifyMessage;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.handshake.EncryptedExtensions;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.handshake.MessageProcessor;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.handshake.NewSessionTicketMessage;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.agent15.handshake.ServerHello;

import java.io.IOException;

public interface ServerMessageProcessor extends MessageProcessor {

    default void received(ServerHello sh, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
    }

    default void received(EncryptedExtensions ee, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
    }

    default void received(CertificateMessage cm, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
    }

    default void received(CertificateVerifyMessage cv, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
    }

    default void received(NewSessionTicketMessage nst, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
    }

    default void received(CertificateRequestMessage cr, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
    }
}
