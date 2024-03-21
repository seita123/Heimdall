package de.tomcory.heimdall.core.vpn.components

import android.os.Environment
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder


class PcapExportService {

    companion object{
        fun copyDataToPCAP(rawPacket: ByteArray){

            // Specify the file path to the Downloads directory on the Android device
            val fileName = "output.pcap"
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val filePath = downloadsDir.absolutePath + "/" + fileName

            // Check if the file exists; if not, write the global header
            if (!File(filePath).exists()) {
                try {
                    FileOutputStream(filePath).use { fos ->
                        // Write pcap file header (you may need to generate it based on pcap format specifications)
                        // Assuming you already have a pcap file header
                        val pcapHeader = createGlobalHeader()
                        fos.write(pcapHeader)
                    }
                } catch (e: IOException) {
                    e.printStackTrace()
                }
            }

            // Append packet header and raw packet data
            try {
                FileOutputStream(filePath, true).use { fos ->
                    val packetHeader = createPacketHeader(rawPacket.size)
                    fos.write(packetHeader)

                    // Write captured data to the pcap file
                    fos.write(rawPacket)
                }
            } catch (e: IOException) {
                e.printStackTrace()
            }
        }

        private fun createGlobalHeader(): ByteArray? {
            val buffer = ByteBuffer.allocate(24)
            buffer.order(ByteOrder.LITTLE_ENDIAN)
            buffer.putInt(-0x5e4d3c2c)

            // Major and Minor Version Number
            buffer.putShort(2.toShort()) // Major Version Number

            buffer.putShort(4.toShort()) // Minor Version Number

            // Timezone offset (in seconds from UTC) - usually 0
            buffer.putInt(0)

            // Timestamp accuracy (in microseconds) - usually 0
            buffer.putInt(0)

            // Snapshot length (maximum number of bytes to capture per packet)
            buffer.putInt(65535)

            // Link-layer header type (e.g., 1 for Ethernet)
            buffer.putInt(101) // Assuming IPv4 or IPv6
            return buffer.array()
        }

        private fun createPacketHeader(size: Int): ByteArray {
            val buffer = ByteBuffer.allocate(16)
            buffer.order(ByteOrder.LITTLE_ENDIAN)

            val unixTime = (System.currentTimeMillis() / 1000).toInt()
            val unixTimeMicroseconds = (System.currentTimeMillis() % 1000 * 1000).toInt() // Convert remaining milliseconds to microseconds

            buffer.putInt(unixTime)
            buffer.putInt(unixTimeMicroseconds)

            buffer.putInt(size)
            buffer.putInt(size)
            return buffer.array()
        }

        // Generate a fake Ethernet Header (not used at the moment since Link Layer Header Type is specified to IPv4/IPv6).
        private fun generateFakeEthernetHeader(): ByteArray {
            val ethernetHeader = ByteArray(14) // Ethernet header is typically 14 bytes

            // Fill in source and destination MAC addresses (dummy values)
            for (i in 0..5) {
                ethernetHeader[i] = 0xFF.toByte() // Dummy MAC address (broadcast)
                ethernetHeader[i + 6] = 0xFF.toByte() // Dummy MAC address (broadcast)
            }

            // EtherType (0x0800 for IPv4)
            ethernetHeader[12] = 0x08.toByte()
            ethernetHeader[13] = 0x00.toByte()
            return ethernetHeader
        }
    }

}