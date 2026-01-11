#!/usr/bin/env python3
"""
Telink BLE Protocol Framing - Based on libBleLib.so decompilation

The native library uses variable-length encoding for packet framing:
- 7-bit encoding with continuation bit (bit 7)
- Frame: [var_offset][var_total_len][type_seq][data...]
- type_seq byte: upper nibble = type, lower nibble = sequence (0-15)
"""

class TelinkFramer:
    """
    Implements the packet framing from trsmitr_send_pkg_encode
    """

    def __init__(self):
        self.sequence = 0  # Cycles 0-15 (DAT_00105718 in decompiled code)

    def _encode_varlen(self, value: int) -> bytes:
        """
        Encode a value using 7-bit variable-length encoding.
        If value >= 0x80, set continuation bit and add more bytes.
        """
        if value < 0x80:
            return bytes([value & 0x7f])
        elif value < 0x4000:
            return bytes([
                (value & 0x7f) | 0x80,
                (value >> 7) & 0x7f
            ])
        elif value < 0x200000:
            return bytes([
                (value & 0x7f) | 0x80,
                ((value >> 7) & 0x7f) | 0x80,
                (value >> 14) & 0x7f
            ])
        else:
            return bytes([
                (value & 0x7f) | 0x80,
                ((value >> 7) & 0x7f) | 0x80,
                ((value >> 14) & 0x7f) | 0x80,
                (value >> 21) & 0x7f
            ])

    def _decode_varlen(self, data: bytes, offset: int = 0) -> tuple[int, int]:
        """
        Decode variable-length value. Returns (value, bytes_consumed).
        """
        value = data[offset] & 0x7f
        consumed = 1

        if data[offset] & 0x80:
            value |= (data[offset + 1] & 0x7f) << 7
            consumed = 2

            if data[offset + 1] & 0x80:
                value |= (data[offset + 2] & 0x7f) << 14
                consumed = 3

                if data[offset + 2] & 0x80:
                    value |= (data[offset + 3] & 0x7f) << 21
                    consumed = 4

        return value, consumed

    def encode_packet(self, frame_type: int, data: bytes) -> list[bytes]:
        """
        Encode data into framed packets (may produce multiple subpackets).

        Args:
            frame_type: Frame type (0-15, stored in upper nibble)
            data: Raw data to encode

        Returns:
            List of encoded subpackets
        """
        packets = []
        total_len = len(data)
        offset = 0
        first_packet = True

        while offset < total_len or first_packet:
            # Calculate how much data we can fit
            # Max subpacket is 0x14 (20) bytes total
            # Need room for: offset_varlen + total_varlen + type_seq + data

            packet = bytearray()

            if first_packet:
                # First packet: offset=0
                offset_bytes = self._encode_varlen(0)
            else:
                offset_bytes = self._encode_varlen(offset)

            total_bytes = self._encode_varlen(total_len)

            # type_seq byte: type in upper nibble, sequence in lower
            type_seq = ((frame_type & 0x0f) << 4) | (self.sequence & 0x0f)

            # Header size
            header_size = len(offset_bytes) + len(total_bytes) + 1  # +1 for type_seq

            # Data that fits
            max_data = 20 - header_size
            chunk_len = min(max_data, total_len - offset)

            # Build packet
            packet.extend(offset_bytes)
            packet.extend(total_bytes)
            packet.append(type_seq)
            packet.extend(data[offset:offset + chunk_len])

            packets.append(bytes(packet))

            offset += chunk_len
            first_packet = False

            # Increment sequence for next packet
            self.sequence = (self.sequence + 1) & 0x0f

            if offset >= total_len:
                break

        return packets

    def decode_packet(self, packet: bytes) -> dict:
        """
        Decode a received packet.

        Returns dict with: offset, total_len, frame_type, sequence, data
        """
        idx = 0

        # Decode offset
        offset, consumed = self._decode_varlen(packet, idx)
        idx += consumed

        # Decode total length
        total_len, consumed = self._decode_varlen(packet, idx)
        idx += consumed

        # Type and sequence
        type_seq = packet[idx]
        frame_type = (type_seq >> 4) & 0x0f
        sequence = type_seq & 0x0f
        idx += 1

        # Remaining is data
        data = packet[idx:]

        return {
            'offset': offset,
            'total_len': total_len,
            'frame_type': frame_type,
            'sequence': sequence,
            'data': data
        }


class KLVEncoder:
    """
    KLV (Key-Length-Value) encoding based on make_klv_list/data_2_klvlist

    Format: [2 bytes: key] [1 byte: length] [N bytes: data]
    """

    # Data types from decompiled code
    TYPE_1 = 1  # Length must be 1
    TYPE_2 = 2  # Length must be 4 (uint32)
    TYPE_3 = 3  # Variable length
    TYPE_4 = 4  # Length must be 1
    TYPE_5 = 5  # Length must be < 5

    @staticmethod
    def encode(key: int, data: bytes) -> bytes:
        """
        Encode a single KLV entry.

        Args:
            key: 16-bit key/ID
            data: Value data

        Returns:
            Encoded KLV bytes
        """
        return bytes([
            key & 0xff,          # Key low byte
            (key >> 8) & 0xff,   # Key high byte
            len(data)            # Length
        ]) + data

    @staticmethod
    def decode(data: bytes) -> list[tuple[int, bytes]]:
        """
        Decode KLV data into list of (key, value) tuples.
        """
        results = []
        idx = 0

        while idx + 3 <= len(data):
            key = data[idx] | (data[idx + 1] << 8)
            length = data[idx + 2]
            idx += 3

            if idx + length > len(data):
                break

            value = data[idx:idx + length]
            results.append((key, value))
            idx += length

        return results


def test_framing():
    """Test the framing implementation"""
    framer = TelinkFramer()

    # Test encoding our handshake commands
    test_data = [
        (0, bytes.fromhex("000501000000000000000000"), "START"),
        (0, bytes.fromhex("00000100000000000000040000"), "KEY_EXCHANGE"),
        (0, bytes.fromhex("3100"), "SYNC_0"),
        (0, bytes.fromhex("3101"), "SYNC_1"),
    ]

    print("=" * 60)
    print("TELINK FRAMING TEST")
    print("=" * 60)

    for frame_type, data, name in test_data:
        print(f"\n[{name}] Raw: {data.hex()}")
        packets = framer.encode_packet(frame_type, data)
        for i, pkt in enumerate(packets):
            print(f"  Encoded[{i}]: {pkt.hex()}")
            decoded = framer.decode_packet(pkt)
            print(f"    -> type={decoded['frame_type']}, seq={decoded['sequence']}, "
                  f"offset={decoded['offset']}, total={decoded['total_len']}, "
                  f"data={decoded['data'].hex()}")


if __name__ == "__main__":
    test_framing()
