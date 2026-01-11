"""
Cync BLE Mesh Protocol - Handshake and Session Management

Implements the handshake protocol and session management for GE Cync BLE devices.
Based on analysis of libBleLib.so and BLEJniLib.java.
"""

from typing import Optional


class MeshProtocol:
    """
    Handles BLE mesh protocol handshake and session management.

    Handshake sequence:
    1. Send handshake start packet
    2. Send key exchange packet
    3. Receive session ID from device
    4. Send sync sequence (5 packets)
    5. Send auth finalize packet
    6. Calculate command prefix from session ID
    """

    # Handshake packet constants
    HANDSHAKE_START = bytes([0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    KEY_EXCHANGE = bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00])
    AUTH_FINALIZE = bytes([0x32, 0x01, 0x19, 0x00, 0x00, 0x00])

    # Sync sequence prefix
    SYNC_PREFIX = 0x31

    @staticmethod
    def create_handshake_start() -> bytes:
        """
        Create handshake start packet.

        Packet structure:
        - Type: 0x00
        - Subtype: 0x05
        - Command: 0x01
        - Padding: 9 bytes of 0x00

        Returns:
            12-byte handshake start packet
        """
        return MeshProtocol.HANDSHAKE_START

    @staticmethod
    def create_key_exchange() -> bytes:
        """
        Create key exchange packet.

        Packet structure:
        - Type: 0x00
        - Sequence: 0x00
        - Command: 0x01
        - Padding: 7 bytes of 0x00
        - Session marker: 0x04
        - Padding: 2 bytes of 0x00

        Returns:
            12-byte key exchange packet
        """
        return MeshProtocol.KEY_EXCHANGE

    @staticmethod
    def create_sync_packet(index: int) -> bytes:
        """
        Create sync packet for the handshake sequence.

        Sync sequence consists of 5 packets (index 0-4):
        - 0x31 0x00
        - 0x31 0x01
        - 0x31 0x02
        - 0x31 0x03
        - 0x31 0x04

        Args:
            index: Sync packet index (0-4)

        Returns:
            2-byte sync packet

        Raises:
            ValueError: If index is not in range 0-4
        """
        if not 0 <= index <= 4:
            raise ValueError(f"Sync index must be 0-4, got {index}")

        return bytes([MeshProtocol.SYNC_PREFIX, index])

    @staticmethod
    def create_auth_finalize() -> bytes:
        """
        Create authentication finalize packet.

        Sent after sync sequence to complete handshake.

        Packet structure:
        - Command: 0x32
        - Subcommand: 0x01
        - Magic: 0x19
        - Padding: 3 bytes of 0x00

        Returns:
            6-byte auth finalize packet
        """
        return MeshProtocol.AUTH_FINALIZE

    @staticmethod
    def parse_session_response(data: bytes) -> Optional[int]:
        """
        Extract session ID from device response.

        Expected response format:
        - Byte 0: Type (0x04)
        - Byte 1: 0x00
        - Byte 2: 0x00
        - Byte 3: Session ID (1 byte)

        Args:
            data: Response bytes from device

        Returns:
            Session ID (0-255) or None if invalid response
        """
        if not data or len(data) < 4:
            return None

        # Check for expected response type
        if data[0] != 0x04:
            return None

        # Session ID is at offset 3
        session_id = data[3]
        return session_id

    @staticmethod
    def calculate_prefix(session_id: int) -> int:
        """
        Calculate command prefix byte from session ID.

        Algorithm (from decompiled Java):
        prefix = (((session_id & 0x0F) + 0x0A) << 4) & 0xFF

        Examples:
        - session_id=0x05 → prefix=0xF0
        - session_id=0x03 → prefix=0xD0
        - session_id=0x07 → prefix=0x10 (wraps due to & 0xFF)

        Args:
            session_id: Session ID from device (0-255)

        Returns:
            Calculated prefix byte (0-255)
        """
        prefix = (((session_id & 0x0F) + 0x0A) << 4) & 0xFF
        return prefix

    @staticmethod
    def get_handshake_sequence() -> list[bytes]:
        """
        Get complete handshake packet sequence in order.

        Returns:
            List of packets to send during handshake:
            1. Handshake start
            2. Key exchange
            3-7. Sync sequence (0-4)
            8. Auth finalize
        """
        packets = [
            MeshProtocol.create_handshake_start(),
            MeshProtocol.create_key_exchange(),
        ]

        # Add sync sequence
        for i in range(5):
            packets.append(MeshProtocol.create_sync_packet(i))

        # Add finalize
        packets.append(MeshProtocol.create_auth_finalize())

        return packets

    @staticmethod
    def validate_session_id(session_id: int) -> bool:
        """
        Validate session ID is in valid range.

        Args:
            session_id: Session ID to validate

        Returns:
            True if valid, False otherwise
        """
        return 0 <= session_id <= 255
