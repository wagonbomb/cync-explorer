"""
Cync BLE KLV (Key-Length-Value) Encoder

Implements KLV format encoding/decoding for data points (DPs).
Based on analysis of BLEJniLib.java and libBleLib.so.
"""

from enum import IntEnum
from typing import List, Tuple, Union


class DataType(IntEnum):
    """
    Data point types (from BLEJniLib.java constants).

    These types determine how DP values are interpreted:
    - RAW: Raw binary data
    - BOOL: Boolean (0=False, 1=True)
    - VALUE: Integer value (1-4 bytes)
    - STRING: UTF-8 text string
    - ENUM: Enumeration (integer index)
    - BITMAP: Bit flags
    """
    RAW = 0
    BOOL = 1
    VALUE = 2
    STRING = 3
    ENUM = 4
    BITMAP = 5


class KLVEncoder:
    """
    Encodes and decodes KLV (Key-Length-Value) format for data points.

    KLV Format:
    ┌─────────────┬────────────┬──────────────┐
    │    Key      │   Length   │    Value     │
    │   1 byte    │   1 byte   │  N bytes     │
    └─────────────┴────────────┴──────────────┘

    Example (Power ON):
    ┌──────┬──────┬────────┬─────────┐
    │ 0x01 │ 0x01 │ 0x01   │ 0x01    │
    │DP_ID │ Type │ Length │  Value  │
    └──────┴──────┴────────┴─────────┘
    """

    @staticmethod
    def encode_dp(dp_id: int, dp_type: DataType, value: Union[bool, int, bytes, str]) -> bytes:
        """
        Encode a single data point in KLV format.

        Args:
            dp_id: Data point ID (1-255)
            dp_type: Data type (DataType enum)
            value: Value to encode (type depends on dp_type)

        Returns:
            Encoded KLV bytes

        Raises:
            ValueError: If dp_id is invalid or value type doesn't match dp_type

        Examples:
            >>> KLVEncoder.encode_dp(1, DataType.BOOL, True)
            b'\\x01\\x01\\x01\\x01'  # DP 1, Type BOOL, Len 1, Value 1

            >>> KLVEncoder.encode_dp(2, DataType.VALUE, 127)
            b'\\x02\\x02\\x01\\x7f'  # DP 2, Type VALUE, Len 1, Value 127
        """
        if not 1 <= dp_id <= 255:
            raise ValueError(f"DP ID must be 1-255, got {dp_id}")

        # Convert value to bytes based on type
        if dp_type == DataType.BOOL:
            if not isinstance(value, (bool, int)):
                raise ValueError(f"BOOL type requires bool/int value, got {type(value)}")
            value_bytes = bytes([0x01 if value else 0x00])

        elif dp_type == DataType.VALUE:
            if not isinstance(value, int):
                raise ValueError(f"VALUE type requires int value, got {type(value)}")

            # Encode as minimal bytes (1-4 bytes)
            if value < 0:
                raise ValueError(f"VALUE must be non-negative, got {value}")
            elif value <= 0xFF:
                value_bytes = bytes([value])
            elif value <= 0xFFFF:
                value_bytes = value.to_bytes(2, 'big')
            elif value <= 0xFFFFFF:
                value_bytes = value.to_bytes(3, 'big')
            else:
                value_bytes = value.to_bytes(4, 'big')

        elif dp_type == DataType.STRING:
            if not isinstance(value, str):
                raise ValueError(f"STRING type requires str value, got {type(value)}")
            value_bytes = value.encode('utf-8')

        elif dp_type == DataType.ENUM:
            if not isinstance(value, int):
                raise ValueError(f"ENUM type requires int value, got {type(value)}")
            if not 0 <= value <= 255:
                raise ValueError(f"ENUM value must be 0-255, got {value}")
            value_bytes = bytes([value])

        elif dp_type == DataType.BITMAP:
            if isinstance(value, int):
                # Convert int to bytes
                if value <= 0xFF:
                    value_bytes = bytes([value])
                elif value <= 0xFFFF:
                    value_bytes = value.to_bytes(2, 'big')
                else:
                    value_bytes = value.to_bytes(4, 'big')
            elif isinstance(value, bytes):
                value_bytes = value
            else:
                raise ValueError(f"BITMAP requires int or bytes, got {type(value)}")

        elif dp_type == DataType.RAW:
            if isinstance(value, bytes):
                value_bytes = value
            elif isinstance(value, (list, tuple)):
                value_bytes = bytes(value)
            else:
                raise ValueError(f"RAW requires bytes/list/tuple, got {type(value)}")

        else:
            raise ValueError(f"Unknown data type: {dp_type}")

        # Build KLV structure
        length = len(value_bytes)
        if length > 255:
            raise ValueError(f"Value too large (max 255 bytes), got {length}")

        klv = bytes([
            dp_id,          # Key
            int(dp_type),   # Type (stored in first byte of "length" conceptually)
            length,         # Length
        ]) + value_bytes

        return klv

    @staticmethod
    def encode_multi_dp(dps: List[Tuple[int, DataType, Union[bool, int, bytes, str]]]) -> bytes:
        """
        Encode multiple data points into a single KLV payload.

        Args:
            dps: List of (dp_id, dp_type, value) tuples

        Returns:
            Concatenated KLV bytes for all DPs

        Example:
            >>> dps = [
            ...     (1, DataType.BOOL, True),      # Power ON
            ...     (2, DataType.VALUE, 200),      # Brightness 200
            ... ]
            >>> KLVEncoder.encode_multi_dp(dps)
            b'\\x01\\x01\\x01\\x01\\x02\\x02\\x01\\xc8'
        """
        result = bytearray()

        for dp_id, dp_type, value in dps:
            klv = KLVEncoder.encode_dp(dp_id, dp_type, value)
            result.extend(klv)

        return bytes(result)

    @staticmethod
    def decode(data: bytes) -> List[Tuple[int, DataType, bytes]]:
        """
        Decode KLV data into list of (dp_id, dp_type, value) tuples.

        Args:
            data: KLV-encoded bytes

        Returns:
            List of (dp_id, dp_type, value_bytes) tuples

        Raises:
            ValueError: If data is malformed

        Example:
            >>> data = b'\\x01\\x01\\x01\\x01\\x02\\x02\\x01\\xc8'
            >>> KLVEncoder.decode(data)
            [(1, DataType.BOOL, b'\\x01'), (2, DataType.VALUE, b'\\xc8')]
        """
        result = []
        offset = 0

        while offset < len(data):
            if offset + 3 > len(data):
                raise ValueError(f"Incomplete KLV entry at offset {offset}")

            dp_id = data[offset]
            dp_type = DataType(data[offset + 1])
            length = data[offset + 2]

            if offset + 3 + length > len(data):
                raise ValueError(f"Incomplete value at offset {offset}, expected {length} bytes")

            value = data[offset + 3:offset + 3 + length]
            result.append((dp_id, dp_type, value))

            offset += 3 + length

        return result

    @staticmethod
    def decode_value(dp_type: DataType, value_bytes: bytes) -> Union[bool, int, str, bytes]:
        """
        Decode value bytes based on data type.

        Args:
            dp_type: Data type
            value_bytes: Raw value bytes

        Returns:
            Decoded value in appropriate Python type
        """
        if dp_type == DataType.BOOL:
            return value_bytes[0] != 0

        elif dp_type == DataType.VALUE:
            return int.from_bytes(value_bytes, 'big')

        elif dp_type == DataType.STRING:
            return value_bytes.decode('utf-8', errors='replace')

        elif dp_type == DataType.ENUM:
            return value_bytes[0]

        elif dp_type == DataType.BITMAP:
            if len(value_bytes) == 1:
                return value_bytes[0]
            else:
                return int.from_bytes(value_bytes, 'big')

        elif dp_type == DataType.RAW:
            return value_bytes

        else:
            return value_bytes
