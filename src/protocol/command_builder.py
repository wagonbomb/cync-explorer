"""
Cync BLE Command Builder

High-level command construction for common operations (ON/OFF, brightness, color).
Based on data point (DP) analysis from BLEJniLib.java.
"""

from typing import Optional, List, Tuple
from .klv_encoder import KLVEncoder, DataType


class DataPointID:
    """
    Common data point IDs for GE Cync lights.

    These IDs are inferred from getDpsCommandList() usage patterns
    in the decompiled Java code.
    """
    POWER = 1           # Main power ON/OFF
    BRIGHTNESS = 2      # Brightness 0-255
    COLOR_TEMP = 3      # Color temperature (Kelvin)
    COLOR_RGB = 4       # RGB color
    SCENE = 5           # Scene mode
    COUNTDOWN = 6       # Timer/countdown


class CommandBuilder:
    """
    Builds control commands using KLV encoding.

    This class provides high-level methods to create commands for
    common operations like turning lights on/off, setting brightness,
    and adjusting color temperature.
    """

    @staticmethod
    def build_power_command(on: bool, prefix: Optional[int] = None) -> bytes:
        """
        Build command to turn light ON or OFF.

        Data Point Structure:
        - DP ID: 1 (Power)
        - Type: BOOL (1)
        - Value: 1=ON, 0=OFF

        Args:
            on: True for ON, False for OFF
            prefix: Optional session prefix byte to prepend

        Returns:
            Command bytes ready to send

        Example:
            >>> CommandBuilder.build_power_command(True)
            b'\\x01\\x01\\x01\\x01'  # DP 1, Type BOOL, Len 1, Value 1 (ON)

            >>> CommandBuilder.build_power_command(False, prefix=0xF0)
            b'\\xf0\\xc0\\x01\\x01\\x01\\x00'  # With session prefix
        """
        # Encode DP
        dp_bytes = KLVEncoder.encode_dp(DataPointID.POWER, DataType.BOOL, on)

        # Apply session prefix if provided
        if prefix is not None:
            # Prepend session prefix + marker byte (0xC0)
            return bytes([prefix, 0xC0]) + dp_bytes

        return dp_bytes

    @staticmethod
    def build_brightness_command(level: int, prefix: Optional[int] = None) -> bytes:
        """
        Build command to set brightness level.

        Data Point Structure:
        - DP ID: 2 (Brightness)
        - Type: VALUE (2)
        - Value: 0-255 (0=min, 255=max)

        Args:
            level: Brightness level (0-255 or 0-100 if percentage=True)
            prefix: Optional session prefix byte

        Returns:
            Command bytes ready to send

        Raises:
            ValueError: If level is out of range

        Example:
            >>> CommandBuilder.build_brightness_command(127)  # 50%
            b'\\x02\\x02\\x01\\x7f'

            >>> CommandBuilder.build_brightness_command(255)  # 100%
            b'\\x02\\x02\\x01\\xff'
        """
        if not 0 <= level <= 255:
            raise ValueError(f"Brightness must be 0-255, got {level}")

        # Encode DP
        dp_bytes = KLVEncoder.encode_dp(DataPointID.BRIGHTNESS, DataType.VALUE, level)

        # Apply session prefix if provided
        if prefix is not None:
            return bytes([prefix, 0xC0]) + dp_bytes

        return dp_bytes

    @staticmethod
    def build_brightness_percent_command(percent: int, prefix: Optional[int] = None) -> bytes:
        """
        Build brightness command using percentage (0-100%).

        Args:
            percent: Brightness percentage (0-100)
            prefix: Optional session prefix byte

        Returns:
            Command bytes ready to send

        Raises:
            ValueError: If percent is out of range

        Example:
            >>> CommandBuilder.build_brightness_percent_command(50)  # 50% → 127
            b'\\x02\\x02\\x01\\x7f'

            >>> CommandBuilder.build_brightness_percent_command(100)  # 100% → 255
            b'\\x02\\x02\\x01\\xff'
        """
        if not 0 <= percent <= 100:
            raise ValueError(f"Brightness percent must be 0-100, got {percent}")

        # Convert percentage to 0-255 range
        level = int((percent / 100.0) * 255)

        return CommandBuilder.build_brightness_command(level, prefix)

    @staticmethod
    def build_color_temp_command(kelvin: int, prefix: Optional[int] = None) -> bytes:
        """
        Build command to set color temperature.

        Data Point Structure:
        - DP ID: 3 (Color Temperature)
        - Type: VALUE (2)
        - Value: 2700-6500 (Kelvin)

        Args:
            kelvin: Color temperature in Kelvin (2700-6500)
                    2700K = warm white, 6500K = cool white
            prefix: Optional session prefix byte

        Returns:
            Command bytes ready to send

        Raises:
            ValueError: If kelvin is out of range

        Example:
            >>> CommandBuilder.build_color_temp_command(2700)  # Warm white
            b'\\x03\\x02\\x02\\n\\x8c'  # Value encoded as 2-byte int

            >>> CommandBuilder.build_color_temp_command(6500)  # Cool white
            b'\\x03\\x02\\x02\\x19d'
        """
        if not 2700 <= kelvin <= 6500:
            raise ValueError(f"Color temperature must be 2700-6500K, got {kelvin}")

        # Encode DP
        dp_bytes = KLVEncoder.encode_dp(DataPointID.COLOR_TEMP, DataType.VALUE, kelvin)

        # Apply session prefix if provided
        if prefix is not None:
            return bytes([prefix, 0xC0]) + dp_bytes

        return dp_bytes

    @staticmethod
    def build_color_rgb_command(r: int, g: int, b: int, prefix: Optional[int] = None) -> bytes:
        """
        Build command to set RGB color.

        Data Point Structure:
        - DP ID: 4 (Color RGB)
        - Type: RAW (0)
        - Value: 3 bytes [R, G, B]

        Args:
            r: Red component (0-255)
            g: Green component (0-255)
            b: Blue component (0-255)
            prefix: Optional session prefix byte

        Returns:
            Command bytes ready to send

        Raises:
            ValueError: If any color component is out of range

        Example:
            >>> CommandBuilder.build_color_rgb_command(255, 0, 0)  # Red
            b'\\x04\\x00\\x03\\xff\\x00\\x00'
        """
        if not (0 <= r <= 255 and 0 <= g <= 255 and 0 <= b <= 255):
            raise ValueError(f"RGB values must be 0-255, got R={r} G={g} B={b}")

        rgb_bytes = bytes([r, g, b])
        dp_bytes = KLVEncoder.encode_dp(DataPointID.COLOR_RGB, DataType.RAW, rgb_bytes)

        # Apply session prefix if provided
        if prefix is not None:
            return bytes([prefix, 0xC0]) + dp_bytes

        return dp_bytes

    @staticmethod
    def build_scene_command(scene_id: int, prefix: Optional[int] = None) -> bytes:
        """
        Build command to activate a scene.

        Data Point Structure:
        - DP ID: 5 (Scene)
        - Type: ENUM (4)
        - Value: Scene ID (0-255)

        Args:
            scene_id: Scene identifier (0-255)
            prefix: Optional session prefix byte

        Returns:
            Command bytes ready to send

        Example:
            >>> CommandBuilder.build_scene_command(1)  # Scene 1
            b'\\x05\\x04\\x01\\x01'
        """
        if not 0 <= scene_id <= 255:
            raise ValueError(f"Scene ID must be 0-255, got {scene_id}")

        dp_bytes = KLVEncoder.encode_dp(DataPointID.SCENE, DataType.ENUM, scene_id)

        if prefix is not None:
            return bytes([prefix, 0xC0]) + dp_bytes

        return dp_bytes

    @staticmethod
    def build_multi_dp_command(
        dps: List[Tuple[int, DataType, any]],
        prefix: Optional[int] = None
    ) -> bytes:
        """
        Build command with multiple data points.

        Allows combining multiple operations into a single command
        (e.g., turn on + set brightness + set color).

        Args:
            dps: List of (dp_id, dp_type, value) tuples
            prefix: Optional session prefix byte

        Returns:
            Command bytes ready to send

        Example:
            >>> dps = [
            ...     (1, DataType.BOOL, True),      # Power ON
            ...     (2, DataType.VALUE, 200),      # Brightness 200
            ...     (3, DataType.VALUE, 4000),     # Color temp 4000K
            ... ]
            >>> CommandBuilder.build_multi_dp_command(dps)
            b'\\x01\\x01\\x01\\x01\\x02\\x02\\x01\\xc8\\x03\\x02\\x02\\x0f\\xa0'
        """
        dp_bytes = KLVEncoder.encode_multi_dp(dps)

        if prefix is not None:
            return bytes([prefix, 0xC0]) + dp_bytes

        return dp_bytes

    @staticmethod
    def build_query_state_command() -> bytes:
        """
        Build command to query current device state.

        This corresponds to FRM_ALL_DP_QUERY (type 4) in the protocol.

        Returns:
            Query command bytes

        Note:
            This may require framing/packaging via getNormalRequestData()
            in the actual protocol. For now, returns a simple query marker.
        """
        # Type 4 = Query all data points
        # Based on BLEJniLib.java:189 - getDeviceStatusQuery()
        return bytes([0x04, 0x00, 0x00])

    @staticmethod
    def parse_response(data: bytes) -> dict:
        """
        Parse device response into structured data.

        Args:
            data: Response bytes from device

        Returns:
            Dictionary with parsed DPs:
            {
                'type': frame_type,
                'dps': [(dp_id, dp_type, value), ...]
            }

        Example:
            >>> data = b'\\x03\\x08\\x01\\x01\\x01\\x01\\x02\\x02\\x01\\xc8'
            >>> CommandBuilder.parse_response(data)
            {
                'type': 3,
                'dps': [(1, DataType.BOOL, True), (2, DataType.VALUE, 200)]
            }
        """
        if len(data) < 2:
            return {'type': None, 'dps': []}

        frame_type = data[0]
        payload_length = data[1]

        # Extract payload (skip type and length bytes)
        payload = data[2:2 + payload_length]

        # Decode KLV data
        try:
            klv_list = KLVEncoder.decode(payload)

            # Convert to readable values
            dps = []
            for dp_id, dp_type, value_bytes in klv_list:
                value = KLVEncoder.decode_value(dp_type, value_bytes)
                dps.append((dp_id, dp_type, value))

            return {
                'type': frame_type,
                'dps': dps
            }
        except Exception as e:
            return {
                'type': frame_type,
                'error': str(e),
                'raw': payload.hex()
            }
