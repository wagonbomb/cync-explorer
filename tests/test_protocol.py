"""
Unit tests for Cync BLE protocol modules.

Tests handshake, KLV encoding, command building, and encryption.
"""

import unittest
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from protocol.mesh_protocol import MeshProtocol
from protocol.klv_encoder import KLVEncoder, DataType
from protocol.command_builder import CommandBuilder, DataPointID
from protocol.aes_crypto import AESCrypto, NullCrypto


class TestMeshProtocol(unittest.TestCase):
    """Test handshake and session management."""

    def test_handshake_start(self):
        """Test handshake start packet generation."""
        packet = MeshProtocol.create_handshake_start()
        self.assertEqual(packet.hex(), "000501000000000000000000")
        self.assertEqual(len(packet), 12)

    def test_key_exchange(self):
        """Test key exchange packet generation."""
        packet = MeshProtocol.create_key_exchange()
        self.assertEqual(packet.hex(), "000001000000000000040000")
        self.assertEqual(len(packet), 12)

    def test_sync_packets(self):
        """Test sync sequence packets."""
        for i in range(5):
            packet = MeshProtocol.create_sync_packet(i)
            self.assertEqual(packet[0], 0x31)
            self.assertEqual(packet[1], i)

    def test_sync_packet_invalid_index(self):
        """Test sync packet with invalid index."""
        with self.assertRaises(ValueError):
            MeshProtocol.create_sync_packet(5)  # Max is 4

    def test_auth_finalize(self):
        """Test auth finalize packet."""
        packet = MeshProtocol.create_auth_finalize()
        self.assertEqual(packet.hex(), "320119000000")
        self.assertEqual(len(packet), 6)

    def test_parse_session_response(self):
        """Test session ID extraction from response."""
        # Valid response
        response = bytes([0x04, 0x00, 0x00, 0x05])
        session_id = MeshProtocol.parse_session_response(response)
        self.assertEqual(session_id, 0x05)

        # Invalid response (wrong type)
        response = bytes([0x02, 0x00, 0x00, 0x05])
        session_id = MeshProtocol.parse_session_response(response)
        self.assertIsNone(session_id)

        # Too short
        response = bytes([0x04, 0x00])
        session_id = MeshProtocol.parse_session_response(response)
        self.assertIsNone(session_id)

    def test_calculate_prefix(self):
        """Test session prefix calculation."""
        # Example from docs: session_id=0x05 → prefix=0xF0
        prefix = MeshProtocol.calculate_prefix(0x05)
        self.assertEqual(prefix, 0xF0)

        # Test another value
        prefix = MeshProtocol.calculate_prefix(0x03)
        self.assertEqual(prefix, 0xD0)

    def test_get_handshake_sequence(self):
        """Test complete handshake sequence."""
        sequence = MeshProtocol.get_handshake_sequence()
        self.assertEqual(len(sequence), 8)  # Start + Exchange + 5 Sync + Finalize
        self.assertEqual(sequence[0], MeshProtocol.HANDSHAKE_START)
        self.assertEqual(sequence[1], MeshProtocol.KEY_EXCHANGE)
        self.assertEqual(sequence[-1], MeshProtocol.AUTH_FINALIZE)


class TestKLVEncoder(unittest.TestCase):
    """Test KLV encoding/decoding."""

    def test_encode_bool_on(self):
        """Test encoding boolean ON."""
        klv = KLVEncoder.encode_dp(1, DataType.BOOL, True)
        self.assertEqual(klv.hex(), "01010101")

    def test_encode_bool_off(self):
        """Test encoding boolean OFF."""
        klv = KLVEncoder.encode_dp(1, DataType.BOOL, False)
        self.assertEqual(klv.hex(), "01010100")

    def test_encode_value_1byte(self):
        """Test encoding 1-byte value."""
        klv = KLVEncoder.encode_dp(2, DataType.VALUE, 127)
        self.assertEqual(klv.hex(), "0202017f")

    def test_encode_value_2byte(self):
        """Test encoding 2-byte value."""
        klv = KLVEncoder.encode_dp(3, DataType.VALUE, 4000)  # 0x0FA0
        self.assertEqual(klv, bytes([3, 2, 2, 0x0F, 0xA0]))

    def test_encode_string(self):
        """Test encoding string."""
        klv = KLVEncoder.encode_dp(10, DataType.STRING, "Test")
        self.assertEqual(klv[0], 10)           # DP ID
        self.assertEqual(klv[1], DataType.STRING)  # Type
        self.assertEqual(klv[2], 4)            # Length
        self.assertEqual(klv[3:], b"Test")    # Value

    def test_encode_raw(self):
        """Test encoding raw bytes."""
        klv = KLVEncoder.encode_dp(4, DataType.RAW, bytes([0xFF, 0x00, 0x00]))
        self.assertEqual(klv.hex(), "040003ff0000")

    def test_encode_multi_dp(self):
        """Test encoding multiple DPs."""
        dps = [
            (1, DataType.BOOL, True),
            (2, DataType.VALUE, 200),
        ]
        klv = KLVEncoder.encode_multi_dp(dps)
        self.assertEqual(klv.hex(), "01010101020201c8")

    def test_decode_single_dp(self):
        """Test decoding single DP."""
        data = bytes([0x01, 0x01, 0x01, 0x01])  # Power ON
        result = KLVEncoder.decode(data)
        self.assertEqual(len(result), 1)
        dp_id, dp_type, value = result[0]
        self.assertEqual(dp_id, 1)
        self.assertEqual(dp_type, DataType.BOOL)
        self.assertEqual(value, b'\x01')

    def test_decode_multi_dp(self):
        """Test decoding multiple DPs."""
        data = bytes([
            0x01, 0x01, 0x01, 0x01,  # Power ON
            0x02, 0x02, 0x01, 0xC8,  # Brightness 200
        ])
        result = KLVEncoder.decode(data)
        self.assertEqual(len(result), 2)

    def test_decode_value_bool(self):
        """Test decoding boolean value."""
        value = KLVEncoder.decode_value(DataType.BOOL, b'\x01')
        self.assertEqual(value, True)

        value = KLVEncoder.decode_value(DataType.BOOL, b'\x00')
        self.assertEqual(value, False)

    def test_decode_value_int(self):
        """Test decoding integer value."""
        value = KLVEncoder.decode_value(DataType.VALUE, b'\x7f')
        self.assertEqual(value, 127)

        value = KLVEncoder.decode_value(DataType.VALUE, bytes([0x0F, 0xA0]))
        self.assertEqual(value, 4000)


class TestCommandBuilder(unittest.TestCase):
    """Test command building."""

    def test_build_power_on(self):
        """Test power ON command."""
        cmd = CommandBuilder.build_power_command(True)
        self.assertEqual(cmd.hex(), "01010101")

    def test_build_power_off(self):
        """Test power OFF command."""
        cmd = CommandBuilder.build_power_command(False)
        self.assertEqual(cmd.hex(), "01010100")

    def test_build_power_with_prefix(self):
        """Test power command with session prefix."""
        cmd = CommandBuilder.build_power_command(True, prefix=0xF0)
        self.assertEqual(cmd[:2], bytes([0xF0, 0xC0]))  # Prefix + marker
        self.assertEqual(cmd[2:].hex(), "01010101")    # DP data

    def test_build_brightness(self):
        """Test brightness command."""
        cmd = CommandBuilder.build_brightness_command(127)
        self.assertEqual(cmd.hex(), "0202017f")

    def test_build_brightness_percent_50(self):
        """Test 50% brightness."""
        cmd = CommandBuilder.build_brightness_percent_command(50)
        # 50% of 255 = 127 (0x7F)
        self.assertEqual(cmd[3], 127)

    def test_build_brightness_percent_100(self):
        """Test 100% brightness."""
        cmd = CommandBuilder.build_brightness_percent_command(100)
        self.assertEqual(cmd[3], 255)

    def test_build_color_temp_warm(self):
        """Test warm white color temperature."""
        cmd = CommandBuilder.build_color_temp_command(2700)
        self.assertEqual(cmd[0], DataPointID.COLOR_TEMP)
        self.assertEqual(cmd[1], DataType.VALUE)

    def test_build_color_temp_cool(self):
        """Test cool white color temperature."""
        cmd = CommandBuilder.build_color_temp_command(6500)
        self.assertEqual(cmd[0], DataPointID.COLOR_TEMP)

    def test_build_color_temp_invalid(self):
        """Test invalid color temperature."""
        with self.assertRaises(ValueError):
            CommandBuilder.build_color_temp_command(1000)  # Too low

        with self.assertRaises(ValueError):
            CommandBuilder.build_color_temp_command(10000)  # Too high

    def test_build_color_rgb(self):
        """Test RGB color command."""
        cmd = CommandBuilder.build_color_rgb_command(255, 0, 0)  # Red
        self.assertEqual(cmd[0], DataPointID.COLOR_RGB)
        self.assertEqual(cmd[1], DataType.RAW)
        self.assertEqual(cmd[3:], bytes([255, 0, 0]))

    def test_build_multi_dp(self):
        """Test multi-DP command."""
        dps = [
            (1, DataType.BOOL, True),
            (2, DataType.VALUE, 200),
        ]
        cmd = CommandBuilder.build_multi_dp_command(dps, prefix=0xF0)
        self.assertEqual(cmd[:2], bytes([0xF0, 0xC0]))


class TestAESCrypto(unittest.TestCase):
    """Test AES encryption/decryption."""

    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        key = b'0123456789ABCDEF'  # 16-byte key
        crypto = AESCrypto(key)

        plaintext = b'Hello, World!'
        encrypted = crypto.encrypt(plaintext)
        decrypted = crypto.decrypt(encrypted)

        self.assertEqual(decrypted, plaintext)
        self.assertNotEqual(encrypted, plaintext)

    def test_set_key(self):
        """Test setting key after initialization."""
        crypto = AESCrypto()

        # Should fail without key
        with self.assertRaises(ValueError):
            crypto.encrypt(b'test')

        # Set key and try again
        crypto.set_key(b'0123456789ABCDEF')
        encrypted = crypto.encrypt(b'test')
        self.assertIsNotNone(encrypted)

    def test_invalid_key_length(self):
        """Test invalid key length."""
        with self.assertRaises(ValueError):
            AESCrypto(b'short')  # Too short

    def test_null_crypto(self):
        """Test null crypto (passthrough)."""
        crypto = NullCrypto()

        data = b'test data'
        encrypted = crypto.encrypt(data)
        decrypted = crypto.decrypt(encrypted)

        self.assertEqual(encrypted, data)
        self.assertEqual(decrypted, data)


def run_tests():
    """Run all tests and print results."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestMeshProtocol))
    suite.addTests(loader.loadTestsFromTestCase(TestKLVEncoder))
    suite.addTests(loader.loadTestsFromTestCase(TestCommandBuilder))
    suite.addTests(loader.loadTestsFromTestCase(TestAESCrypto))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)
