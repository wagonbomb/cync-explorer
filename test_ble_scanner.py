"""
Test Suite for Cync BLE Scanner
Tests utility functions and mocks BLE scanning behavior.
"""

import unittest
import os
import json
import tempfile
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import asyncio

# Import functions to test
from ble_scanner import (
    normalize_mac,
    format_mac,
    is_ge_device,
    get_oui_info,
    DeviceLogger,
    GE_MAC_PREFIXES
)


class TestMacFunctions(unittest.TestCase):
    """Tests for MAC address utility functions."""
    
    def test_normalize_mac_with_colons(self):
        """Test normalizing MAC with colons."""
        result = normalize_mac("34:13:43:46:CA:85")
        self.assertEqual(result, "34134346CA85")
    
    def test_normalize_mac_with_dashes(self):
        """Test normalizing MAC with dashes."""
        result = normalize_mac("34-13-43-46-ca-85")
        self.assertEqual(result, "34134346CA85")
    
    def test_normalize_mac_already_normalized(self):
        """Test normalizing already normalized MAC."""
        result = normalize_mac("34134346CA85")
        self.assertEqual(result, "34134346CA85")
    
    def test_normalize_mac_lowercase(self):
        """Test that lowercase is converted to uppercase."""
        result = normalize_mac("34:13:43:46:ca:85")
        self.assertEqual(result, "34134346CA85")
    
    def test_format_mac_from_raw(self):
        """Test formatting raw MAC to colon format."""
        result = format_mac("34134346CA85")
        self.assertEqual(result, "34:13:43:46:CA:85")
    
    def test_format_mac_from_dashes(self):
        """Test formatting dashed MAC to colon format."""
        result = format_mac("34-13-43-46-CA-85")
        self.assertEqual(result, "34:13:43:46:CA:85")
    
    def test_format_mac_idempotent(self):
        """Test that formatting already formatted MAC works."""
        result = format_mac("34:13:43:46:CA:85")
        self.assertEqual(result, "34:13:43:46:CA:85")


class TestGEDeviceDetection(unittest.TestCase):
    """Tests for GE device detection."""
    
    def test_is_ge_device_341343_prefix(self):
        """Test detection of 34:13:43 prefix."""
        self.assertTrue(is_ge_device("34:13:43:46:CA:85"))
        self.assertTrue(is_ge_device("34-13-43-46-ca-85"))
        self.assertTrue(is_ge_device("34134346CA85"))
    
    def test_is_ge_device_786deb_prefix(self):
        """Test detection of 78:6D:EB prefix."""
        self.assertTrue(is_ge_device("78:6D:EB:4C:EF:15"))
        self.assertTrue(is_ge_device("78-6d-eb-4c-ef-15"))
        self.assertTrue(is_ge_device("786DEB4CEF15"))
    
    def test_is_ge_device_non_ge(self):
        """Test non-GE devices return False."""
        self.assertFalse(is_ge_device("AA:BB:CC:DD:EE:FF"))
        self.assertFalse(is_ge_device("00:11:22:33:44:55"))
    
    def test_ge_mac_prefixes_defined(self):
        """Test that expected prefixes are defined."""
        self.assertIn("341343", GE_MAC_PREFIXES)
        self.assertIn("786DEB", GE_MAC_PREFIXES)


class TestOUILookup(unittest.TestCase):
    """Tests for OUI manufacturer lookup."""
    
    def test_oui_ge_341343(self):
        """Test GE OUI lookup for 34:13:43."""
        result = get_oui_info("34:13:43:00:00:00")
        self.assertIn("GE", result)
        self.assertIn("Cync", result)
    
    def test_oui_ge_786deb(self):
        """Test GE OUI lookup for 78:6D:EB."""
        result = get_oui_info("78:6D:EB:00:00:00")
        self.assertIn("GE", result)
        self.assertIn("Cync", result)
    
    def test_oui_unknown(self):
        """Test unknown OUI returns appropriate message."""
        result = get_oui_info("AA:BB:CC:DD:EE:FF")
        self.assertIn("Unknown", result)
        self.assertIn("AABBCC", result)


class TestDeviceLogger(unittest.TestCase):
    """Tests for the DeviceLogger class."""
    
    def setUp(self):
        """Create a temporary directory for log files."""
        self.temp_dir = tempfile.mkdtemp()
        self.logger = DeviceLogger(self.temp_dir)
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_logger_creates_log_file(self):
        """Test that logger creates text log file."""
        log_file, _ = self.logger.get_log_paths()
        self.assertTrue(os.path.exists(log_file))
    
    def test_logger_log_writes_to_file(self):
        """Test that log() writes to file."""
        self.logger.log("Test message")
        log_file, _ = self.logger.get_log_paths()
        
        with open(log_file, 'r') as f:
            content = f.read()
        
        self.assertIn("Test message", content)
    
    def test_logger_add_device_creates_json(self):
        """Test that add_device creates JSON file."""
        device_info = {
            "address": "34:13:43:46:CA:85",
            "is_ge": True,
            "test": "data"
        }
        self.logger.add_device(device_info)
        
        _, json_file = self.logger.get_log_paths()
        self.assertTrue(os.path.exists(json_file))
        
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["address"], "34:13:43:46:CA:85")
    
    def test_logger_multiple_devices(self):
        """Test logging multiple devices."""
        self.logger.add_device({"address": "11:11:11:11:11:11"})
        self.logger.add_device({"address": "22:22:22:22:22:22"})
        self.logger.add_device({"address": "33:33:33:33:33:33"})
        
        _, json_file = self.logger.get_log_paths()
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(len(data), 3)


class TestMockedBLEScanning(unittest.TestCase):
    """Tests using mocked BLE components."""
    
    def test_mock_advertisement_data_parsing(self):
        """Test that we correctly parse mock advertisement data."""
        # Create mock advertisement data
        mock_adv = Mock()
        mock_adv.local_name = "Test Light"
        mock_adv.rssi = -65
        mock_adv.service_uuids = ["0000fee9-0000-1000-8000-00805f9b34fb"]
        mock_adv.manufacturer_data = {0x004C: bytes([0x02, 0x15, 0x01])}
        mock_adv.service_data = {}
        mock_adv.tx_power = -10
        
        # Simulate parsing as done in deep_scan_device
        adv_info = {
            "local_name": mock_adv.local_name,
            "rssi": mock_adv.rssi,
            "service_uuids": list(mock_adv.service_uuids),
            "manufacturer_data": {
                str(k): v.hex() for k, v in mock_adv.manufacturer_data.items()
            },
            "tx_power": mock_adv.tx_power
        }
        
        self.assertEqual(adv_info["local_name"], "Test Light")
        self.assertEqual(adv_info["rssi"], -65)
        self.assertEqual(len(adv_info["service_uuids"]), 1)
        self.assertIn("76", adv_info["manufacturer_data"])  # 0x004C = 76


class TestEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""
    
    def test_empty_mac(self):
        """Test handling of empty MAC."""
        result = normalize_mac("")
        self.assertEqual(result, "")
    
    def test_partial_mac(self):
        """Test handling of partial MAC."""
        result = normalize_mac("34:13:43")
        self.assertEqual(result, "341343")
    
    def test_is_ge_device_short_mac(self):
        """Test is_ge_device with short MAC."""
        # Should still work if prefix matches
        self.assertTrue(is_ge_device("341343"))


def run_tests():
    """Run all tests and return results."""
    # Create a test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestMacFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestGEDeviceDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestOUILookup))
    suite.addTests(loader.loadTestsFromTestCase(TestDeviceLogger))
    suite.addTests(loader.loadTestsFromTestCase(TestMockedBLEScanning))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    print("=" * 70)
    print("CYNC BLE SCANNER TEST SUITE")
    print("=" * 70)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print()
    
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED!")
    else:
        print("❌ SOME TESTS FAILED")
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback[:100]}...")
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"  - {test}: {traceback[:100]}...")
