"""
GE Cync BLE Protocol Implementation

Python implementation of the Telink-based BLE mesh protocol used by GE Cync smart lights.
Based on reverse engineering of the Android APK (v6.20.0).
"""

from .mesh_protocol import MeshProtocol
from .klv_encoder import KLVEncoder, DataType
from .command_builder import CommandBuilder
from .aes_crypto import AESCrypto
from .telink_framing import TelinkFramer, KLVEncoder as TelinkKLV

__all__ = [
    'MeshProtocol',
    'KLVEncoder',
    'DataType',
    'CommandBuilder',
    'AESCrypto',
    'TelinkFramer',
    'TelinkKLV',
]

__version__ = '1.0.0'
