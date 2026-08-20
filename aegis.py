import ctypes
import os
from typing import Optional

class AegisCore:
    def __init__(self, dll_path: str = r"F:\AEGIS\aegis-core\target\release\aegis_core.dll"):
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"DLL introuvable : {dll_path}")
        
        self.dll = ctypes.CDLL(dll_path)
        
        # Declarations FFI
        self.dll.aegis_generate_mnemonic.restype = ctypes.c_void_p
        self.dll.aegis_generate_mnemonic.argtypes = []
        
        self.dll.aegis_derive_identity_hash.restype = ctypes.c_void_p
        self.dll.aegis_derive_identity_hash.argtypes = [ctypes.c_char_p]
        
        self.dll.aegis_encrypt_message.restype = ctypes.c_void_p
        self.dll.aegis_encrypt_message.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        
        self.dll.aegis_decrypt_message.restype = ctypes.c_void_p
        self.dll.aegis_decrypt_message.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

        self.dll.aegis_emergency_purge.restype = ctypes.c_int
        self.dll.aegis_emergency_purge.argtypes = []

        self.dll.aegis_stegano_hide.restype = ctypes.c_void_p
        self.dll.aegis_stegano_hide.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

        self.dll.aegis_stegano_extract.restype = ctypes.c_void_p
        self.dll.aegis_stegano_extract.argtypes = [ctypes.c_char_p]

        self.dll.aegis_free_string.restype = None
        self.dll.aegis_free_string.argtypes = [ctypes.c_void_p]

    def generate_mnemonic(self) -> Optional[str]:
        ptr = self.dll.aegis_generate_mnemonic()
        if not ptr: return None
        try:
            val = ctypes.cast(ptr, ctypes.c_char_p).value
            return val.decode('utf-8') if val else None
        finally:
            self.dll.aegis_free_string(ptr)

    def derive_identity_hash(self, mnemonic: str) -> Optional[str]:
        ptr = self.dll.aegis_derive_identity_hash(mnemonic.encode('utf-8'))
        if not ptr: return None
        try:
            val = ctypes.cast(ptr, ctypes.c_char_p).value
            return val.decode('utf-8') if val else None
        finally:
            self.dll.aegis_free_string(ptr)

    def encrypt_message(self, shared_secret: str, message: str) -> Optional[str]:
        ptr = self.dll.aegis_encrypt_message(shared_secret.encode('utf-8'), message.encode('utf-8'))
        if not ptr: return None
        try:
            val = ctypes.cast(ptr, ctypes.c_char_p).value
            return val.decode('utf-8') if val else None
        finally:
            self.dll.aegis_free_string(ptr)

    def decrypt_message(self, shared_secret: str, hex_payload: str) -> Optional[str]:
        ptr = self.dll.aegis_decrypt_message(shared_secret.encode('utf-8'), hex_payload.encode('utf-8'))
        if not ptr: return None
        try:
            val = ctypes.cast(ptr, ctypes.c_char_p).value
            return val.decode('utf-8') if val else None
        finally:
            self.dll.aegis_free_string(ptr)

    def emergency_purge(self) -> bool:
        return self.dll.aegis_emergency_purge() == 1

    def stegano_hide(self, secret: str, cover: str) -> Optional[str]:
        ptr = self.dll.aegis_stegano_hide(secret.encode('utf-8'), cover.encode('utf-8'))
        if not ptr: return None
        try:
            val = ctypes.cast(ptr, ctypes.c_char_p).value
            return val.decode('utf-8') if val else None
        finally:
            self.dll.aegis_free_string(ptr)

    def stegano_extract(self, stego_text: str) -> Optional[str]:
        ptr = self.dll.aegis_stegano_extract(stego_text.encode('utf-8'))
        if not ptr: return None
        try:
            val = ctypes.cast(ptr, ctypes.c_char_p).value
            return val.decode('utf-8') if val else None
        finally:
            self.dll.aegis_free_string(ptr)