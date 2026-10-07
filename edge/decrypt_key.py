import ctypes
import os
import sys

lib = ctypes.CDLL("libcrypto.so.3")
lib.BIO_new_mem_buf.restype = ctypes.c_void_p
lib.BIO_new_mem_buf.argtypes = [ctypes.c_char_p, ctypes.c_int]
lib.BIO_s_mem.restype = ctypes.c_void_p
lib.BIO_new.restype = ctypes.c_void_p
lib.BIO_new.argtypes = [ctypes.c_void_p]
lib.BIO_ctrl.restype = ctypes.c_long
lib.BIO_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
lib.PEM_read_bio_PrivateKey.restype = ctypes.c_void_p
lib.PEM_read_bio_PrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p]
lib.PEM_write_bio_PKCS8PrivateKey.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
BIO_CTRL_INFO = 3

encrypted = sys.stdin.buffer.read()
passphrase = os.environ["EDGE_KEY_PASSPHRASE"].encode()
pkey = lib.PEM_read_bio_PrivateKey(lib.BIO_new_mem_buf(encrypted, len(encrypted)), None, None, passphrase)
if not pkey:
    sys.exit("cannot decrypt the exported private key")
out = lib.BIO_new(lib.BIO_s_mem())
if lib.PEM_write_bio_PKCS8PrivateKey(out, pkey, None, None, 0, None, None) != 1:
    sys.exit("cannot write the private key")
data = ctypes.c_char_p()
size = lib.BIO_ctrl(out, BIO_CTRL_INFO, 0, ctypes.byref(data))
sys.stdout.buffer.write(ctypes.string_at(data, size))
