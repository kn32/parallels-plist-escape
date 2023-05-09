import ctypes
import os
from ctypes import addressof, c_char
from pwn import *
from .structs import *
from .constants import *

class ToolgateClient:
    def __init__(self, device_path: str = '/proc/driver/prl_tg'):
        # It is important we use the os.* file functions because if we
        # use Python files, Python seems hang infinitely when writing to the
        # device.
        self.tg_fd = os.open(device_path, os.O_WRONLY)
        self.refs = []

    def submit(self, req) -> int:
        return os.write(self.tg_fd, p64(addressof(req)))
    
    def close(self) -> int:
        return os.close(self.tg_fd)
        
    def get_tg_buffer_from_data(self, 
            data: bytes, 
            data_len: int = None,
            writeable: bool = True) -> TG_BUFFER:
        buf = ctypes.create_string_buffer(data)
        self.refs.append(buf)
        if data_len is None:
            data_len = len(data)
        flags = 0
        if writeable:
            flags = 1
        tg_buf = TG_BUFFER(ctypes.addressof(buf), data_len, flags)
        return tg_buf
   
    def get_bytes_from_tg_buffer(self, buf: TG_BUFFER) -> bytes:
        return bytes((c_char * buf.ByteCount).from_address(buf.Address))

    def get_shared_folder_list(self) -> list[str]:
        share_names = []
        for i in range(1, 20):
            data1 = prlfs_sf_parameters(i, GET_SF_INFO, b'')
            buf1 = self.get_tg_buffer_from_data(bytes(data1))
            buf2 = self.get_tg_buffer_from_data(b'\0'*0x1000)
            req = create_tg_request_type(0, 2)(TG_REQUEST_FS_L_GETSFPARM, TG_STATUS_PENDING, 0, 2, 0, b'', (TG_BUFFER * 2)(buf1, buf2))
            self.submit(req)
            # response is prlfs_sf_response but it's easier to not use the ctypes struct here
            out = self.get_bytes_from_tg_buffer(buf2)[1:].strip(b'\x00').decode()
            if out == '':
                break
            share_names.append(out)
        return share_names
    