from ctypes import (Structure, c_char, c_byte, c_uint, c_uint32, 
                    c_uint64, c_ushort, c_void_p)

class TG_BUFFER(Structure):
    _fields_ = [
        ("Address", c_void_p),
        ("ByteCount", c_uint),
        ("Writeable", c_uint), # top 30 bits are reserved
    ]

def create_tg_request_type(inline_data_len: int, num_buffers: int):
    """Utility for creating custom TG_REQUEST structure types."""
    class TG_REQUEST_CUSTOM(Structure):
        _fields_ = [
            ("Request", c_uint),
            ("Status", c_uint),
            ("InlineLen", c_ushort),
            ("BufferCount", c_ushort),
            ("Reserved", c_uint),
            ("inline_bytes", c_byte * inline_data_len),
            ("Buffers", TG_BUFFER * num_buffers),
        ]
        def __init__(
            self, 
            request, 
            status, 
            inline_len, 
            buf_count, 
            reserved, 
            inline_bytes, 
            buffers):
            # This is required because if we use c_char for inline_bytes 
            # and use a bytestring to initialise the c_char_Array, then 
            # ctypes will only initialise the array with data until a null byte, 
            # which is not what we want. Instead we use c_byte and add the below 
            # line. Couldn't find a cleaner way to do this.
            inline_bytes = (c_byte * inline_data_len).from_buffer_copy(inline_bytes)
            super().__init__(request, status, inline_len, buf_count, reserved, inline_bytes, buffers)

    return TG_REQUEST_CUSTOM

class prlfs_file_desc(Structure):
    _fields_ = [
        ("fd", c_uint64),
        ("offset", c_uint64),
        ("flags", c_uint32),
        ("sfid", c_uint32),
    ]

# Valid values for prlfs_sf_parameters id field
GET_SF_INFO = 0
GET_SF_ID_BY_NAME = 1
GET_SF_FEATURES = 2
class prlfs_sf_parameters(Structure):
    _fields_ = [
        ("index", c_uint),
        ("id", c_uint),
        ("locale", c_char * 40),
    ]

class prlfs_sf_response(Structure):
    _fields_ = [
        ("ret", c_uint),
        ("buf", c_char * 4095),
    ]
