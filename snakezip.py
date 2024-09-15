import struct
import sys
import binascii
import zlib
import os
import argparse
import logging
from watchDir import getDirSize
import math
import json



CHUNKSIZE=64*1024**2 # Allowed Buffer Size

logging.basicConfig(level=logging.INFO, format='%(message)s')
__description__ = '''Snakezip. Extract large zip files in space limited areas. '''
parser = argparse.ArgumentParser(description=__description__)
parser.add_argument('input_zipfile', type=str, help='Input zip file name')
parser.add_argument('extract_under_name', type=str, help='Output file name')


colors = {
    'red': "\033[31m",
    'green': "\033[32m",
    'yellow': "\033[33m",
    'reset': "\033[0m"
}

def colorText(*args, color="red"):
    return colors[color] + ''.join(map(str, args)) + colors['reset']

def roundFloat2Digits(x):
    return f"{x:.2f}"

def paddInteger7(x):
    return f"{x:07}"

def byteSerializer(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    else:
        return obj

def checksumCRC32(filePath):
    '''
    Calculates CRC32 Checksum Of File
    Params:
        - filePath: *str Input File Path()
    Returns:
        - *string, Checksum Of File
    '''
    checksum = 0
    with open(filePath, 'rb') as f:
        while True:
            chunk = f.read(CHUNKSIZE)
            if not chunk:
                break
            checksum = zlib.crc32(chunk, checksum)
    return checksum


def findCentralDirectory(file):
    '''
    Finds Offset Of End Central Directory(s)
    Params:
        - file: Input fileio object.
    Return:
        - *int, Starting offset of central directory
    '''
    eocd_signature = b'\x50\x4b\x05\x06'
    file.seek(-22, 2)
    while True:
        h = file.read(4)
        if not h:
            logging.error("[!] Error -02: EOCD signature cannot be found. Make sure file is not corrupt.")
            sys.exit(-2)
        if h == eocd_signature:
            return file.tell()


def readCentralDirectory(file, endCdOffset, all=False, zip64=False):
    '''
    Extracts Central Directory Metadata
    Params:
        - file: *file.io Input file.
        - endCdOffset: *int End Of Central Directory Offset
        - All?: *bool Extract all info
    Return:
        - *dict, Central Directory Metadata Object
    '''
    # Extract Central Directory Headers
    file.seek(endCdOffset)
    res = {}
    
    # End Of Central Directory

    #64 Bit
    #======
    '''    res['eocd_size'] = int.from_bytes(file.read(8), 'little')
    res['version'] = int.from_bytes(file.read(2), 'little')
    res['min_version'] = int.from_bytes(file.read(2), 'little')
    res['disc_number'] = int.from_bytes(file.read(4), 'little')
    res['cd_start_disc'] = int.from_bytes(file.read(4), 'little')
    res['n_cd_on_disc'] = int.from_bytes(file.read(8), 'little')
    res['n_c_total'] = int.from_bytes(file.read(8), 'little')
    res['cd_size'] = int.from_bytes(file.read(8), 'little')
    res['cd_offset'] = int.from_bytes(file.read(8), 'little')
    res['comment_len'] = int.from_bytes(file.read(2), 'little')'''
    
    res['disc_number'] = int.from_bytes(file.read(2), 'little')
    res['cd_start_disc'] = int.from_bytes(file.read(2), 'little')
    res['n_cd_on_disc'] = int.from_bytes(file.read(2), 'little')
    res['n_c_total'] = int.from_bytes(file.read(2), 'little')
    res['cd_size'] = int.from_bytes(file.read(4), 'little')
    res['cd_offset'] = int.from_bytes(file.read(4), 'little')
    res['comment_len'] = int.from_bytes(file.read(2), 'little')
    
    #print(res)
    #sys.exit()
    
    '''
    
    '''    
    

    # Files Specific
    file.seek(res['cd_offset'])
    res['signature'] = binascii.hexlify(file.read(4)).decode("utf-8")
    res['version'] = struct.unpack('<H', file.read(2))[0]
    res['min_ver'] = struct.unpack('<H', file.read(2))[0]
    res['bit_flag'] = struct.unpack('<H', file.read(2))[0]
    res['compression_method'] = struct.unpack('<H', file.read(2))[0]
    res['f_last_modif_time'] = struct.unpack('<H', file.read(2))[0]
    res['f_last_modif_date'] = struct.unpack('<H', file.read(2))[0]
    res['crc_32'] = struct.unpack('<I', file.read(4))[0]
    res['compressed_size'] = struct.unpack('<I', file.read(4))[0]
    res['uncompressed_size'] = struct.unpack('<I', file.read(4))[0]
    res['f_name_length'] = struct.unpack('<H', file.read(2))[0]
    res['extra_field_length'] = struct.unpack('<H', file.read(2))[0]
    res['file_comment_length'] = struct.unpack('<H', file.read(2))[0]
    res['disc_n_file_start'] = struct.unpack('<H', file.read(2))[0]
    res['intern_file_attr'] = struct.unpack('<H', file.read(2))[0]
    res['extern_file_attr'] = struct.unpack('<I', file.read(4))[0]
    res['file_header_offset'] = struct.unpack('<I', file.read(4))[0]
    
    #return res
    res['file_name'] = struct.unpack(f'{res["f_name_length"]}s', file.read(res['f_name_length']))[0].decode()
    res['extra_field'] = struct.unpack(f'{res["extra_field_length"]}s', file.read(res['extra_field_length']))[0]
    res['file_comment'] = struct.unpack(f'{res["file_comment_length"]}s', file.read(res["file_comment_length"]))[0].decode()

    # File Header
    file.seek(res['file_header_offset'])
    res['LFH_signature'] = struct.unpack('<I', file.read(4))[0]
    res['LFH_ver_min'] = struct.unpack('<H', file.read(2))[0]
    res['LFG_bit_flag'] = struct.unpack('<H', file.read(2))[0]
    res['LFG_compress_method'] = struct.unpack('<H', file.read(2))[0]
    res['LFG_file_last_modif_t'] = struct.unpack('<H', file.read(2))[0]
    res['LFG_file_last_modif_d'] = struct.unpack('<H', file.read(2))[0]
    res['LFG_crc32'] = struct.unpack('<I', file.read(4))[0]
    res['LFG_size_compressed'] = struct.unpack('<I', file.read(4))[0]
    res['LFG_size_uncompressed'] = struct.unpack('<I', file.read(4))[0]
    res['LFG_filename_length'] = struct.unpack('<H', file.read(2))[0]
    res['LFH_extrafield_length'] = struct.unpack('<H', file.read(2))[0]
    res['LFH_filename'] = struct.unpack(f'{res["LFG_filename_length"]}s', file.read(res["LFG_filename_length"]))[0].decode()
    res['LFH_extrafield'] = struct.unpack(f'{res["LFH_extrafield_length"]}s', file.read(res["LFH_extrafield_length"]))[0]


    res['rawfile_offset'] = file.tell()
    res['rawfile_size'] = res['compressed_size']

    return res if all else {'file_offset': res['rawfile_offset'], 'file_size': res['rawfile_size'], 'crc_32': res['crc_32']}


def findOffset(zip_path):
    """Extract file header attributes and data offsets from a ZIP file without using zipfile library.

    Args:
        zip_path (str): Path to the ZIP file.

    Returns:
        list of dict: A list of dictionaries, each containing file header attributes and data offset.
    """
    headers = []

    with open(zip_path, 'rb') as file:
        # Read local file header signature (0x04034b50)
        signature = struct.unpack('<I', file.read( 4))[0]
        if signature == 0x04034b50:
            pass
        elif signature == 0x05054b50:
            pass
        else:
            logging.error("Local File Header Signature can't be not found.")
            sys.exit(-1)
        
        # Read local file header fields
        version_needed = struct.unpack('<H', file.read( 2))[0]
        flag_bits = struct.unpack('<H', file.read( 2))[0]
        compression_method = struct.unpack('<H', file.read( 2))[0]
        last_mod_file_time = struct.unpack('<H', file.read( 2))[0]
        last_mod_file_date = struct.unpack('<H', file.read( 2))[0]
        crc32 = struct.unpack('<I', file.read( 4))[0]
        compressed_size_b = file.read(4)#struct.unpack('<I', file.read( 4))[0]
        uncompressed_size_b = file.read(4)#struct.unpack('<I', file.read( 4))[0]
        file_name_length = struct.unpack('<H', file.read( 2))[0]
        extra_field_length = struct.unpack('<H', file.read( 2))[0]

        # Read file name
        file_name = file.read( file_name_length).decode('utf-8')

        # Read extra field
        extra_field = file.read( extra_field_length)

        # Record the current file offset
        file_offset = file.tell()

        # Zip64 case
        if uncompressed_size_b == b'\xff\xff\xff\xff' or  compressed_size_b == b'\xff\xff\xff\xff':
            stripped_extra_field = extra_field[extra_field.find(b'\x01\x00\x10\x00'):]
            uncompressed_size = struct.unpack('<Q', stripped_extra_field[4:12])[0]
            compressed_size = struct.unpack('<Q', stripped_extra_field[12:20])[0]
        else:
            uncompressed_size = struct.unpack('<I', uncompressed_size_b)[0]
            compressed_size = struct.unpack('<I', compressed_size_b)[0]

        # Look for signature in extra field for zip64 compressed and decompressed size values.

        # Read file data (not processed in this function)
        #file_data = file.read( compressed_size)
        # Append header information to the list
        headers.append({
            'filename': file_name,
            'version_needed': version_needed,
            'flag_bits': flag_bits,
            'compression_method': compression_method,
            'last_mod_file_time': last_mod_file_time,
            'last_mod_file_date': last_mod_file_date,
            'CRC': crc32,
            'compressed_size_hex': compressed_size,
            'uncompressed_size_hex': uncompressed_size,
            'file_name_length': file_name_length,
            'extra_field_length': extra_field_length,
            'extra_field': extra_field,
            'uncompressed_size': uncompressed_size,
            'compressed_size': compressed_size,
            'data_offset': file_offset,
        })
    

    return file_offset, headers[0]['compression_method'], headers[0]['compressed_size'], headers[0]['uncompressed_size'], headers[0]['CRC'], headers[0]['filename']

def extractCoreFile(inputFile):
    '''
    Extracts Core File From Zip And Overrides Original File
    Params: 
        - inputFile: *str, Input File
    '''
    offset, compression_method, size, decom_size, crc32, core_filename = findOffset(inputFile)
    
    logging.info(f"[i] Extracting Core File Started..")
    logging.info(f"\t* Core Filename     : `{colorText(core_filename, color='green')}`")
    logging.info(f"\t* Compressed Size   :  {colorText(size, ' Bytes', color='green')}")
    logging.info(f"\t* Decompressed Size :  {colorText(decom_size, ' Bytes', color='green')}")
    logging.info(f"\t* CRC32 Checksum    :  {colorText(crc32, color='green')}")
    logging.info(f"\t* Compression Method:  {colorText(compression_method, color='green')}")
    logging.info(f"\t* Compression Method:  {colorText(compression_method, color='green')}")

    logging.info("")

    if compression_method != 8:
        logging.error(f"[!] Compression method {compression_method} is not supported, Only Deflate (8) is supported.")
        sys.exit(-2)

    dest_cursor = 0
    source_cursor = offset
    n_copies = int(size / CHUNKSIZE)

    with open(inputFile, 'rb+') as f:
        for i in range(0, n_copies):
            f.seek(source_cursor)
            chunk = f.read(CHUNKSIZE)
            source_cursor = f.tell()
            # Override data to top
            f.seek(dest_cursor)
            f.write(chunk)
            dest_cursor = f.tell()
            logging.info(f"[~] Progress {colorText(int(i/n_copies*100),'%', color='red')}..  Resource Usage:  RAM: { colorText(paddInteger7(int(len(chunk)/(1024**2))),'MB', color='red')}  Disc: {colorText(roundFloat2Digits(getDirSize()/(1024**3)),'GB', color='red')}")
            if dest_cursor >= source_cursor:
                logging.error("ERROR: Snake beat it's tail!")
                sys.exit(-1)
        # Add leftovers
        f.seek(source_cursor)
        chunk = f.read(int(size)%CHUNKSIZE)
        f.seek(dest_cursor)
        f.write(chunk)
        # Remove excess
        f.truncate()
    logging.info("[i] Extraction finished.")
    return crc32



def safeDecompress(filename):
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    with open(filename, 'rb') as fi:
        with open(filename+'.output', 'wb') as fo:
            while True:
                chunk = fi.read(CHUNKSIZE)
                if not chunk:
                    break
                buff = decompressor.decompress(chunk)
                fo.write(buff)
            buff = decompressor.flush()
            fo.write(buff)


def snakeDecompress(filename):
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    f = open(filename, "rb+")
    fsize = os.path.getsize(filename)

    # Fileio cursors
    dest = 0
    source = 0

    # Data Stream implementation
    mem = b''
    crc32_checksum = 0
    while True:
        f.seek(source)
        buff = f.read(CHUNKSIZE)
        if not buff:
            break
        source += len(buff)
        mem += decompressor.decompress(buff)
        # Calc free space in file
        free = source - dest
        # Occupy it with compressed data from mem buffer
        f.seek(dest)
        part = mem[:free]
        f.write(part)
        crc32_checksum = zlib.crc32(part, crc32_checksum)
        mem = mem[free:]
        dest += len(part)
        # Logging
        logging.info(f"[~] Progress {colorText(int(dest/fsize*100),'%', color='red')}.. Resource Usage:   RAM: { colorText(paddInteger7(int(len(mem)/(1024**2))),'MB', color='red')}  Disc: {colorText(roundFloat2Digits(getDirSize()/(1024**3)),'GB', color='red')}")

    # Collect leftover data
    leftover = mem + decompressor.flush()
    f.seek(dest)  
    f.write(leftover)
    crc32_checksum = zlib.crc32(leftover, crc32_checksum)
    f.truncate()
    f.close()

    return crc32_checksum


if __name__ == "__main__":
    args = parser.parse_args()
    
    input_zipfile = args.input_zipfile
    extract_under_name = args.extract_under_name
    
    if not os.path.exists(input_zipfile):
        logging.error(f"Input zip file can't be found {input_zipfile}.")
        sys.exit(-1)

    fsize = os.path.getsize(input_zipfile)
    logging.info("[i] Resource optimized zip extraction started..")
    
    ideal_checksum = extractCoreFile(input_zipfile)
    os.rename(input_zipfile, extract_under_name)
    logging.info("\n[~] Decompression started..")
    real_checksum = snakeDecompress(extract_under_name)
    
    # Compare crc32 checksums
    if ideal_checksum != real_checksum:
        print(f'[!] Checksums dont match. Ideal: {ideal_checksum} Actual:{real_checksum}')
    else:
        print(f'\n[+] Checksum test passed.')
