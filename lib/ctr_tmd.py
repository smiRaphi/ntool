from .common import *
from .keys import *
from .ctr_tik import signature_types
from .ctr_ncch import NCCHReader

class TMDHdr(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('issuer', c_char * 0x40),
        ('format_ver', c_uint8),
        ('ca_crl_ver', c_uint8),
        ('signer_crl_ver', c_uint8),
        ('reserved1', c_uint8),
        ('system_ver', c_uint64),
        ('titleID', c_uint8 * 8),
        ('title_type', c_uint32),
        ('groupID', c_uint16),
        ('save_data_size', c_uint32),
        ('priv_save_data_size', c_uint32),
        ('reserved2', c_uint32),
        ('twl_flag', c_uint8),
        ('reserved3', c_uint8 * 0x31),
        ('access_rights', c_uint32),
        ('title_ver', c_uint16),
        ('content_count', c_uint16),
        ('boot_content', c_uint16),
        ('reserved4', c_uint16),
        ('content_info_records_hash', c_uint8 * 32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class TMDContentInfoRecord(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('content_index_offset', c_uint16),
        ('content_command_count', c_uint16),
        ('content_chunk_record_hash', c_uint8 * 32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class TMDContentChunkRecord(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('contentID', c_uint32),
        ('content_index', c_uint16),
        ('content_type', c_uint16),
        ('content_size', c_uint64),
        ('content_hash', c_uint8 * 32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class TMDReader:
    def __init__(self, file, dev=0):
        self.file = file
        self.dev = dev

        with open(file, 'rb') as f:
            sig_type = readbe(f.read(4))
            self.sig = f.read(signature_types[sig_type][0])
            padding = f.read(signature_types[sig_type][1])
            self.hdr = TMDHdr(f.read(0xC4))
            self.titleID = hex(readbe(self.hdr.titleID))[2:].zfill(16)

            content_infos_all = b''
            content_infos = []
            for _ in range(0x40):
                content_info = f.read(0x24)
                content_infos_all += content_info
                if content_info != b'\0' * 0x24:
                    content_infos.append(TMDContentInfoRecord(content_info))
            self.content_infos_all = content_infos_all
            self.content_infos = content_infos

            content_chunks = []
            files = {}
            for _ in range(self.hdr.content_count):
                tmd_chunk = TMDContentChunkRecord(f.read(0x30))
                content_chunks.append(tmd_chunk)

                if tmd_chunk.content_index == 0 and self.titleID[3:5] == '48':
                    ext = 'nds'
                else:
                    ext = 'ncch'

                name = f'{hex(tmd_chunk.content_index)[2:].zfill(4)}.{hex(tmd_chunk.contentID)[2:].zfill(8)}.{ext}'
                files[name] = {
                    'size': tmd_chunk.content_size,
                    'crypt': 'none',
                    'hash': bytes(tmd_chunk.content_hash),
                }

                if tmd_chunk.content_type & 1: # Encrypted flag set in content type
                    files[name]['crypt'] = 'normal'
                    files[name]['key'] = b''
                    files[name]['iv'] = int.to_bytes(tmd_chunk.content_index, 2, 'big') + (b'\0' * 14)
            self.content_chunks = content_chunks
            self.files = files

    def verify(self, no_print=0): # 'no_print' parameter to facilitate CIAReader.verify()
        hash_check = []

        # Content info records hash in header
        h = hashlib.sha256()
        h.update(self.content_infos_all)
        hash_check.append(('TMD CntInfo', h.digest() == bytes(self.hdr.content_info_records_hash)))

        # Content chunk records hash in content info records
        hashed = []
        for i in self.content_infos:
            to_hash = b''
            for j in self.content_chunks[i.content_index_offset:i.content_index_offset + i.content_command_count]:
                to_hash += (bytes(j))
            h = hashlib.sha256()
            h.update(to_hash)
            hashed.append(h.digest() == bytes(i.content_chunk_record_hash))
        hash_check.append(('TMD CntChunk', all(hashed)))

        sig_check = []
        sig_check.append(('TMD Header', Crypto.verify_rsa_sha256(CTR.tmd_mod[self.dev], bytes(self.hdr), self.sig)))

        if no_print == 0:
            print("Hashes:")
            for i in hash_check:
                print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
            print('Signatures:')
            for i in sig_check:
                print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

        return (hash_check, sig_check)

    def __str__(self):
        contents = ''
        for i in self.content_chunks:
            contents += f' > {hex(i.content_index)[2:].zfill(4)}\n'
            cid = f'   Content ID:     {hex(i.contentID)[2:].zfill(8)}'
            if i.content_type & 1:
                cid += f' [encrypted]'
            if i.content_type & 0x4000:
                cid += f' [optional]'
            contents += f'{cid}\n'
            contents += f'   Content size:   {i.content_size}\n'
            contents += f'   Content hash:   {hex(readbe(bytes(i.content_hash)))[2:]}\n'
        contents = contents[:-1] # Remove last '\n'

        return (
            f'TitleID:           {self.titleID}\n'
            f'Title version:     {self.hdr.title_ver}\n'
            f'Contents:\n'
            f'{contents}'
        )

class TMDBuilder:
    def __init__(self, tmd='', content_files=[], content_files_dev=0, titleID='', title_ver=-1, save_data_size='', priv_save_data_size='', twl_flag='', crypt=1, regen_sig='', out='tmd_new'):
        '''
        tmd: path to TMD (if available)
        Following parameters are required if no TMD is provided:
            - content_files: list containing filenames of content files, which must each be named '[content index in hex, 4 chars].[contentID in hex, 8 chars].[ncch/nds]'
            - content_files_dev: 0 or 1 (whether content files are dev-crypted)
        Following parameters are required if no TMD is provided; if both TMD and parameter is supplied, the parameter overrides the TMD
            - titleID: titleID in hex, e.g. '000400000FF3FF00'
            - title_ver: title version in decimal
            - save_data_size (leave blank for auto)
            - priv_save_data_size (leave blank for auto)
            - twl_flag (leave blank for auto)
            - crypt: 0 or 1
        regen_sig: '' or 'retail' (test keys) or 'dev'
        out: path to output file
        '''

        # Checks
        if titleID != '':
           if not all([i in string.hexdigits for i in titleID]) or len(titleID) != 16:
                raise Exception('Invalid TitleID')

        # Defaults
        if tmd == '':
            if regen_sig == '':
                regen_sig = 'retail'

            if content_files[0].endswith('.nds'): # Get public and private savedata size from TWL header
                with open(content_files[0], 'rb') as f:
                    f.seek(0x238)
                    if save_data_size == '' or priv_save_data_size == '':
                        save_data_size = readbe(f.read(4))
                        priv_save_data_size = readbe(f.read(4))
                    f.seek(0x1BF)
                    if twl_flag == '':
                        twl_flag = (readbe(f.read(1)) & 6) >> 1
            else:
                if save_data_size == '':
                    ncch = NCCHReader(content_files[0], dev=content_files_dev)
                    if 'exheader.bin' in ncch.files.keys(): # If exheader exists, read savedata size from it. Otherwise, savedata size is set to 0
                        info = ncch.files['exheader.bin']
                        with open(content_files[0], 'rb') as f:
                            f.seek(info['offset'])
                            if ncch.is_decrypted:
                                exheader = f.read(info['size'])
                            else:
                                counter = Counter.new(128, initial_value=readbe(info['counter']))
                                cipher = AES.new(info['key'], AES.MODE_CTR, counter=counter)
                                exheader = cipher.decrypt(f.read(info['size']))
                        save_data_size = readbe(exheader[0x1C0:0x1C4])

        # Create (or modify) TMD header
        if tmd == '':
            content_files.sort(key=lambda h: int(h.split('.')[0], 16)) # Sort list of content files by content index (since that is how content chunk records are ordered)

            hdr = TMDHdr(b'\x00' * 0xC4)
            hdr.format_ver = 1
            hdr.title_type = 0x40
            hdr.content_count = len(content_files)
        else:
            with open(tmd, 'rb') as f:
                sig_type = readbe(f.read(4))
                sig = f.read(signature_types[sig_type][0])
                padding = f.read(signature_types[sig_type][1])
                hdr = TMDHdr(f.read(0xC4))
                content_infos_all = f.read(0x900)
                content_chunks_all = f.read(0x30 * hdr.content_count)

        if tmd == '' or regen_sig != '':
            hdr.issuer = b'Root-CA00000003-CP0000000b'
            if regen_sig == 'dev':
                hdr.issuer = b'Root-CA00000004-CP0000000a'

        if titleID != '':
            titleID_bytes = int.to_bytes((int(titleID, 16)), 8, 'big')
            hdr.titleID = (c_uint8 * sizeof(hdr.titleID))(*titleID_bytes)

        if title_ver != -1:
            hdr.title_ver = title_ver

        if save_data_size != '':
            hdr.save_data_size = save_data_size

        if priv_save_data_size != '':
            hdr.priv_save_data_size = priv_save_data_size

        if twl_flag != '':
            hdr.twl_flag = twl_flag

        # Create (or modify) content chunk records
        content_chunks = b''
        if tmd == '':
            for i in range(len(content_files)):
                tmd_chunk = TMDContentChunkRecord(b'\x00' * 0x30)

                # Get content index and contentID from file name
                name = content_files[i].split('.')
                tmd_chunk.content_index = int(name[0], 16)
                tmd_chunk.contentID = int(name[1], 16)

                if crypt:
                    tmd_chunk.content_type |= 1
                if titleID[3:8].lower() == '4008c' and i >= 1:
                    tmd_chunk.content_type |= 0x4000 # Set Optional flag

                # Calculate hashes
                f = open(content_files[i], 'rb')
                tmd_chunk.content_size = os.path.getsize(content_files[i])
                hashed = Crypto.sha256(f, tmd_chunk.content_size)
                tmd_chunk.content_hash = (c_uint8 * sizeof(tmd_chunk.content_hash))(*hashed)
                f.close()

                content_chunks += bytes(tmd_chunk)
        else:
            for i in range(hdr.content_count):
                tmd_chunk = TMDContentChunkRecord(content_chunks_all[i * 0x30:(i + 1) * 0x30])

                tmd_chunk.content_type &= ~1 # Reset flags
                if crypt:
                    tmd_chunk.content_type |= 1

                content_chunks += bytes(tmd_chunk)

        # Create content info records
        content_info = TMDContentInfoRecord(b'\x00' * 0x24)
        content_info.content_command_count = hdr.content_count
        h = hashlib.sha256()
        h.update(content_chunks)
        hashed = h.digest()
        content_info.content_chunk_record_hash = (c_uint8 * sizeof(content_info.content_chunk_record_hash))(*hashed)
        content_infos = bytes(content_info) + (b'\x00' * 0x24 * 0x3F) # Only fill first content info record

        # Finalise header
        h = hashlib.sha256()
        h.update(content_infos)
        hashed = h.digest()
        hdr.content_info_records_hash = (c_uint8 * sizeof(hdr.content_info_records_hash))(*hashed)

        if regen_sig == 'retail':
            sig = Crypto.sign_rsa_sha256(CTR.test_mod, CTR.test_priv, bytes(hdr))
        elif regen_sig == 'dev':
            sig = Crypto.sign_rsa_sha256(CTR.tmd_mod[1], CTR.tmd_priv[1], bytes(hdr))

        # Write TMD
        with open(f'{out}', 'wb') as f:
            f.write(int.to_bytes(0x00010004, 4, 'big'))
            f.write(sig)
            f.write(b'\x00' * 0x3C)
            f.write(bytes(hdr))
            f.write(content_infos)
            f.write(content_chunks)

        print(f'Wrote to {out}')
