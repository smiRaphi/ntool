from .common import *
from .keys import *
from .ctr_ncch import NCCHReader, NCCHBuilder
from .ctr_cia import CIAReader
from .ctr_romfs import RomFSReader

media_unit = 0x200
KB = 1024
MB = 1 << 20
GB = 1 << 30

class CCIHdr(Structure): # 0x0 - 0x1FF
    _pack_ = 1

    _fields_ = [
        ('sig', c_uint8 * 0x100),
        ('magic', c_char * 4),
        ('ncsd_size', c_uint32),
        ('mediaID', c_uint8 * 8),
        ('partitions_fs_type', c_uint8 * 8),
        ('partitions_crypt_type', c_uint8 * 8),
        ('partitions_offset_size', c_uint8 * 64),
        ('exh_hash', c_uint8 * 32),
        ('exh_size', c_uint32),
        ('sector_0_offset', c_uint32),
        ('flags', c_uint8 * 8),
        ('partitionIDs', c_uint8 * 64),
        ('reserved', c_uint8 * 0x2E),
        ('crypt_type', c_uint8),
        ('backup_security_ver', c_uint8)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class CardInfo(Structure): # 0x200 - 0x2FF
    _pack_ = 1

    _fields_ = [
        ('writable_addr', c_uint32),
        ('reserved1', c_uint8 * 3),
        ('card_flags', c_uint8),
        ('reserved2', c_uint8 * 0xF8),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class MasteringInfo(Structure): # 0x300 - 0x3FF
    _pack_ = 1

    _fields_ = [
        ('media_size_used', c_uint32),
        ('reserved1', c_uint8 * 0xC),
        ('title_ver', c_uint16),
        ('card_rev', c_uint16),
        ('reserved2', c_uint8 * 0xC),
        ('cver_titleID', c_uint8 * 8),
        ('cver_title_ver', c_uint16),
        ('reserved3', c_uint8 * 0xD6)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class InitialData(Structure): # 0x1000 - 0x11FF
    _pack_ = 1

    _fields_ = [
        ('keyY', c_uint8 * 16),
        ('enc_titlekey', c_uint8 * 16),
        ('mac', c_uint8 * 16),
        ('nonce', c_uint8 * 0xC),
        ('reserved', c_uint8 * 0xC4),
        ('ncch_hdr_copy', c_uint8 * 0x100)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class CardDeviceInfo(Structure): # 0x1200 - 0x3FFF, retail cards returns 'FF' here when read
    _pack_ = 1

    _fields_ = [
        ('card_device_reserved_1', c_uint8 * 0x200),
        ('titlekey', c_uint8 * 16),
        ('card_device_reserved_2', c_uint8 * 0x1BF0),
        ('test_pattern', c_uint8 * 0x1000)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class CCIReader:
    def __init__(self, file, dev=0):
        self.file = file
        self.dev = dev

        with open(file, 'rb') as f:
            self.hdr = CCIHdr(f.read(0x200))
            self.card_info = CardInfo(f.read(0x100))
            self.mastering_info = MasteringInfo(f.read(0x100))
            padding = f.read(0xC00)
            self.initial_data = InitialData(f.read(0x200))
            self.card_device_info = CardDeviceInfo(f.read(0x2E00))

        # Decrypt InitialData TitleKey
        if self.card_info.card_flags >> 6 == 3:
            normal_key = b'\x00' * 16
        else:
            normal_key = CTR.key_scrambler(CTR.KeyX0x3B[0], readbe(bytes(self.initial_data.keyY)))
        cipher = AES.new(normal_key, AES.MODE_CCM, nonce=bytes(self.initial_data.nonce))
        self.title_key = cipher.decrypt(bytes(self.initial_data.enc_titlekey))

        # Get component offset and size
        files = {}

        files['cci_header.bin'] = {
            'offset': 0,
            'size': 0x200
        }
        files['card_info.bin'] = {
            'offset': 0x200,
            'size': 0x100
        }
        files['mastering_info.bin'] = {
            'offset': 0x300,
            'size': 0x100
        }
        files['initialdata.bin'] = {
            'offset': 0x1000,
            'size': 0x200
        }
        if bytes(self.card_device_info) != b'\xFF' * 0x2E00:
            files['card_device_info.bin'] = {
                'offset': 0x1200,
                'size': 0x2E00
            }

        names = {
            0: 'game',
            1: 'manual',
            2: 'dlp',
            3: 'unk3',
            4: 'unk4',
            5: 'unk5',
            6: 'update_n3ds',
            7: 'update_o3ds'
        }
        for i in range(0, 64, 8):
            part_off, part_size = readle(self.hdr.partitions_offset_size[i:i + 4]) * media_unit, readle(self.hdr.partitions_offset_size[i + 4:i + 8]) * media_unit
            if part_off:
                files[f'content{i // 8}.{names[i // 8]}.ncch'] = {
                    'offset': part_off,
                    'size': part_size
                }
        self.files = files

    def extract(self):
        f = open(self.file, 'rb')
        for name, info in self.files.items():
            f.seek(info['offset'])
            g = open(name, 'wb')
            for data in read_chunks(f, info['size']):
                g.write(data)
            print(f'Extracted {name}')
            g.close()
        f.close()

    def decrypt(self):
        # Extract components
        f = open(self.file, 'rb')
        for name, info in self.files.items():
            f.seek(info['offset'])
            g = open(name, 'wb')
            for data in read_chunks(f, info['size']):
                g.write(data)
            g.close()
        f.close()

        f = open('decrypted.3ds', 'wb')
        with open('cci_header.bin', 'rb') as g:
            f.write(g.read())
        with open('card_info.bin', 'rb') as g:
            f.write(g.read())
        with open('mastering_info.bin', 'rb') as g:
            f.write(g.read())
        f.write(b'\x00' * 0xC00)
        with open('initialdata.bin', 'rb') as g:
            f.write(g.read())
        if os.path.isfile('card_device_info.bin'):
            with open('card_device_info.bin', 'rb') as g:
                f.write(g.read())
        else:
            f.write(b'\xFF' * 0x2E00)

        # Use NCCHReader to decrypt NCCHs and write to new file
        sys.stdout = open(os.devnull, 'w') # Block print statements
        for name, info in self.files.items():
            if name.endswith('ncch'):
                h = open(name, 'rb')
                h.seek(0x100)
                if h.read(4) == b'NCCH':
                    ncch = NCCHReader(name, dev=self.dev)
                    ncch.decrypt()
                    g = open('decrypted.ncch', 'rb')
                else:
                    g = open(name, 'rb')
                for data in read_chunks(g, info['size']):
                    f.write(data)
                g.close()
                h.close()
        sys.stdout = sys.__stdout__

        curr = f.tell()
        padding_size = os.path.getsize(self.file) - curr
        g = open(self.file, 'rb')
        g.seek(curr)
        for data in read_chunks(g, padding_size):
            f.write(data)
        f.close()
        g.close()

        for name, info in self.files.items():
            os.remove(name)
        if os.path.isfile('decrypted.ncch'):
            os.remove('decrypted.ncch')
        print(f'Decrypted to decrypted.3ds')

    def encrypt(self):
        # Extract components
        f = open(self.file, 'rb')
        for name, info in self.files.items():
            f.seek(info['offset'])
            g = open(name, 'wb')
            for data in read_chunks(f, info['size']):
                g.write(data)
            g.close()

        # Read original partition 0 flags from NCCH header copy
        f.seek(0x1188)
        flags = f.read(8)
        if flags[7] & 0x1:
            part0_crypto = 'fixed'
        else:
            part0_crypto = { 0x00: 'Secure1',
                             0x01: 'Secure2',
                             0x0A: 'Secure3',
                             0x0B: 'Secure4' }[flags[3]]
        f.close()

        f = open('encrypted.3ds', 'wb')
        with open('cci_header.bin', 'rb') as g:
            f.write(g.read())
        with open('card_info.bin', 'rb') as g:
            f.write(g.read())
        with open('mastering_info.bin', 'rb') as g:
            f.write(g.read())
        f.write(b'\x00' * 0xC00)
        with open('initialdata.bin', 'rb') as g:
            f.write(g.read())
        if os.path.isfile('card_device_info.bin'):
            with open('card_device_info.bin', 'rb') as g:
                f.write(g.read())
        else:
            f.write(b'\xFF' * 0x2E00)

        # Use NCCHReader to extract and NCCHBuilder to re-encrypt NCCHs, then write to new file
        sys.stdout = open(os.devnull, 'w') # Block print statements
        for name, info in self.files.items():
            if name.endswith('ncch'):
                h = open(name, 'rb')
                h.seek(0x100)
                if h.read(4) == b'NCCH':
                    ncch = NCCHReader(name, dev=self.dev)
                    ncch.extract()
                    ncch_header = 'ncch_header.bin'
                    if os.path.isfile('exheader.bin'):
                        exheader = 'exheader.bin'
                    else:
                        exheader = ''
                    if os.path.isfile('logo.bin'):
                        logo = 'logo.bin'
                    else:
                        logo = ''
                    if os.path.isfile('plain.bin'):
                        plain = 'plain.bin'
                    else:
                        plain = ''
                    if os.path.isfile('exefs.bin'):
                        exefs = 'exefs.bin'
                    else:
                        exefs = ''
                    if os.path.isfile('romfs.bin'):
                        romfs = 'romfs.bin'
                    else:
                        romfs = ''
                    if name.startswith('content0'):
                        NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto=part0_crypto, dev=self.dev)
                    else: # Partitions 1 and up use Secure1, but if partition 0 uses fixed key, then the others will also use fixed key
                        if part0_crypto == 'fixed':
                            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='fixed', dev=self.dev)
                        else:
                            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='Secure1', dev=self.dev)

                    g = open('new.ncch', 'rb')
                else:
                    g = open(name, 'rb')
                for data in read_chunks(g, info['size']):
                    f.write(data)
                g.close()
                h.close()
                for i in os.listdir('.'):
                    if i in ['ncch_header.bin', 'exheader.bin', 'logo.bin', 'plain.bin', 'exefs.bin', 'romfs.bin']:
                        os.remove(i)
        sys.stdout = sys.__stdout__

        curr = f.tell()
        padding_size = os.path.getsize(self.file) - curr
        g = open(self.file, 'rb')
        g.seek(curr)
        for data in read_chunks(g, padding_size):
            f.write(data)
        f.close()
        g.close()

        for name, info in self.files.items():
            os.remove(name)
        if os.path.isfile('new.ncch'):
            os.remove('new.ncch')
        print(f'Encrypted to encrypted.3ds')

    def regen_undumpable(self):
        with open(os.path.join(resources_dir, 'test_pattern.bin'), 'rb') as f:
            test_pattern = f.read()

        shutil.copyfile(self.file, 'new.3ds')
        with open('new.3ds', 'r+b') as f:
            f.seek(0x1400)
            f.write(self.title_key)
            f.seek(0x3000)
            f.write(test_pattern)
        print('Wrote to new.3ds')

    def verify(self):
        sig_check = []
        sig_check.append(('NCSD Header', Crypto.verify_rsa_sha256(CTR.cci_mod[self.dev], bytes(self.hdr)[0x100:], bytes(self.hdr.sig))))

        mac_check = []
        if self.card_info.card_flags >> 6 == 3:
            normal_key = b'\x00' * 16
        else:
            normal_key = CTR.key_scrambler(CTR.KeyX0x3B[0], readbe(bytes(self.initial_data.keyY)))
        cipher = AES.new(normal_key, AES.MODE_CCM, nonce=bytes(self.initial_data.nonce))
        try:
            cipher.decrypt_and_verify(bytes(self.initial_data.enc_titlekey), received_mac_tag=bytes(self.initial_data.mac))
            mac_check.append(('TitleKey', True))
        except ValueError:
            mac_check.append(('TitleKey', False))

        others = []
        if self.hdr.crypt_type & 1: # Bit 0 of hdr.crypt_type is set
            others.append(('Cardbus crypto', self.hdr.crypt_type >> 1 == self.card_info.card_flags >> 6)) # Check if bits 2-1 of hdr.crypt_type == crypt type in card info section

        print("Signatures:")
        for i in sig_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
        print("MACs:")
        for i in mac_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
        if others != []:
            print("Others:")
            for i in others:
                print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

    def __str__(self):
        partitions = ''
        for i in range(0, 64, 8):
            part_id = hex(readle(self.hdr.partitionIDs[i:i + 8]))[2:].zfill(16)
            if part_id != '0' * 16:
                partitions += f'Partition {i // 8}\n'
                partitions += f' > ID:                {part_id}\n'

        card_device = {
            1: 'NOR Flash',
            2: 'None',
            3: 'BT'
        }
        media_platform = {
            1: 'CTR'
        }
        media_type = {
            0: 'Inner device',
            1: 'CARD1',
            2: 'CARD2',
            3: 'Extended device'
        }
        card_type = {
            0: 'S1',
            1: 'S2'
        }
        crypt_type = {
            0: 'Secure0',
            1: 'Secure1',
            2: 'Secure2',
            3: 'Fixed key'
        }

        return (
            f'TitleID:              {hex(readle(self.hdr.mediaID))[2:].zfill(16)}\n'
            f'{partitions}'
            f'Flags:\n'
            f' > BkupWriteWaitTime: {hex(self.hdr.flags[0])[2:].zfill(2)}\n'
            f' > BkupSecurityVer:   {hex(self.hdr.flags[1] + self.hdr.backup_security_ver)[2:].zfill(2)}\n'
            f' > Card device:       {card_device[self.hdr.flags[3] | self.hdr.flags[7]]}\n'
            f' > Media platform:    {media_platform[self.hdr.flags[4]]}\n'
            f' > Media type:        {media_type[self.hdr.flags[5]]}\n'
            f'Card info:\n'
            f'  Writable address:   0x{hex(self.card_info.writable_addr)[2:].zfill(8)}\n'
            f'  Card type:          {card_type[(self.card_info.card_flags >> 5) & 1]}\n' # Bit 5
            f'  Cardbus crypto:     {crypt_type[self.card_info.card_flags >> 6]}\n' # Bit 7-6
            f'Mastering metadata:\n'
            f'  Media size used:    0x{hex(self.mastering_info.media_size_used)[2:].zfill(8)}\n'
            f'  Title version:      {self.mastering_info.title_ver}\n'
            f'  Card revision:      {self.mastering_info.card_rev}\n'
            f'  CVer TitleID:       {hex(readle(self.mastering_info.cver_titleID))[2:].zfill(16)}\n'
            f'  CVer title version: {self.mastering_info.cver_title_ver}\n'
            f'Initial data:\n'
            f'  KeyY:               {hex(readbe(self.initial_data.keyY))[2:].zfill(32)}\n'
            f'  TitleKey:           {hex(readbe(self.initial_data.enc_titlekey))[2:].zfill(32)} (decrypted: {hex(readbe(self.title_key))[2:].zfill(32)})\n'
            f'  MAC:                {hex(readbe(self.initial_data.mac))[2:].zfill(32)}\n'
            f'Card device info:\n'
            f'  TitleKey:           {hex(readbe(self.card_device_info.titlekey))[2:].zfill(32)}'
        )

class CCIBuilder:
    def __init__(self, cci_header='', card_info='', mastering_info='', initialdata='', card_device_info='', ncchs=[], size='', backup_write_wait_time=-1, save_crypto='', card_device='', media_type='', writable_addr='', card_type='', cardbus_crypto='', title_ver=-1, card_rev=-1, regen_sig='', dev=0, gen_card_device_info=0, out='new.3ds'):
        '''
        cci_header, card_info, mastering_info, initialdata, card_device_info: path to respective component (if available)
        ncchs: list containing filenames of NCCHs, which must each be named 'content[content index]*' (* is wildcard)
        Following parameters are required if no cci_header, card_info and mastering_info are provided; if files and parameter is supplied, the parameter overrides the file(s)
            - size: total ROM size; '128MB' or '256MB' or '512MB' or '1GB' or '2GB' or '4GB' or '8GB' (leave blank for auto)
            - backup_write_wait_time (leave blank for auto)
            - save_crypto: 'fw1' or 'fw2' or 'fw3' or 'fw6' (leave blank for auto)
            - card_device: 'NorFlash' or 'None' or 'BT' (leave blank for auto)
            - media_type: 'InnerDevice' or 'CARD1' or 'CARD2' or 'ExtendedDevice' (leave blank for auto)
            - writable_addr: in hex (leave blank for auto)
            - card_type: 'S1' or 'S2' (leave blank for auto)
            - cardbus_crypto: 'Secure0' or 'Secure1' or 'Secure2' or 'fixed' (leave blank for auto)
            - title_ver
            - card_rev
        regen_sig: '' or 'retail' (test keys) or 'dev'
        dev: 0 or 1
        gen_card_device_info: 0 or 1 (whether to fill in 0x1400-0x140F and 0x3000-0x3FFF)
        out: path to output file
        '''

        # Get savedata size
        ncchs.sort() # Sort NCCHs by content index
        used_size = 0x4000 + sum([os.path.getsize(i) for i in ncchs])
        ncch = NCCHReader(ncchs[0], dev=dev)
        info = ncch.files['exheader.bin']
        with open(ncchs[0], 'rb') as f:
            f.seek(0x100)
            ncch_hdr = f.read(0x100)
            f.seek(info['offset'])
            if ncch.is_decrypted:
                exheader = f.read(info['size'])
            else:
                counter = Counter.new(128, initial_value=readbe(info['counter']))
                cipher = AES.new(info['key'], AES.MODE_CTR, counter=counter)
                exheader = cipher.decrypt(f.read(info['size']))
        save_data_size = readle(exheader[0x1C0:0x1C8])
        if save_data_size > 0 and save_data_size < 128 * KB:
            save_data_size = 128 * KB
        elif save_data_size > 128 * KB and save_data_size < 512 * KB:
            save_data_size = 512 * KB
        elif save_data_size > 512 * KB:
            save_data_size += align(save_data_size, MB)

        # Checks
        if backup_write_wait_time != -1:
            if not (backup_write_wait_time >= 0 and backup_write_wait_time <= 255):
                raise Exception('Invalid backup write wait time')

        if card_device == 'NorFlash':
            if media_type == 'CARD2':
                raise Exception('NorFlash is invalid for CARD2')
            elif media_type == 'CARD1' and save_data_size != 128 * KB and save_data_size != 512 * KB:
                raise Exception('NorFlash can only be used with save-data sizes 128K and 512K')

        if writable_addr != '':
           if not all([i in string.hexdigits for i in writable_addr]):
                raise Exception('Invalid writable address')

        # Defaults
        if cci_header == '':
            if regen_sig == '':
                regen_sig = 'retail'
            if size == '':
                if save_data_size >= MB:
                    data_size = used_size + save_data_size
                else:
                    data_size = used_size
                if data_size < 128 * MB:
                    size = '128MB'
                elif data_size < 256 * MB:
                    size = '256MB'
                elif data_size < 512 * MB:
                    size = '512MB'
                elif data_size < 1 * GB:
                    size = '1GB'
                elif data_size < 2 * GB:
                    size = '2GB'
                elif data_size < 4 * GB:
                    size = '4GB'
                elif data_size < 8 * GB:
                    size = '8GB'
                else:
                    raise Exception('NCCH partitions are too large')
            if backup_write_wait_time == -1:
                backup_write_wait_time = 0
            if save_crypto == '':
                save_crypto = 'fw3'
            if card_device == '':
                if save_data_size == 0 or save_data_size >= MB:
                    card_device = 'None'
                else:
                    card_device = 'NorFlash'
            if media_type == '':
                if save_data_size >= MB:
                    media_type = 'CARD2'
                else:
                    media_type = 'CARD1'
            if card_type == '':
                card_type = 'S1'
            if cardbus_crypto == '':
                if regen_sig == 'dev':
                    cardbus_crypto = 'fixed'
                else:
                    cardbus_crypto = 'Secure0'

        # Create (or modify) CCI header
        if cci_header == '':
            hdr = CCIHdr(b'\x00' * 0x200)
            hdr.magic = b'NCSD'
        else:
            with open(cci_header, 'rb') as f:
                hdr = CCIHdr(f.read())

        if size != '':
            hdr.ncsd_size = { '128MB': 128 * MB,
                              '256MB': 256 * MB,
                              '512MB': 512 * MB,
                              '1GB':   1 * GB  ,
                              '2GB':   2 * GB  ,
                              '4GB':   4 * GB  ,
                              '8GB':   8 * GB   }[size] // media_unit

        titleID = bytes(ncch.hdr.titleID)
        hdr.mediaID = (c_uint8 * sizeof(hdr.mediaID))(*titleID)

        curr = 0x4000
        for i in range(0, 64, 8):
            for file in ncchs:
                if file.startswith(f'content{i // 8}'):
                    hdr.partitions_offset_size[i:i + 4] = int32tobytes(curr // media_unit)
                    file_size = os.path.getsize(file)
                    hdr.partitions_offset_size[i + 4:i + 8] = int32tobytes(file_size // media_unit)
                    curr += file_size

        for i in range(0, 64, 8):
            for file in ncchs:
                if file.startswith(f'content{i // 8}'):
                    tmp = NCCHReader(file, dev)
                    hdr.partitionIDs[i:i + 8] = bytes(tmp.hdr.titleID)

        if backup_write_wait_time != -1:
            hdr.flags[0] = backup_write_wait_time

        if save_crypto != '':
            if save_crypto == 'fw6':
                hdr.flags[1] = 1

        if card_device != '':
            card_device = { 'NorFlash': 1,
                            'None':     2,
                            'BT':       3 }[card_device]
            if save_crypto == 'fw2':
                hdr.flags[7] = card_device
            elif save_crypto == 'fw3' or 'fw6':
                hdr.flags[3] = card_device

        hdr.flags[4] = 1

        if media_type != '':
            hdr.flags[5] = { 'InnerDevice':    0,
                             'CARD1':          1,
                             'CARD2':          2,
                             'ExtendedDevice': 3 }[media_type]

        if regen_sig == 'retail':
            sig = Crypto.sign_rsa_sha256(CTR.test_mod, CTR.test_priv, bytes(hdr)[0x100:])
            hdr.sig = (c_uint8 * sizeof(hdr.sig))(*sig)
        elif regen_sig == 'dev':
            sig = Crypto.sign_rsa_sha256(CTR.cci_mod[1], CTR.cci_priv[1], bytes(hdr)[0x100:])
            hdr.sig = (c_uint8 * sizeof(hdr.sig))(*sig)

        # Create (or modify) card info
        if card_info == '':
            cinfo = CardInfo(b'\x00' * 0x100)
        else:
            with open(card_info, 'rb') as f:
                cinfo = CardInfo(f.read())

        if (hdr.ncsd_size * media_unit / 2 < save_data_size) or (save_data_size > 2047 * MB):
            raise Exception('Too large savedata size')
        if card_info == '' and writable_addr == '': # Defaults
            if media_type == 'CARD1':
                writable_addr = hex(0xFFFFFFFF * media_unit)[2:]
            else:
                # unused_size: values related to the physical implementation of gamecards
                if media_type == 'CARD1':
                    unused_size = { '128MB': 0x00280000,
                                    '256MB': 0x00500000,
                                    '512MB': 0x00a00000,
                                    '1GB':   0x04680000,
                                    '2GB':   0x08c80000,
                                    '4GB':   0x11900000,
                                    '8GB':   0x23000000 }[size]
                elif media_type == 'CARD2':
                    unused_size = { '512MB': 0x02380000,
                                    '1GB':   0x04680000,
                                    '2GB':   0x08c80000,
                                    '4GB':   0x11900000,
                                    '8GB':   0x23000000 }[size]
                if unused_size > 0:
                    writable_addr = hdr.ncsd_size * media_unit - unused_size - save_data_size # Nintendo's method of calculating writable region offset
                else:
                    warnings.warn('Nintendo does not support CARD2 for the current ROM size, aligning save offset after last NCCH')
                    writable_addr = used_size + align(used_size, media_unit)
                writable_addr = hex(writable_addr)[2:]
        if writable_addr != '':
            writable_addr = int(writable_addr, 16)
            cinfo.writable_addr = writable_addr // media_unit

        if card_type != '':
            cinfo.card_flags &= 0b11011111 # Clear flag
            cinfo.card_flags |= { 'S1': 0,
                                  'S2': 1 }[card_type] << 5

        if cardbus_crypto != '':
            cinfo.card_flags &= 0b00111111 # Clear flag
            cinfo.card_flags |= { 'Secure0': 0,
                                  'Secure1': 1,
                                  'Secure2': 2,
                                  'fixed':   3 }[cardbus_crypto] << 6

        # Create (or modify) mastering info
        if mastering_info == '':
            minfo = MasteringInfo(b'\x00' * 0x100)
        else:
            with open(mastering_info, 'rb') as f:
                minfo = MasteringInfo(f.read())

        minfo.media_size_used = used_size

        if title_ver != -1:
            minfo.title_ver = title_ver

        if card_rev != -1:
            minfo.card_rev = card_rev

        cver_tids = ['000400db00017102',
                     '000400db00017202',
                     '000400db00017302',
                     '000400db00017402',
                     '000400db00017502',
                     '000400db00017602' ]
        for i in ncchs:
            if i.startswith('content7'):
                sys.stdout = open(os.devnull, 'w') # Block print statements
                upd = NCCHReader(i, dev)
                upd.extract()
                upd_romfs = RomFSReader('romfs.bin')
                for path, info in upd_romfs.files.items():
                    tid = path.replace('.cia', '')
                    if tid in cver_tids:
                        f = open('romfs.bin', 'rb')
                        f.seek(info['offset'])
                        g = open(path, 'wb')
                        for data in read_chunks(f, info['size']):
                            g.write(data)
                        g.close()
                        f.close()

                        cia = CIAReader(path)
                        titleID_bytes = int64tobytes(int(tid, 16))
                        minfo.cver_titleID = (c_uint8 * sizeof(minfo.cver_titleID))(*titleID_bytes)
                        minfo.cver_title_ver = cia.tmd.hdr.title_ver
                        os.remove(path)
                        break
                sys.stdout = sys.__stdout__
                for i in os.listdir('.'):
                    if i in ['ncch_header.bin', 'exheader.bin', 'logo.bin', 'plain.bin', 'exefs.bin', 'romfs.bin']:
                        os.remove(i)

        # Create initialdata
        if initialdata == '':
            idata = InitialData(b'\x00' * 0x200)
            idata.keyY = (c_uint8 * sizeof(idata.keyY))(*titleID)
            if cinfo.card_flags >> 6 == 3:
                normal_key = b'\x00' * 16
            else:
                normal_key = CTR.key_scrambler(CTR.KeyX0x3B[0], readbe(bytes(idata.keyY)))
            title_key = secrets.token_bytes(16) # Random
            nonce = secrets.token_bytes(0xC) # Random
            cipher = AES.new(normal_key, AES.MODE_CCM, nonce=nonce)
            enc_titlekey, mac = cipher.encrypt_and_digest(title_key)

            idata.enc_titlekey = (c_uint8 * sizeof(idata.enc_titlekey))(*enc_titlekey)
            idata.mac = (c_uint8 * sizeof(idata.mac))(*mac)
            idata.nonce = (c_uint8 * sizeof(idata.nonce))(*nonce)
            idata.ncch_hdr_copy = (c_uint8 * sizeof(idata.ncch_hdr_copy))(*ncch_hdr)
        else:
            with open(initialdata, 'rb') as f:
                idata = InitialData(f.read())
            if cinfo.card_flags >> 6 == 3:
                normal_key = b'\x00' * 16
            else:
                normal_key = CTR.key_scrambler(CTR.KeyX0x3B[0], readbe(bytes(idata.keyY)))
            cipher = AES.new(normal_key, AES.MODE_CCM, nonce=bytes(idata.nonce))
            title_key = cipher.decrypt(bytes(idata.enc_titlekey))

        # Create card device info (if necessary)
        if card_device_info == '':
            cdinfo = CardDeviceInfo(b'\xFF' * 0x2E00)
        else:
            with open(card_device_info, 'rb') as f:
                cdinfo = CardDeviceInfo(f.read())

        if gen_card_device_info:
            cdinfo.titlekey = (c_uint8 * sizeof(cdinfo.titlekey))(*title_key)
            with open(os.path.join(resources_dir, 'test_pattern.bin'), 'rb') as f:
                test_pattern = f.read()
            cdinfo.test_pattern = (c_uint8 * sizeof(cdinfo.test_pattern))(*test_pattern)

        # Write CCI
        with open(out, 'wb') as f:
            f.write(bytes(hdr))
            f.write(bytes(cinfo))
            f.write(bytes(minfo))
            f.write(b'\x00' * 0xC00)
            f.write(bytes(idata))
            f.write(bytes(cdinfo))

            for i in ncchs:
                g = open(i, 'rb')
                for data in read_chunks(g, os.path.getsize(i)):
                    f.write(data)
                g.close()

            f.write(b'\xFF' * (hdr.ncsd_size * media_unit - used_size))
        print(f'Wrote to {out}')
