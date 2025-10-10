from .common import *
from .keys import *
from .ctr_exefs import ExeFSFileHdr
from .ctr_romfs import RomFSReader

class NCCHHdr(Structure):
    _fields_ = [
        ('sig', c_uint8 * 0x100),
        ('magic', c_char * 4),
        ('ncch_size', c_uint32),
        ('titleID', c_uint8 * 8),
        ('maker_code', c_char * 2),
        ('format_ver', c_uint16),
        ('seed_hash', c_uint8 * 4),
        ('programID', c_uint8 * 8),
        ('reserved1', c_uint8 * 16),
        ('logo_hash', c_uint8 * 32),
        ('product_code', c_char * 16),
        ('exh_hash', c_uint8 * 32),
        ('exh_size', c_uint32),
        ('reserved2', c_uint32),
        ('flags', c_uint8 * 8),
        ('plain_offset', c_uint32),
        ('plain_size', c_uint32),
        ('logo_offset', c_uint32),
        ('logo_size', c_uint32),
        ('exefs_offset', c_uint32),
        ('exefs_size', c_uint32),
        ('exefs_hash_size', c_uint32),
        ('reserved4', c_uint32),
        ('romfs_offset', c_uint32),
        ('romfs_size', c_uint32),
        ('romfs_hash_size', c_uint32),
        ('reserved5', c_uint32),
        ('exefs_hash', c_uint8 * 32),
        ('romfs_hash', c_uint8 * 32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)
    
    def __init__(self, data):
        pass

# Returns the initial value for the AES-CTR counter
def get_ncch_counter(hdr, component):
    counter = bytearray(b'\0' * 16)
    
    if hdr.format_ver == 0 or hdr.format_ver == 2:
        section = { 'exheader.bin': 0x01,
                    'exefs.bin':    0x02,
                    'romfs.bin':    0x03 }
        counter[:8] = bytearray(hdr.titleID[::-1])
        counter[8:9] = int8tobytes(section[component])
    elif hdr.format_ver == 1:
        if component == 'exheader.bin':
            x = 0x200
        elif component == 'exefs.bin':
            x = hdr.exefs_offset
        elif component == 'romfs.bin':
            x = hdr.romfs_offset
        counter[:8] = bytearray(hdr.titleID)
        for i in range(4):
            counter[12 + i:12 + i + 1] = int8tobytes(x >> (3 - i) * 8 & 255)

    return bytes(counter)

def get_seed(titleID: bytes):
    with open(os.path.join(resources_dir, 'seeddb.bin'), 'rb') as f:
        seed_count = readle(f.read(4))
        f.seek(0x10)
        seed = -1
        for _ in range(seed_count):
            entry = f.read(0x20)
            if entry[:8] == titleID:
                seed = entry[8:24]
        if seed == -1:
            raise Exception('Could not find TitleID in SEEDDB')
    
    return seed

class NCCHReader:
    def __init__(self, file, dev=0, build=0): # 'build' parameter is to facilitate NCCHBuilder class
        self.file = file
        self.dev = dev

        with open(file, 'rb') as f:
            self.hdr = NCCHHdr(f.read(0x200))

        if self.hdr.format_ver == 0 or self.hdr.format_ver == 2:
            media_unit = 0x200
        elif self.hdr.format_ver == 1:
            media_unit = 1

        # Parse flags
        self.keyX_2 = { 0x00: CTR.KeyX0x2C,
                        0x01: CTR.KeyX0x25,
                        0x0A: CTR.KeyX0x18,
                        0x0B: CTR.KeyX0x1B }[self.hdr.flags[3]]
        self.fixed_key = self.hdr.flags[7] & 0x1
        self.no_romfs = self.hdr.flags[7] & 0x2
        self.is_decrypted = self.hdr.flags[7] & 0x4
        self.uses_seed = self.hdr.flags[7] & 0x20

        # Generate keys
        if self.fixed_key:
            if readle(bytes(self.hdr.titleID)) & (0x10 << 32): # System category bit set in TitleID
                self.normal_key = [hextobytes(hex(CTR.fixed_system)[2:]) for _ in range(2)]
            else:
                self.normal_key = [b'\0' * 16 for _ in range(2)]
        else:
            self.keyY = [bytes(self.hdr.sig)[:0x10], bytes(self.hdr.sig)[:0x10]]
            self.keyX = [CTR.KeyX0x2C[dev], self.keyX_2[dev]]
            
            if self.uses_seed: # This will result in keyY_2 being different
                seed = get_seed(bytes(self.hdr.programID))
                
                # Verify seed in SEEDDB
                if hashlib.sha256(seed + self.hdr.programID).digest()[:4] != bytes(self.hdr.seed_hash):
                    raise Exception('Seed in SEEDDB failed verification')
                
                self.keyY[1] = hashlib.sha256(self.keyY[0] + seed).digest()[:16]

            self.normal_key = [CTR.key_scrambler(self.keyX[i], readbe(self.keyY[i])) for i in range(2)]
    
        # Get component offset, size, AES-CTR key and initial value for counter, hash and size of component to calculate hash over
        # Exheader, ExeFS and RomFS are encrypted
        files = {}
        files['ncch_header.bin'] = {
            'name': 'NCCH Header',
            'size': 0x200,
            'offset': 0,
            'crypt': 'none'
        }

        if self.hdr.exh_size:
            files['exheader.bin'] = {
                'name': 'Exheader',
                'size': 0x800,
                'offset': 0x200,
                'crypt': 'normal',
                'key': self.normal_key[0],
                'counter': get_ncch_counter(self.hdr, 'exheader.bin'),
                'hashes': (bytes(self.hdr.exh_hash), 0x400)
            }
        
        if self.hdr.logo_offset:
            files['logo.bin'] = {
                'name': 'Logo',
                'size': self.hdr.logo_size * media_unit,
                'offset': self.hdr.logo_offset * media_unit,
                'crypt': 'none',
                'hashes': (bytes(self.hdr.logo_hash), self.hdr.logo_size * media_unit)
            }
        
        if self.hdr.plain_size:
            files['plain.bin'] = {
                'name': 'Plain',
                'size': self.hdr.plain_size * media_unit,
                'offset': self.hdr.plain_offset * media_unit,
                'crypt': 'none',
            }
        
        if self.hdr.exefs_offset:
            files['exefs.bin'] = {
                'name': 'ExeFS',
                'size': self.hdr.exefs_size * media_unit,
                'offset': self.hdr.exefs_offset * media_unit,
                'crypt': 'exefs',
                'key': self.normal_key,
                'counter': get_ncch_counter(self.hdr, 'exefs.bin'),
                'hashes': (bytes(self.hdr.exefs_hash), self.hdr.exefs_hash_size * media_unit)
            }

            # ExeFS header, 'icon' and 'banner' use normal_key[0], all other files in ExeFS use normal_key[1]
            counter = Counter.new(128, initial_value=readbe(files['exefs.bin']['counter']))
            cipher = AES.new(self.normal_key[0], AES.MODE_CTR, counter=counter)
            with open(file, 'rb') as f:
                f.seek(self.hdr.exefs_offset * media_unit)
                if self.is_decrypted or build:
                    exefs_file_hdr = f.read(0xA0)
                else:
                    exefs_file_hdr = cipher.decrypt(f.read(0xA0))
            
            exefs_files = [(0, 0x200, 0, 'header')] # Each tuple is (offset in ExeFS, size, normal_key index, name)
            for i in range(10):
                file_hdr = ExeFSFileHdr(exefs_file_hdr[i * 16:(i + 1) * 16])
                if file_hdr.size:
                    name = file_hdr.name.decode('utf-8').strip('\0')
                    if name in ('icon', 'banner'):
                        exefs_files.append((0x200 + file_hdr.offset, file_hdr.size, 0, name))
                    else:
                        exefs_files.append((0x200 + file_hdr.offset, file_hdr.size, 1, name))
                    curr = 0x200 + file_hdr.offset + file_hdr.size
                    if align(curr, 0x200): # Padding between ExeFS files uses normal_key[0]
                        exefs_files.append((curr, align(curr, 0x200), 0, 'padding'))
            files['exefs.bin']['files'] = exefs_files

        if not self.no_romfs:
            if self.hdr.romfs_offset:
                files['romfs.bin'] = {
                    'name': 'RomFS',
                    'size': self.hdr.romfs_size * media_unit,
                    'offset': self.hdr.romfs_offset * media_unit,
                    'crypt': 'normal',
                    'key': self.normal_key[1],
                    'counter': get_ncch_counter(self.hdr, 'romfs.bin'),
                    'hashes': (bytes(self.hdr.romfs_hash), self.hdr.romfs_hash_size * media_unit)
                }
        
        self.files = files

    def extract(self):
        f = open(self.file, 'rb')
        for name, info in self.files.items():
            f.seek(info['offset'])
            g = open(name, 'wb')

            if self.is_decrypted or info['crypt'] == 'none':
                for data in read_chunks(f, info['size']):
                    g.write(data)
            elif info['crypt'] == 'normal':
                counter = Counter.new(128, initial_value=readbe(info['counter']))
                cipher = AES.new(info['key'], AES.MODE_CTR, counter=counter)
                for data in read_chunks(f, info['size']):
                    g.write(cipher.decrypt(data))
            elif info['crypt'] == 'exefs':
                for off, size, key, _ in info['files']:
                    f.seek(info['offset'] + off)
                    counter = Counter.new(128, initial_value=readbe(info['counter']) + (off // 16)) # We have to set the counter manually (initial value increments by 1 per AES block i.e. 16 bytes) since we are decrypting an arbitrary portion (and not from beginning)
                    cipher = AES.new(info['key'][key], AES.MODE_CTR, counter=counter)
                    cipher.decrypt(b'\0' * (off % 16)) # Cipher has to be advanced manually also
                    for data in read_chunks(f, size):
                        g.write(cipher.decrypt(data))
            
            print(f'Extracted {name}')
            g.close()
        f.close()

    def decrypt(self):
        f = open(self.file, 'rb')
        g = open('decrypted.ncch', 'wb')
        curr = 0
        for name, info in self.files.items():
            if curr < info['offset']: # Padding between NCCH components
                pad_size = info['offset'] - curr
                g.write(b'\x00' * pad_size)
                curr += pad_size
            f.seek(info['offset'])

            if name == 'ncch_header.bin':
                hdr_dec = self.hdr
                hdr_dec.flags[3] = 0 # Set keyX_2 to Key 0x2C
                hdr_dec.flags[7] |= 4 # Set NoCrypto flag
                hdr_dec.flags[7] &= ~1 # Unset FixedCryptoKey flag
                hdr_dec.flags[7] &= ~0x20 # Unset UseSeedCrypto flag
                g.write(bytes(hdr_dec))
            elif self.is_decrypted or info['crypt'] == 'none':
                for data in read_chunks(f, info['size']):
                    g.write(data)
            elif info['crypt'] == 'normal':
                counter = Counter.new(128, initial_value=readbe(info['counter']))
                cipher = AES.new(info['key'], AES.MODE_CTR, counter=counter)
                for data in read_chunks(f, info['size']):
                    g.write(cipher.decrypt(data))
            elif info['crypt'] == 'exefs':
                for off, size, key, _ in info['files']:
                    f.seek(info['offset'] + off)
                    counter = Counter.new(128, initial_value=readbe(info['counter']) + (off // 16))
                    cipher = AES.new(info['key'][key], AES.MODE_CTR, counter=counter)
                    cipher.decrypt(b'\0' * (off % 16))
                    for data in read_chunks(f, size):
                        g.write(cipher.decrypt(data))
            curr += info['size']
            
        f.close()
        g.close()
        print(f'Decrypted to decrypted.ncch')

    def verify(self):
        f = open(self.file, 'rb')

        # Hash checks
        hash_check = []
        for name, info in self.files.items():
            if 'hashes' in info.keys():
                hashes = info['hashes']
                f.seek(info['offset'])
                if self.is_decrypted or info['crypt'] == 'none':
                    hash_check.append((info['name'], Cryptodome.sha256(f, hashes[1]) == hashes[0]))
                else:
                    h = hashlib.sha256()
                    counter = Counter.new(128, initial_value=readbe(info['counter']))
                    if info['crypt'] == 'normal':
                        cipher = AES.new(info['key'], AES.MODE_CTR, counter=counter)
                    elif info['crypt'] == 'exefs': # ExeFS hash is only over the ExeFS header (size 0x200), so we don't need to change the counter or the key
                        cipher = AES.new(info['key'][0], AES.MODE_CTR, counter=counter)
                    for data in read_chunks(f, hashes[1]):
                        h.update(cipher.decrypt(data))
                    hash_check.append((info['name'], h.digest() == hashes[0]))

        # Signature checks
        sig_check = []
        if self.hdr.flags[5] & 0x2: # CXI
            # Modulus for NCCH header signature is in accessdesc of exheader
            f.seek(0x700)
            if self.is_decrypted:
                ncch_mod = f.read(0x100)
            else:
                info = self.files['exheader.bin']
                counter = Counter.new(128, initial_value=readbe(info['counter']) + 0x500 // 16)
                cipher = AES.new(info['key'], AES.MODE_CTR, counter=counter)
                ncch_mod = cipher.decrypt(f.read(0x100))
            sig_check.append(('NCCH Header', Cryptodome.verify_rsa_sha256(ncch_mod, bytes(self.hdr)[0x100:], bytes(self.hdr.sig))))

            f.seek(0x600)
            if self.is_decrypted:
                data = f.read(0x400)
            else:
                info = self.files['exheader.bin']
                counter = Counter.new(128, initial_value=readbe(info['counter']) + 0x400 // 16)
                cipher = AES.new(info['key'], AES.MODE_CTR, counter=counter)
                data = cipher.decrypt(f.read(0x400))
            sig_check.append(('Exheader', Cryptodome.verify_rsa_sha256(CTR.accessdesc_mod[self.dev], data[0x100:], data[:0x100])))
        elif self.hdr.flags[5] & 0x1: # CFA
            sig_check.append(('NCCH Header', Cryptodome.verify_rsa_sha256(CTR.cfa_mod[self.dev], bytes(self.hdr)[0x100:], bytes(self.hdr.sig))))

        f.close()
        print("Hashes:")
        for i in hash_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
        print("Signatures:")
        for i in sig_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

    def __str__(self):
        keyX_2 = { 0x00: 'Secure1 (Key 0x2C)',
                   0x01: 'Secure2 (Key 0x25)',
                   0x0A: 'Secure3 (Key 0x18)',
                   0x0B: 'Secure4 (Key 0x1B)' }
        if self.is_decrypted:
            crypto = 'None (Decrypted)'
        elif self.fixed_key:
            if readle(bytes(self.hdr.titleID)) & (0x10 << 32):
                crypto = 'Fixed key (System)'
            else:
                crypto = 'Fixed key (Zero key)'
        else:
            crypto = keyX_2[self.hdr.flags[3]]
            if self.uses_seed:
                crypto += ' (KeyY seeded)'
        
        platform = {
            1: 'CTR',
            2: 'SNAKE'
        }
        form_type = {
            1: 'CFA',
            2: 'CXI without RomFS',
            3: 'CXI'
        }
        content_type = {
            0: 'Application',
            1: 'CTR System Update',
            2: 'Manual',
            3: 'Child',
            4: 'Trial',
            5: 'SNAKE System Update'
        }

        return (
            f'TitleID:           {hex(readle(self.hdr.titleID))[2:].zfill(16)}\n'
            f'Maker code:        {self.hdr.maker_code.decode("ascii")}\n'
            f'Format version:    {self.hdr.format_ver}\n'
            f'Product code:      {self.hdr.product_code.decode("ascii")}\n'
            f'Flags:\n'
            f' > Cryptodome method:  {crypto}\n'
            f' > Platform:       {platform[self.hdr.flags[4]]}\n'
            f' > Form type:      {form_type[self.hdr.flags[5] & 0b11]}\n' # Lower 2 bits
            f' > Content type:   {content_type[self.hdr.flags[5] >> 2]}' # Bits 2-7
        )

class NCCHBuilder:
    def __init__(self, ncch_header='', exheader='', logo='', plain='', exefs='', romfs='', platform='', ncch_type='', maker_code='', product_code='', titleID='', programID='', crypto='', seed=0, regen_sig='', replace_tid=0, dev=0, out='new.ncch'):
        '''
        ncch_header, exheader, logo, plain, exefs, romfs: path to respective component (if available)
        Following parameters are required if no NCCH header is provided; if both header and parameter is supplied, the parameter overrides the header(s)
            - platform: 'CTR' or 'SNAKE'
            - ncch_type: 'CXI' or 'CTRSystemUpdate' or 'SNAKESystemUpdate' or 'Manual' or 'Child' or 'Trial'
            - maker_code: maker code, e.g. '00'
            - product_code: product code, e.g. 'CTR-P-CTAP'
            - titleID: titleID in hex (if not provided, take from exheader), e.g. '000400000FF3FF00'
            - programID: programID in hex (if not provided, use the titleID)
            - crypto: 'none' / 'fixed' / 'Secure1' / 'Secure2' / 'Secure3' / 'Secure4'
            - seed: 0 or 1
        regen_sig: '' or 'retail' (test keys; CXI header signature only) or 'dev' (NCCH header and exheader signature)
        replace_tid: 0 or 1 (replaces TitleID in NCCH header and exheader)
        dev: 0 or 1
        out: path to output file
        '''

        # Checks
        if ncch_type != '' and ncch_type != 'CXI' and exheader != '':
            warnings.warn('Ignoring exheader since NCCH type is CFA')
            exheader = ''

        if maker_code != '':
            if not len(maker_code) == 2:
                raise Exception('Maker code length must be 2')

        if product_code != '':
            if not all([i == '-' or i.isdigit() or i.isupper() for i in product_code]) or len(product_code) < 10 or len(product_code) > 16 or product_code[:3] not in ['CTR', 'KTR']:
                raise Exception('Invalid product code')
        
        if titleID != '':
           if not all([i in string.hexdigits for i in titleID]) or len(titleID) != 16:
                raise Exception('Invalid TitleID')
        
        if programID != '':
           if not all([i in string.hexdigits for i in programID]) or len(programID) != 16:
                raise Exception('Invalid programID')
        
        if seed == 1 and (not crypto.startswith('Secure')):
            raise Exception('Seed crypto can only be used with Secure crypto')

        # Defaults
        if ncch_header == '' and regen_sig == '':
            regen_sig = 'retail'
        
        if regen_sig == 'dev':
            dev = 1

        # Create (or modify) NCCH header
        if exheader != '' and (regen_sig != '' or replace_tid == 1):
            shutil.copyfile(exheader, 'exheader_mod')

        if ncch_header == '':
            hdr = NCCHHdr(b'\x00' * 0x200)
            hdr.magic = b'NCCH'
            if romfs == '':
                hdr.flags[7] |= 2
            if titleID == '' and exheader != '':
                with open(exheader, 'rb') as f:
                    f.seek(0x200)
                    titleID = hex(readle(f.read(8)))[2:].zfill(16)
        else:
            with open(ncch_header, 'rb') as f:
                hdr = NCCHHdr(f.read())
        
        if ncch_header == '' and programID == '': # Defaults
            programID = titleID
        
        if titleID != '':
            titleID_bytes = int64tobytes(int(titleID, 16))
            hdr.titleID = (c_uint8 * sizeof(hdr.titleID))(*titleID_bytes)
            
            if replace_tid == 1: # Replace TitleID in exheader
                if exheader != '':
                    with open('exheader_mod', 'r+b') as f:
                        offs = [0x1C8, 0x200, 0x600]
                        for off in offs:
                            f.seek(off)
                            f.write(hextobytes(titleID))
        
        if programID != '':
            programID_bytes = int64tobytes(int(programID, 16))
            hdr.programID = (c_uint8 * sizeof(hdr.programID))(*programID_bytes)
        
        if maker_code != '':
            hdr.maker_code = maker_code.encode('ascii')
        
        if ncch_type != '':
            if ncch_type == 'CXI':
                hdr.format_ver = 2
            else:
                hdr.format_ver = 0
            
            if ncch_header != '': # Reset content type flag first if existing value already exists
                hdr.flags[5] = 0
            if ncch_type == 'CXI' and romfs == '':
                hdr.flags[5] |= 2
            elif ncch_type == 'CXI' and romfs != '':
                hdr.flags[5] |= 3
            else:
                hdr.flags[5] |= 1
                if ncch_type == 'CTRSystemUpdate':
                    hdr.flags[5] |= 4
                elif ncch_type == 'Manual':
                    hdr.flags[5] |= 8
                elif ncch_type == 'Child':
                    hdr.flags[5] |= 0xC
                elif ncch_type == 'Trial':
                    hdr.flags[5] |= 0x10
                elif ncch_type == 'SNAKESystemUpdate':
                    hdr.flags[5] |= 0x14
        
        if product_code != '':
            hdr.product_code = product_code.encode('ascii')
        
        if platform != '':
            if platform == 'CTR':
                hdr.flags[4] = 1
            elif platform == 'SNAKE':
                hdr.flags[4] = 2
        
        if crypto != '':
            # Reset crypto flags
            hdr.flags[7] &= ~1
            hdr.flags[7] &= ~4
            hdr.flags[7] &= ~0x20

            if crypto == 'none':
                hdr.flags[7] |= 4
            elif crypto == 'fixed':
                hdr.flags[7] |= 1
            else:
                hdr.flags[3] = { 'Secure1': 0x00,
                                 'Secure2': 0x01,
                                 'Secure3': 0x0A,
                                 'Secure4': 0x0B }[crypto]
        if seed == 1:
            hdr.flags[7] |= 0x20
            seed = get_seed(bytes(hdr.programID))
            seed_hash = hashlib.sha256(seed + hdr.programID).digest()[:4]
            hdr.seed_hash = (c_uint8 * sizeof(hdr.seed_hash))(*seed_hash)

        # Modify exheader (if necessary)
        if regen_sig == 'retail':
            if exheader != '':
                with open('exheader_mod', 'r+b') as f: # Replace NCCH header mod
                    f.seek(0x500)
                    f.write(CTR.test_mod)
        elif regen_sig == 'dev':
            if exheader != '':
                with open('exheader_mod', 'r+b') as f:
                    # NCCH header mod
                    f.seek(0x500)
                    f.write(CTR.test_mod)

                    # Exheader signature
                    f.seek(0x500)
                    sig = Cryptodome.sign_rsa_sha256(CTR.accessdesc_mod[1], CTR.accessdesc_priv[1], f.read(0x300))
                    f.seek(0x400)
                    f.write(sig)

        if hdr.format_ver == 0 or hdr.format_ver == 2:
            media_unit = 0x200
        elif hdr.format_ver == 1:
            media_unit = 1

        curr = 0x200
        files = {}
        size_check = []
        if exheader != '':
            if regen_sig != '' or replace_tid == 1:
                exheader = 'exheader_mod'
            hdr.exh_size = 0x400
            
            f = open(exheader, 'rb')
            h = Cryptodome.sha256(f, 0x400)
            hdr.exh_hash = (c_uint8 * sizeof(hdr.exh_hash))(*h)
            f.close()
            
            curr += os.path.getsize(exheader)
            files['exheader.bin'] = {
                'path': exheader
            }
        if logo != '':
            curr += align(curr, 0x200)
            size_check.append(hdr.logo_size == os.path.getsize(logo) // media_unit)
            
            hdr.logo_offset = curr // media_unit
            hdr.logo_size = os.path.getsize(logo) // media_unit
            
            f = open(logo, 'rb')
            h = Cryptodome.sha256(f, os.path.getsize(logo))
            hdr.logo_hash = (c_uint8 * sizeof(hdr.logo_hash))(*h)
            f.close()
            
            curr += os.path.getsize(logo)
            files['logo.bin'] = {
                'path': logo
            }
        if plain != '':
            curr += align(curr, 0x200)
            size_check.append(hdr.plain_size == os.path.getsize(plain) // media_unit)

            hdr.plain_offset = curr // media_unit
            hdr.plain_size = os.path.getsize(plain) // media_unit
            
            curr += os.path.getsize(plain)
            files['plain.bin'] = {
                'path': plain
            }
        if exefs != '':
            curr += align(curr, 0x200)
            size_check.append(hdr.exefs_size == os.path.getsize(exefs) // media_unit)
            
            hdr.exefs_offset = curr // media_unit
            hdr.exefs_size = os.path.getsize(exefs) // media_unit
            
            f = open(exefs, 'rb')
            h = Cryptodome.sha256(f, 0x200)
            hdr.exefs_hash = (c_uint8 * sizeof(hdr.exefs_hash))(*h)
            f.close()
            hdr.exefs_hash_size = 0x200 // media_unit
            
            curr += os.path.getsize(exefs)
            files['exefs.bin'] = {
                'path': exefs
            }
        if romfs != '':
            r = RomFSReader(romfs)
            romfs_hash_size = roundup(0x60 + r.hdr.master_hash_size, media_unit) # RomFS hash in NCCH is over RomFS header + master hash
        
            size_check.append(hdr.romfs_size == os.path.getsize(romfs) // media_unit)
            if all(size_check): # RomFS offset may be 0x200 aligned ("SDK 2.x and prior" according to makerom). In order for rebuilt NCCH to match original, we don't overwrite the existing RomFS offset if all sizes in provided NCCH header match provided files
                curr = hdr.romfs_offset * media_unit
            else:
                curr += align(curr, 0x1000)

            hdr.romfs_offset = curr // media_unit
            hdr.romfs_size = os.path.getsize(romfs) // media_unit
            
            f = open(romfs, 'rb')
            h = Cryptodome.sha256(f, romfs_hash_size)
            hdr.romfs_hash = (c_uint8 * sizeof(hdr.romfs_hash))(*h)
            f.close()
            hdr.romfs_hash_size = romfs_hash_size // media_unit
            
            curr += os.path.getsize(romfs)
            files['romfs.bin'] = {
                'path': romfs
            }
        hdr.ncch_size = curr // media_unit
        
        # Generate header signature (if necessary)
        if regen_sig == 'retail':
            if hdr.flags[5] & 0x2: # CXI
                sig = Cryptodome.sign_rsa_sha256(CTR.test_mod, CTR.test_priv, bytes(hdr)[0x100:])
                hdr.sig = (c_uint8 * sizeof(hdr.sig))(*sig)
        elif regen_sig == 'dev':
            if hdr.flags[5] & 0x2: # CXI
                sig = Cryptodome.sign_rsa_sha256(CTR.test_mod, CTR.test_priv, bytes(hdr)[0x100:])
                hdr.sig = (c_uint8 * sizeof(hdr.sig))(*sig)
            else: # CFA
                sig = Cryptodome.sign_rsa_sha256(CTR.cfa_mod[1], CTR.cfa_priv[1], bytes(hdr)[0x100:])
                hdr.sig = (c_uint8 * sizeof(hdr.sig))(*sig)

        # Generate keys by using NCCHReader on dummy NCCH with only NCCH header and ExeFS header
        with open('tmp', 'wb') as f:
            f.write(bytes(hdr))
            if hdr.exefs_offset:
                f.seek(hdr.exefs_offset * media_unit)
                with open(files['exefs.bin']['path'], 'rb') as g:
                    exefs_file_hdr = g.read(0xA0)
                f.write(exefs_file_hdr)
        ncch = NCCHReader('tmp', dev=dev, build=1)

        # Write NCCH
        f = open(f'{out}', 'wb')
        f.write(bytes(hdr))
        curr = 0x200
        for name, info in files.items():
            info.update(ncch.files[name])
            g = open(info['path'], 'rb')
            if curr < info['offset']:
                pad_size = info['offset'] - curr
                f.write(b'\x00' * pad_size)
                curr += pad_size

            if ncch.is_decrypted or info['crypt'] == 'none':
                for data in read_chunks(g, info['size']):
                    f.write(data)
            elif info['crypt'] == 'normal':
                counter = Counter.new(128, initial_value=readbe(info['counter']))
                cipher = AES.new(info['key'], AES.MODE_CTR, counter=counter)
                for data in read_chunks(g, info['size']):
                    f.write(cipher.encrypt(data))
            elif info['crypt'] == 'exefs':
                for off, size, key, _ in info['files']:
                    g.seek(off)
                    counter = Counter.new(128, initial_value=readbe(info['counter']) + (off // 16))
                    cipher = AES.new(info['key'][key], AES.MODE_CTR, counter=counter)
                    cipher.encrypt(b'\0' * (off % 16))
                    for data in read_chunks(g, size):
                        f.write(cipher.encrypt(data))
            curr += info['size']
            g.close()
        f.close()
        os.remove('tmp')
        if os.path.isfile('exheader_mod'):
            os.remove('exheader_mod')
        print(f'Wrote to {out}')
