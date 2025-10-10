from .common import *
from .keys import *

magic30 = 0x72636E65 # 'encr'
magic34 = 0x6A624F79 # 'yObj'
decrypted_id = 0xE7FFDEFF
sec_area_id_special = { # Non-standard decryption values
    'YV5P': (0xD0D48B67, 0x39392F23), # Dragon Quest 5 (EU)
    'YV5E': (0x014A191A, 0xA5C470B9), # Dragon Quest 5 (USA)
    'YV5J': (0x7829BC8D, 0x9968EF44), # Dragon Quest 5 (JP)
    'CP5P': (0xC4A15AB8, 0xD2E667C8), # Prince of Persia (EU)
    'CP5E': (0xD5E97D20, 0x21B2A159), # Prince of Persia (USA)
}
block_size = 512

def mod_add(a, b):
    return (a + b) % (2 ** 32)

def blowfish_encrypt(key, xl, xr): # xl and xr are u32
    a = xl
    b = xr
    for i in range(0, 16):
        c = key[i] ^ a
        a = b ^ f(key, c)
        b = c

    xr = a ^ key[16]
    xl = b ^ key[17]
    return xl, xr

def blowfish_decrypt(key, xl, xr):
    a = xl
    b = xr
    for i in range(17, 1, -1):
        c = key[i] ^ a
        a = b ^ f(key, c)
        b = c
    
    xl = b ^ key[0]
    xr = a ^ key[1]
    return xl, xr

def f(key, v):
    a = key[18 + 0 + ((v >> 24) & 0xFF)]
    b = key[18 + 256 + ((v >> 16) & 0xFF)]
    c = key[18 + 512 + ((v >> 8) & 0xFF)]
    d = key[18 + 768 + ((v >> 0) & 0xFF)]

    return mod_add((mod_add(a, b) ^ c), d)
 
def apply_keycode(key, mod, keycode): # keycode is an array of size 3
    mod //= 4

    keycode[2], keycode[1] = blowfish_encrypt(key, keycode[2], keycode[1])
    keycode[1], keycode[0] = blowfish_encrypt(key, keycode[1], keycode[0])

    tmp1 = tmp2 = 0
    for i in range(0, 18):
        key[i] ^= byteswap32(keycode[i % mod])
    for i in range(0, 18 + 1024, 2):
        tmp1, tmp2 = blowfish_encrypt(key, tmp1, tmp2)
        key[i + 0] = tmp1
        key[i + 1] = tmp2
    
    return key

def init_keycode(key, gamecode, level, mod):
    key = [byteswap32(i) for i in key] # Original table is raw bytes which is big endian
    keycode = [gamecode, gamecode // 2, gamecode * 2]

    if level >= 1:
        key = apply_keycode(key, mod, keycode)
    if level >= 2:
        key = apply_keycode(key, mod, keycode)
    keycode[1] *= 2
    keycode[2] //= 2
    if level >= 3:
        key = apply_keycode(key, mod, keycode)
    
    return key

def get_rsa_key_idx(hdr, hdr_ext): # The RSA key to be used depends on which bits in the titleID are set
    if hdr.unit_code == 0 and (hdr_ext.flags >> 6) & 1:
        return 3
    elif hdr.unit_code == 2 or hdr.unit_code == 3:
        if (hdr_ext.titleID_hi >> 1) & 1:
            return 0
        elif (hdr_ext.titleID_hi >> 4) & 1:
            return 2
        elif hdr_ext.titleID_hi & 1:
            return 1
        else:
            return 3

class NTRBaseHdr(Structure): # For all games, 0x0 - 0x17F
    _pack_ = 1

    _fields_ = [
        ('game_title', c_char * 12),
        ('game_code', c_char * 4),
        ('maker_code', c_char * 2),
        ('unit_code', c_uint8),
        ('encryption_seed_select', c_uint8),
        ('device_capacity', c_uint8),
        ('reserved1', c_uint8 * 7),
        ('data1', c_uint8), # DS: reserved, DSi enhanced/exclusive: crypto flags
        ('data2', c_uint8), # DS: region, DSi enhanced/exclusive: permit jump
        ('rom_ver', c_uint8),
        ('autostart', c_uint8),
        ('arm9_rom_offset', c_uint32),
        ('arm9_entry_addr', c_uint32),
        ('arm9_ram_addr', c_uint32),
        ('arm9_size', c_uint32),
        ('arm7_rom_offset', c_uint32),
        ('arm7_entry_addr', c_uint32),
        ('arm7_ram_addr', c_uint32),
        ('arm7_size', c_uint32),
        ('fnt_offset', c_uint32),
        ('fnt_size', c_uint32),
        ('fat_offset', c_uint32),
        ('fat_size', c_uint32),
        ('arm9_overlay_offset', c_uint32),
        ('arm9_overlay_size', c_uint32),
        ('arm7_overlay_offset', c_uint32),
        ('arm7_overlay_size', c_uint32),
        ('rom_control_normal', c_uint32),
        ('rom_control_key1', c_uint32),
        ('banner_offset', c_uint32),
        ('secure_area_crc', c_uint16),
        ('secure_area_delay', c_uint16),
        ('arm9_autoload_ram_addr', c_uint32),
        ('arm7_autoload_ram_addr', c_uint32),
        ('secure_area_disable', c_uint64),
        ('ntr_rom_size', c_uint32),
        ('hdr_size', c_uint32),
        ('data3', c_uint32), # DS: unknown, DS games after DSi / DSi enhanced/exclusive: ARM9 parameters table offset
        ('data4', c_uint32), # DS: reserved, DS games after DSi / DSi enhanced/exclusive: ARM7 parameters table offset
        ('data5', c_uint16), # DS: reserved, DSi enhanced/exclusive: NTR ROM region end
        ('data6', c_uint16), # DS: reserved, DSi enhanced/exclusive: TWL ROM region start
        ('nand_rom_end', c_uint16),
        ('nand_rw_start', c_uint16),
        ('reserved2', c_uint8 * 0x28),
        ('logo', c_uint8 * 0x9C),
        ('logo_crc', c_uint16),
        ('hdr_crc', c_uint16),
        ('debug_rom_offset', c_uint32),
        ('debug_size', c_uint32),
        ('debug_ram_addr', c_uint32),
        ('reserved3', c_uint8 * 0x14)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)
    
    def __init__(self, data):
        pass

class NTRExtendedHdr(Structure): # For DS games released after the DSi, 0x1BF - 0x1000
    _pack_ = 1

    _fields_ = [
        ('flags', c_uint8),
        ('reserved1', c_uint8 * 0x17C),
        ('banner_hmac', c_uint8 * 20),
        ('reserved2', c_uint8 * 0x28),
        ('hdr_arm9_arm7_hmac', c_uint8 * 20),
        ('arm9overlay_fat_hmac', c_uint8 * 20),
        ('reserved3', c_uint8 * 0xBE0),
        ('sig', c_uint8 * 0x80)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)
    
    def __init__(self, data):
        pass

class TWLExtendedHdr(Structure): # For DSi enhanced or exclusive games, 0x180 - 0x1000
    _pack_ = 1

    _fields_ = [
        ('global_mbk1_5_settings', c_uint8 * 20),
        ('local_mbk6_8_settings_wram_arm9', c_uint8 * 12),
        ('local_mbk6_8_settings_wram_arm7', c_uint8 * 12),
        ('global_mbk9_wram_write_protect', c_uint8 * 3),
        ('global_wramcnt', c_uint8),
        ('region', c_uint32),
        ('access_control', c_uint32),
        ('arm7_scfg_ext7', c_uint32),
        ('reserved1', c_uint8 * 3),
        ('flags', c_uint8),
        ('arm9i_rom_offset', c_uint32),
        ('reserved2', c_uint32),
        ('arm9i_ram_addr', c_uint32),
        ('arm9i_size', c_uint32),
        ('arm7i_rom_offset', c_uint32),
        ('arm7i_ram_addr_sd', c_uint32),
        ('arm7i_ram_addr', c_uint32),
        ('arm7i_size', c_uint32),
        ('ntr_digest_region_offset', c_uint32),
        ('ntr_digest_region_size', c_uint32),
        ('twl_digest_region_offset', c_uint32),
        ('twl_digest_region_size', c_uint32),
        ('digest1_table_offset', c_uint32),
        ('digest1_table_size', c_uint32),
        ('digest2_table_offset', c_uint32),
        ('digest2_table_size', c_uint32),
        ('digest1_block_size', c_uint32),
        ('digest2_digest1_count', c_uint32),
        ('banner_size', c_uint32),
        ('shared2_0000_size', c_uint8),
        ('shared2_0001_size', c_uint8),
        ('eula_ver', c_uint8),
        ('use_ratings', c_uint8),
        ('total_rom_size', c_uint32),
        ('shared2_0002_size', c_uint8),
        ('shared2_0003_size', c_uint8),
        ('shared2_0004_size', c_uint8),
        ('shared2_0005_size', c_uint8),
        ('arm9i_params_table_offset', c_uint32),
        ('arm7i_params_table_offset', c_uint32),
        ('modcrypt_area_1_offset', c_uint32),
        ('modcrypt_area_1_size', c_uint32),
        ('modcrypt_area_2_offset', c_uint32),
        ('modcrypt_area_2_size', c_uint32),
        ('titleID_lo', c_uint32),
        ('titleID_hi', c_uint32),
        ('pub_save_data_size', c_uint32),
        ('priv_save_data_size', c_uint32),
        ('reserved3', c_uint8 * 0xB0),
        ('parental_control', c_uint8 * 16),
        ('arm9_hmac', c_uint8 * 20),
        ('arm7_hmac', c_uint8 * 20),
        ('digest2_hmac', c_uint8 * 20),
        ('banner_hmac', c_uint8 * 20),
        ('arm9i_hmac', c_uint8 * 20),
        ('arm7i_hmac', c_uint8 * 20),
        ('reserved4', c_uint8 * 40),
        ('arm9_no_secure_area_hmac', c_uint8 * 20),
        ('reserved5', c_uint8 * 0xA4C),
        ('debug_args', c_uint8 * 0x180),
        ('sig', c_uint8 * 0x80)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)
    
    def __init__(self, data):
        pass

class KeyTable(Structure): # In ROM dumps, the NTR KeyTable is all '00', and the TWL KeyTable contains mirrors of the data in 0x8000 - 0x8FFF
    _pack_ = 1

    _fields_ = [
        ('reserved_1', c_uint8 * 0x600),
        ('p_array', c_uint8 * 0x48),
        ('reserved_2', c_uint8 * 0x5B8),
        ('s_boxes', c_uint8 * 0x1000),
        ('reserved_3', c_uint8 * 0x400),
        ('test_pattern', c_uint8 * 0x1000)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)
    
    def __init__(self, data):
        pass

class SRLReader:
    def __init__(self, file, dev=0):
        self.file = file
        self.dev = dev
        self.media = 'Game card'

        with open(file, 'rb') as f:
            self.hdr = NTRBaseHdr(f.read(0x180))
            if self.hdr.unit_code == 0:
                f.seek(0x1BF)
                self.hdr_ext = NTRExtendedHdr(f.read(0xE41))
            elif self.hdr.unit_code == 2 or self.hdr.unit_code == 3:
                self.hdr_ext = TWLExtendedHdr(f.read(0xE80))
                if (self.hdr_ext.titleID_hi >> 2) & 1:
                    self.media = 'NAND'
            
            if self.media == 'Game card':
                f.seek(0x1000)
                self.keytable = KeyTable(f.read(0x3000))
                if self.hdr.unit_code == 2 or self.hdr.unit_code == 3:
                    f.seek(self.hdr.data6 * 0x80000)
                    self.keytable_2 = KeyTable(f.read(0x3000))
            
            # Check NTR secure area
            if self.hdr.arm9_rom_offset != 0x4000:
                self.secure_area_status = 'not present'
            else:
                f.seek(0x4000)
                tmp1 = readle(f.read(4))
                tmp2 = readle(f.read(4))
                if tmp1 == 0 and tmp2 == 0:
                    self.secure_area_status = 'empty'
                elif (tmp1, tmp2) in [
                    # properly decrypted standard value
                    (decrypted_id, decrypted_id),
                    # properly decrypted non-standard value
                    (0xD0D48B67, 0x39392F23), # Dragon Quest 5 (EU)
                    (0x014A191A, 0xA5C470B9), # Dragon Quest 5 (USA)
                    (0x7829BC8D, 0x9968EF44), # Dragon Quest 5 (JP)
                    (0xC4A15AB8, 0xD2E667C8), # Prince of Persia (EU)
                    (0xD5E97D20, 0x21B2A159), # Prince of Persia (USA)
                    # properly decrypted prototype value
                    (0xBA35F813, 0xB691AAE8),
                    # improperly decrypted empty secure area (decrypt empty with woodsec)
                    (0xE386C397, 0x82775B7E),
                    (0xF98415B8, 0x698068FC),
                    (0xA71329EE, 0x2A1D4C38),
                    (0xC44DCC48, 0x38B6F8CB),
                    (0x3A9323B5, 0xC0387241),
                ]:
                    self.secure_area_status = 'decrypted'
                else:
                    self.secure_area_status = 'encrypted'

        files = {}
        
        files['header.bin'] = {
            'name': 'Header',
            'offset': 0,
            'size': 0x1000
        }

        if self.media == 'Game card' and bytes(self.keytable) != b'\x00' * 0x3000: # Only exists for game card SRLs
            files['keytable.bin'] = {
                'name': 'KeyTable',
                'offset': 0x1000,
                'size': 0x3000
            }

        if self.hdr.arm9_rom_offset:
            size = self.hdr.arm9_size
            with open(file, 'rb') as f:
                f.seek(self.hdr.arm9_rom_offset + self.hdr.arm9_size)
                if readle(f.read(4)) == 0xDEC00621:
                    size += 0xC
            files['arm9.bin'] = {
                'name': 'ARM9',
                'offset': self.hdr.arm9_rom_offset,
                'size': size
            }

        if self.hdr.arm9_overlay_offset:
            files['arm9overlay.bin'] = {
                'name': 'ARM9 overlay',
                'offset': self.hdr.arm9_overlay_offset,
                'size': self.hdr.arm9_overlay_size
            }
        
        if self.hdr.arm7_rom_offset:
            files['arm7.bin'] = {
                'name': 'ARM7',
                'offset': self.hdr.arm7_rom_offset,
                'size': self.hdr.arm7_size
            }
        
        if self.hdr.arm7_overlay_offset:
            files['arm7overlay.bin'] = {
                'name': 'ARM7 overlay',
                'offset': self.hdr.arm7_overlay_offset,
                'size': self.hdr.arm7_overlay_size
            }

        if self.hdr.banner_offset:
            with open(file, 'rb') as f:
                f.seek(self.hdr.banner_offset)
                ver = readle(f.read(2))
            
                calc_banner_size = False
                banner_sizes = { 0x0001: 0x0840,
                                0x0002: 0x0940,
                                0x0003: 0x1240,
                                0x0103: 0x23C0 }
                if self.hdr.unit_code == 0:
                    if ver in banner_sizes.keys():
                        size = banner_sizes[ver]
                        if ver == 0x0003:
                            f.seek(self.hdr.banner_offset + size - 1)
                            if f.read(33) != b'\x00' + b'\xFF' * 32:
                                calc_banner_size = True
                    else:
                        calc_banner_size = True
                elif self.hdr.unit_code == 2 or self.hdr.unit_code == 3:
                    size = self.hdr_ext.banner_size
            
                # Calculate banner size manually (need to do this for some NTR games)
                if calc_banner_size:
                    f.seek(self.hdr.banner_offset)
                    banner = f.read(0x1240)
                    off = banner[0x240:].find(b'\xFF' * 32) # Find the padding after the end of the banner
                    if off == -1: # Can't determine
                        size = 0x1240
                    else:
                        size = off + 0x240
            
            files['banner.bin'] = {
                'name': 'Banner',
                'offset': self.hdr.banner_offset,
                'size': size
            }
        
        if self.media == 'Game card' and (self.hdr.unit_code == 2 or self.hdr.unit_code == 3): # Only exists for game card SRLs
            if bytes(self.keytable_2) != b'\x00' * 0x3000:
                files['keytable2.bin'] = {
                    'name': 'KeyTable2',
                    'offset': self.hdr.data6 * 0x80000,
                    'size': 0x3000
                }

        if self.hdr.unit_code == 2 or self.hdr.unit_code == 3:
            if self.hdr_ext.arm9i_rom_offset:
                files['arm9i.bin'] = {
                    'name': 'ARM9i',
                    'offset': self.hdr_ext.arm9i_rom_offset,
                    'size': self.hdr_ext.arm9i_size
                }
            
            if self.hdr_ext.arm7i_rom_offset:
                files['arm7i.bin'] = {
                    'name': 'ARM7i',
                    'offset': self.hdr_ext.arm7i_rom_offset,
                    'size': self.hdr_ext.arm7i_size
                }
        
        # TODO: parse FNT/FAT
        self.files = files

        # Generate modcrypt keys (if present)
        if self.hdr.unit_code == 0:
            self.modcrypted = False
        elif self.hdr.unit_code == 2 or self.hdr.unit_code == 3:
            self.modcrypted = True
            if self.hdr.data1 >> 1 == 0:
                self.modcrypted = False
        
        modcrypt = []
        if self.modcrypted:
            if (self.hdr.data1 >> 2 & 1) or ((self.hdr_ext.flags >> 7) & 1): # ModcryptKeyDebug or DeveloperApp
                self.normal_key = bytes(self.hdr)[:16]
            else:
                keyX = b'Nintendo' + bytes(self.hdr.game_code) + bytes(self.hdr.game_code)[::-1]
                keyY = bytes(self.hdr_ext.arm9i_hmac)[:16]
                self.normal_key = TWL.key_scrambler(readle(keyX), readle(keyY))[::-1]
            self.normal_key = self.normal_key[::-1] # Key and IV needs to be reversed before use

            if self.hdr_ext.modcrypt_area_1_offset:
                modcrypt.append({
                    'name': 'modcrypt area 1',
                    'offset': self.hdr_ext.modcrypt_area_1_offset,
                    'size': self.hdr_ext.modcrypt_area_1_size,
                    'key': self.normal_key,
                    'counter': bytes(self.hdr_ext.arm9_hmac)[:16][::-1]
                })
            if self.hdr_ext.modcrypt_area_2_offset:
                modcrypt.append({
                    'name': 'modcrypt area 2',
                    'offset': self.hdr_ext.modcrypt_area_2_offset,
                    'size': self.hdr_ext.modcrypt_area_2_size,
                    'key': self.normal_key,
                    'counter': bytes(self.hdr_ext.arm7_hmac)[:16][::-1]
                })
        self.modcrypt = modcrypt

    def decrypt_secure_area(self, secure_area, key):
        # Checks
        if self.secure_area_status != 'encrypted':
            raise Exception(f'Secure area is {self.secure_area_status}, cannot be decrypted')
        
        # Initialize with level 2, modulo 8 and decrypt first 8 bytes of secure area
        key_lvl2 = init_keycode(key, readle(self.hdr.game_code), 2, 8)
        p1, p0 = blowfish_decrypt(key_lvl2, readle(secure_area[4:8]), readle(secure_area[:4]))
        secure_area = int32tobytes(p0) + int32tobytes(p1) + secure_area[8:]

        # Initialize again with level 3, modulo 8 and decrypt first 2KB of secure area
        key_lvl3 = init_keycode(key, readle(self.hdr.game_code), 3, 8)
        for i in range(0, 0x800, 8):
            p1, p0 = blowfish_decrypt(key_lvl3, readle(secure_area[i + 4:i + 8]), readle(secure_area[i:i + 4]))
            secure_area = secure_area[:i] + int32tobytes(p0) + int32tobytes(p1) + secure_area[i + 8:]
        
        game_code = self.hdr.game_code.decode("ascii")
        if game_code not in sec_area_id_special.keys():
            if readle(secure_area[:4]) == magic30 and readle(secure_area[4:8]) == magic34:
                secure_area = int32tobytes(decrypted_id) + int32tobytes(decrypted_id) + secure_area[8:]
            else:
                raise Exception('Secure area ID decryption failed')

            secure_area_crc = readle(secure_area[0xE:0x10])
            crc_calculated = crc16(list(secure_area[0x10:0x800]))
            if secure_area_crc != crc_calculated:
                raise Exception('Secure area CRC invalid')

        return secure_area

    def encrypt_secure_area(self, secure_area, key):
        # Checks
        if self.secure_area_status != 'decrypted':
            raise Exception(f'Secure area is {self.secure_area_status}, cannot be encrypted')
        
        # Set the secure area ID, which was overwritten with decrypted_id
        game_code = self.hdr.game_code.decode("ascii")
        if game_code not in sec_area_id_special.keys():
            secure_area = int32tobytes(magic30) + int32tobytes(magic34) + secure_area[8:]

        # Initialize with level 3, modulo 8 and encrypt first 2KB of secure area
        key_lvl3 = init_keycode(key, readle(self.hdr.game_code), 3, 8)
        for i in range(0, 0x800, 8):
            p1, p0 = blowfish_encrypt(key_lvl3, readle(secure_area[i + 4:i + 8]), readle(secure_area[i:i + 4]))
            secure_area = secure_area[:i] + int32tobytes(p0) + int32tobytes(p1) + secure_area[i + 8:]

        # Initialize with level 2, modulo 8 and encrypt first 8 bytes of secure area
        key_lvl2 = init_keycode(key, readle(self.hdr.game_code), 2, 8)
        p1, p0 = blowfish_encrypt(key_lvl2, readle(secure_area[4:8]), readle(secure_area[:4]))
        secure_area = int32tobytes(p0) + int32tobytes(p1) + secure_area[8:]

        return secure_area

    def regen_undumpable(self):
        # Checks
        if self.media == 'NAND':
            raise Exception('No undumpable region to re-generate for NAND SRL')

        with open(os.path.join(resources_dir, 'test_pattern.bin'), 'rb') as f:
            test_pattern = f.read()
        with open(os.path.join(resources_dir, 'keytable2_dev.bin'), 'rb') as f:
            keytable2_dev = f.read()

        shutil.copyfile(self.file, 'new.nds')
        with open('new.nds', 'r+b') as f:
            # KeyTable (NTR)
            key = init_keycode(NTR.blowfish_key, readle(self.hdr.game_code), 2, 8)

            f.seek(0x1600)
            for i in range(0, 18):
                f.write(int32tobytes(key[i]))
            
            f.seek(0x1C00)
            for i in range(18, 18 + 1024):
                f.write(int32tobytes(key[i]))

            f.seek(0x3000)
            f.write(test_pattern)

            # KeyTable2 (TWL)
            if self.hdr.unit_code == 2 or self.hdr.unit_code == 3:
                if self.dev:
                    f.seek(self.hdr.data6 * 0x80000)
                    f.write(keytable2_dev)
                else:
                    key = init_keycode(TWL.blowfish_key[0], readle(self.hdr.game_code), 1, 8)

                    f.seek(self.hdr.data6 * 0x80000 + 0x600)
                    for i in range(0, 18):
                        f.write(int32tobytes(key[i]))
                    
                    f.seek(self.hdr.data6 * 0x80000 + 0xC00)
                    for i in range(18, 18 + 1024):
                        f.write(int32tobytes(key[i]))
                    
                    f.seek(self.hdr.data6 * 0x80000 + 0x2000)
                    f.write(test_pattern)
        
        print('Wrote to new.nds')

    def decrypt_modcrypt(self):
        if self.modcrypted:
            shutil.copyfile(self.file, 'decrypted.nds')
            f = open(self.file, 'rb')
            for i in self.modcrypt:
                g = open('decrypted.nds', 'r+b')
                f.seek(i['offset'])
                g.seek(i['offset'])

                counter = Counter.new(128, initial_value=readbe(i['counter']))
                cipher = AES.new(i['key'], AES.MODE_CTR, counter=counter)
                for data in read_chunks(f, i['size']):
                    g.write(TWL.aes_ctr(cipher, data))
                
                print(f'Decrypted {i["name"]}')
                g.close()
            f.close()
            print(f'Wrote to decrypted.nds')
        else:
            raise Exception('Not modcrypted')

    def verify(self):
        # NOTE: Some checks (those that involve the ARM9) will report FAIL if (NTR) secure area is decrypted; since the HMACs are calculated over the ARM9 with encrypted secure area

        # Decrypt modcrypt first (if present) since HMACs and digests are calculated with modcrypt decrypted
        file = self.file
        if self.hdr.data1 >> 1 != 0:
            sys.stdout = open(os.devnull, 'w') # Block print statements
            self.decrypt_modcrypt()
            file = 'decrypted.nds'
            sys.stdout = sys.__stdout__

        crc_check = []
        with open(file, 'rb') as f:
            f.seek(self.hdr.arm9_rom_offset)
            data = f.read(0x4000)
            crc_check.append(('Secure area', crc16(list(data)) == self.hdr.secure_area_crc))

            f.seek(0xC0)
            data = f.read(0x9C)
            crc_check.append(('Nintendo logo', crc16(list(data)) == self.hdr.logo_crc))

            f.seek(0)
            data = f.read(0x15E)
            crc_check.append(('Header', crc16(list(data)) == self.hdr.hdr_crc))
        
        hmac_check = []
        if self.hdr.unit_code == 0:
            f = open(file, 'rb')
            
            if (self.hdr_ext.flags >> 5) & 1 and 'banner.bin' in self.files.keys():
                f.seek(self.files['banner.bin']['offset'])
                hmac_digest = hmac.new(key=TWL.hmac_key_whitelist34, digestmod=hashlib.sha1)
                for data in read_chunks(f, self.files['banner.bin']['size']):
                    hmac_digest.update(data)
                hmac_check.append(('Banner', hmac_digest.digest() == bytes(self.hdr_ext.banner_hmac)))
            
            if (self.hdr_ext.flags >> 6) & 1 and 'arm9.bin' in self.files.keys() and 'arm7.bin' in self.files.keys():
                hmac_digest = hmac.new(key=TWL.hmac_key_whitelist12, digestmod=hashlib.sha1)

                # Header
                f.seek(0)
                hmac_digest.update(f.read(0x160))

                # ARM9
                f.seek(self.files['arm9.bin']['offset'])
                for data in read_chunks(f, self.hdr.arm9_size):
                    hmac_digest.update(data)
                
                # ARM7
                f.seek(self.files['arm7.bin']['offset'])
                for data in read_chunks(f, self.files['arm7.bin']['size']):
                    hmac_digest.update(data)

                hmac_check.append(('Hdr,ARM9,ARM7', hmac_digest.digest() == bytes(self.hdr_ext.hdr_arm9_arm7_hmac)))
            
            if (self.hdr_ext.flags >> 6) & 1 and 'arm9overlay.bin' in self.files.keys() and self.hdr.fat_offset:
                hmac_digest = hmac.new(key=TWL.hmac_key_whitelist12, digestmod=hashlib.sha1)

                # ARM9 overlay
                f.seek(self.files['arm9overlay.bin']['offset'])
                for data in read_chunks(f, self.files['arm9overlay.bin']['size']):
                    hmac_digest.update(data)
                
                # FAT entries for ARM9 overlay
                num_overlays = self.files['arm9overlay.bin']['size'] // 0x20
                f.seek(self.hdr.fat_offset)
                for data in read_chunks(f, num_overlays * 8):
                    hmac_digest.update(data)
                
                # Partial content of overlays
                blocks_read = 0
                for i in range(num_overlays):
                    f.seek(self.hdr.fat_offset + (i * 8))
                    overlay_off = readle(f.read(4))
                    overlay_size = roundup(readle(f.read(4)) - overlay_off, block_size)

                    remaining_overlays = num_overlays - i
                    max_size = ((1 << 0xA) - blocks_read) // remaining_overlays * block_size
                    if overlay_size > max_size:
                        hash_size = max_size
                    else:
                        hash_size = overlay_size

                    f.seek(overlay_off)
                    for data in read_chunks(f, hash_size):
                        hmac_digest.update(data)
                    blocks_read += hash_size // block_size

                hmac_check.append(('ARM9overlayFAT', hmac_digest.digest() == bytes(self.hdr_ext.arm9overlay_fat_hmac)))

            f.close()
        elif self.hdr.unit_code == 2 or self.hdr.unit_code == 3:
            hmac_info = [('arm9.bin', bytes(self.hdr_ext.arm9_hmac)),
                         ('arm7.bin', bytes(self.hdr_ext.arm7_hmac)),
                         ('banner.bin', bytes(self.hdr_ext.banner_hmac)),
                         ('arm9i.bin', bytes(self.hdr_ext.arm9i_hmac)),
                         ('arm7i.bin', bytes(self.hdr_ext.arm7i_hmac))]
            f = open(file, 'rb')
            for fname, expected_digest in hmac_info:
                if fname in self.files.keys():
                    info = self.files[fname]
                    f.seek(info['offset'])
                    hmac_digest = hmac.new(key=TWL.hmac_key, digestmod=hashlib.sha1)
                    for data in read_chunks(f, info['size']):
                        hmac_digest.update(data)
                    hmac_check.append((info['name'], hmac_digest.digest() == expected_digest))
            
            expected_digest = bytes(self.hdr_ext.arm9_no_secure_area_hmac)
            if 'arm9.bin' in self.files.keys() and expected_digest != b'\x00' * 20:
                f.seek(self.files['arm9.bin']['offset'] + 0x4000)
                hmac_digest = hmac.new(key=TWL.hmac_key, digestmod=hashlib.sha1)
                for data in read_chunks(f, self.files['arm9.bin']['size'] - 0x4000):
                    hmac_digest.update(data)
                hmac_check.append(('ARM9 wosecarea', hmac_digest.digest() == expected_digest))
            f.close()

            # Digests
            f = open(file, 'rb')
            data = []
            info = [(self.hdr_ext.ntr_digest_region_offset, self.hdr_ext.ntr_digest_region_size),
                    (self.hdr_ext.twl_digest_region_offset, self.hdr_ext.twl_digest_region_size)]
            for off, size in info:
                f.seek(off)
                data += [f.read(self.hdr_ext.digest1_block_size) for _ in range(size // self.hdr_ext.digest1_block_size)]
            digest1 = b''.join([hmac.new(key=TWL.hmac_key, msg=i, digestmod=hashlib.sha1).digest() for i in data])
            f.seek(self.hdr_ext.digest1_table_offset)
            expected_digest = f.read(self.hdr_ext.digest1_table_size)
            hmac_check.append(('Digest1 table', expected_digest[:len(digest1)] == digest1))

            block_len = self.hdr_ext.digest2_digest1_count * 20
            data = [digest1[i * block_len:(i + 1) * block_len].ljust(block_len, b'\x00') for i in range(self.hdr_ext.digest2_table_size // 20)]
            digest2 = b''.join([hmac.new(key=TWL.hmac_key, msg=i, digestmod=hashlib.sha1).digest() for i in data])
            f.seek(self.hdr_ext.digest2_table_offset)
            expected_digest = f.read(self.hdr_ext.digest2_table_size)
            hmac_check.append(('Digest2 table', expected_digest == digest2))
            f.close()

            hmac_digest = hmac.new(key=TWL.hmac_key, msg=digest2, digestmod=hashlib.sha1)
            hmac_check.append(('Digest2', bytes(self.hdr_ext.digest2_hmac) == hmac_digest.digest()))

        sig_check = []
        # Header signature is the raw SHA1 hash (with padding); easier to manually decrypt and remove the padding
        if (self.hdr_ext.flags >> 6) & 1 or self.hdr.unit_code == 2 or self.hdr.unit_code == 3:
            idx = get_rsa_key_idx(self.hdr, self.hdr_ext)
            n = readbe(TWL.rsa_key_mod[idx][self.dev])
            e = 0x10001
            dec = pow(readbe(bytes(self.hdr_ext.sig)), e, n).to_bytes(0x80, 'big')
            
            f = open(self.file, 'rb')
            sha1_calculated = Cryptodome.sha1(f, 0xE00)
            f.close()
            sig_check.append(('Header', dec[-20:] == sha1_calculated))

        print("CRCs:")
        for i in crc_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
        if hmac_check != []:
            print("HMACs:")
            for i in hmac_check:
                print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
        if sig_check != []:
            print("Signatures:")
            for i in sig_check:
                print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

        if os.path.isfile('decrypted.nds'):
            os.remove('decrypted.nds')

    def __str__(self):
        unit_code = {
            0: 'DS',
            2: 'DSi Enhanced',
            3: 'DSi Exclusive',
        }

        ntr = (
            f'Game title:            {self.hdr.game_title.decode("ascii")}\n'
            f'Game code:             {self.hdr.game_code.decode("ascii")}\n'
            f'Maker code:            {self.hdr.maker_code.decode("ascii")}\n'
            f'Unit code:             {unit_code[self.hdr.unit_code]}\n'
            f'Encryption seed:       {hex(self.hdr.encryption_seed_select)[2:].zfill(2)}\n'
            f'Chip size (KB):        {128 << self.hdr.device_capacity}\n'
            f'ROM version:           {self.hdr.rom_ver}\n'
            f'Autostart:             {"Yes" if (self.hdr.autostart >> 2) & 1 else "No"}'
        )

        if self.hdr.unit_code == 2 or self.hdr.unit_code == 3:
            reg = ''
            if self.hdr_ext.region == 0xFFFFFFFF:
                reg = 'Region free'
            else:
                if self.hdr_ext.region & 1: reg += 'Japan, '
                if (self.hdr_ext.region >> 1) & 1: reg += 'USA, '
                if (self.hdr_ext.region >> 2) & 1: reg += 'Europe, '
                if (self.hdr_ext.region >> 3) & 1: reg += 'Australia, '
                if (self.hdr_ext.region >> 4) & 1: reg += 'China, '
                if (self.hdr_ext.region >> 5) & 1: reg += 'Korea, '
                reg = reg[:-2]
            
            def split_parental_control(b):
                parental_ctrl = str(b & 0b00001111) # age
                if (b >> 6) & 1:
                    parental_ctrl += ', prohibited in country'
                elif (b >> 7) & 1:
                    parental_ctrl += ', rating valid'
                return parental_ctrl

            twl = (
                f'\nCrypto flags:\n'
                f' > Has DSi excl region:{"Yes" if self.hdr.data1 & 1 else "No"}\n'
                f' > Modcrypted:         {"Yes" if (self.hdr.data1 >> 1) & 1 else "No"}\n'
                f' > Modcrypt key:       {"Debug" if (self.hdr.data1 >> 2) & 1 else "Retail"}\n'
                f' > Disable debug:      {"Yes" if (self.hdr.data1 >> 3) & 1 else "No"}\n'
                f'Permit jump:\n'
                f'  Normal jump:         {self.hdr.data2 & 1}\n'
                f'  Temporary jump:      {(self.hdr.data2 >> 1) & 1}\n'
                f'Region:                {reg}\n'
                f'Access control:\n'
                f'  Common client key:   {self.hdr_ext.access_control & 1}\n'
                f'  AES slot B:          {(self.hdr_ext.access_control >> 1) & 1}\n'
                f'  AES slot C:          {(self.hdr_ext.access_control >> 2) & 1}\n'
                f'  SD card:             {(self.hdr_ext.access_control >> 3) & 1}\n'
                f'  NAND access:         {(self.hdr_ext.access_control >> 4) & 1}\n'
                f'  Game card power on:  {(self.hdr_ext.access_control >> 5) & 1}\n'
                f'  Shared2 file:        {(self.hdr_ext.access_control >> 6) & 1}\n'
                f'  SignJPEGforlauncher: {(self.hdr_ext.access_control >> 7) & 1}\n'
                f'  Game card NTR mode:  {(self.hdr_ext.access_control >> 8) & 1}\n'
                f'  SSL client cert:     {(self.hdr_ext.access_control >> 9) & 1}\n'
                f'  Commonclientkeydev:  {(self.hdr_ext.access_control >> 31) & 1}\n'
                f'Flags:\n'
                f' > TSC mode:           {"DSi" if self.hdr_ext.flags & 1 else "DS"}\n'
                f' > EULA required:      {"Yes" if (self.hdr_ext.flags >> 1) & 1 else "No"}\n'
                f' > Banner:             {"Use banner.sav" if (self.hdr_ext.flags >> 2) & 1 else "From ROM"}\n'
                f' > ShowWiFiconnicon:   {"Yes" if (self.hdr_ext.flags >> 3) & 1 else "No"}\n'
                f' > ShowDSwirelessicon: {"Yes" if (self.hdr_ext.flags >> 4) & 1 else "No"}\n'
                f' > DScartwithiconSHA1: {"Yes" if (self.hdr_ext.flags >> 5) & 1 else "No"}\n'
                f' > DScartwithheaderRSA:{"Yes" if (self.hdr_ext.flags >> 6) & 1 else "No"}\n'
                f' > Developer app:      {"Yes" if (self.hdr_ext.flags >> 7) & 1 else "No"}\n'
                f'EULA ver:              {self.hdr_ext.eula_ver}\n'
                f'TitleID:               {hex(self.hdr_ext.titleID_hi)[2:].zfill(8) + hex(self.hdr_ext.titleID_lo)[2:].zfill(8)}\n'
                f'  Media:               {"NAND" if (self.hdr_ext.titleID_hi >> 2) & 1 else "Game card"}\n'
                f'Parental control:\n'
                f'  CERO (Japan):        {split_parental_control(self.hdr_ext.parental_control[0])}\n'
                f'  ESRB (USA/Canada):   {split_parental_control(self.hdr_ext.parental_control[1])}\n'
                f'  USK (Germany):       {split_parental_control(self.hdr_ext.parental_control[3])}\n'
                f'  PEGI (Pan-Europe):   {split_parental_control(self.hdr_ext.parental_control[4])}\n'
                f'  PEGI (Portugal):     {split_parental_control(self.hdr_ext.parental_control[6])}\n'
                f'  PEGI and BBFC (UK):  {split_parental_control(self.hdr_ext.parental_control[7])}\n'
                f'  AGCB (Australia):    {split_parental_control(self.hdr_ext.parental_control[8])}\n'
                f'  GRB (South Korea):   {split_parental_control(self.hdr_ext.parental_control[9])}'
            )

            return ntr + twl
        else:
            if self.hdr.data2 == 0:
                reg = 'Normal'
            elif self.hdr.data2 == 0x40:
                reg = 'Korea'
            elif self.hdr.data2 == 0x80:
                reg = 'China'
            ntr += f'\nRegion:                {reg}'

            if self.hdr_ext.flags != 0:
                ntr += (
                    f'\nFlags:\n'
                    f' > TSC mode:           {"DSi" if self.hdr_ext.flags & 1 else "DS"}\n'
                    f' > EULA required:      {"Yes" if (self.hdr_ext.flags >> 1) & 1 else "No"}\n'
                    f' > Banner:             {"Use banner.sav" if (self.hdr_ext.flags >> 2) & 1 else "From cartridge"}\n'
                    f' > ShowWiFiconnicon:   {"Yes" if (self.hdr_ext.flags >> 3) & 1 else "No"}\n'
                    f' > ShowDSwirelessicon: {"Yes" if (self.hdr_ext.flags >> 4) & 1 else "No"}\n'
                    f' > DScartwithiconSHA1: {"Yes" if (self.hdr_ext.flags >> 5) & 1 else "No"}\n'
                    f' > DScartwithheaderRSA:{"Yes" if (self.hdr_ext.flags >> 6) & 1 else "No"}\n'
                    f' > Developer app:      {"Yes" if (self.hdr_ext.flags >> 7) & 1 else "No"}'
                )

            return ntr