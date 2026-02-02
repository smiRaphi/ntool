from .common import *
from .keys import *

page_size = 0x800
ecc_size = 0x40
clusters_count = 0x8000

class FSTEntry(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('filename', c_char * 0x0C),
        ('mode', c_uint8),
        ('attrib', c_uint8),
        ('sub', c_uint16),
        ('sib', c_uint16),
        ('filesize', c_uint32),
        ('uid', c_uint32),
        ('gid', c_uint16),
        ('x3', c_uint32)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class FSTEntryECC(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('filename', c_char * 0x0C),
        ('mode', c_uint8),
        ('attrib', c_uint8),
        ('sub', c_uint16),
        ('sib', c_uint16),
        ('filesize1', c_uint16),
        ('ecc', c_uint8 * 0x40),
        ('filesize2', c_uint16),
        ('uid', c_uint32),
        ('gid', c_uint16),
        ('x3', c_uint32)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class HMACMetaExtra(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('padding', c_uint8 * 0x12),
        ('cluster', c_uint16),
        ('padding2', c_uint8 * 0x2C),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class HMACFileExtra(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('uid', c_uint32),
        ('filename', c_char * 0x0C),
        ('index', c_uint32),
        ('fst_entry', c_uint32),
        ('x3', c_uint32),
        ('padding', c_uint8 * 0x24),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class RVLNANDReader:
    def __init__(self, nand, keys=''): # keys: must be named either 'keys.bin' or 'otp.bin'
        self.nand = nand
        self.keys = keys

        nand_size = os.path.getsize(nand)
        if nand_size == page_size * 8 * clusters_count:
            self.file_type = 'No ECC'
        elif nand_size == (page_size + ecc_size) * 8 * clusters_count:
            self.file_type = 'Has ECC'
        elif nand_size == (page_size + ecc_size) * 8 * clusters_count + 0x400:
            self.file_type = 'BootMii, with ECC'
        else:
            raise Exception('NAND has unknown file size')

        if self.file_type == 'No ECC':
            self.page_size = page_size
        else:
            self.page_size = page_size + ecc_size
        self.cluster_size = self.page_size * 8

        with open(nand, 'rb') as f:
            f.seek(self.cluster_size * 0x7FF0)
            magic = f.read(4)
            if magic == b'SFFS': # Wii NAND / Wii U SLCCMPT
                self.nand_type = 'Wii'
            elif magic == b'SFS!': # Wii U SLC
                self.nand_type = 'Wii U'
            else:
                raise Exception('Could not find valid superblock magic')

        # Get AES key, HMAC key
        if keys != '':
            if os.path.basename(keys) == 'keys.bin':
                offset_hmac = 0x144
                offset_aes = 0x158
            elif os.path.basename(keys) == 'otp.bin':
                if self.nand_type == 'Wii':
                    offset_hmac = 0x44
                    offset_aes = 0x58
                else:
                    offset_hmac = 0x1E0
                    offset_aes = 0x170
            with open(keys, 'rb') as f:
                f.seek(offset_hmac)
                self.hmac_key = f.read(20)
                f.seek(offset_aes)
                self.aes_key = f.read(16)
        else:
            if self.file_type == 'BootMii, with ECC':
                with open(nand, 'rb') as f:
                    f.seek(0x21000144)
                    self.hmac_key = f.read(20)
                    f.seek(0x21000158)
                    self.aes_key = f.read(16)
            else:
                raise Exception('Could not get keys')

        # Find superblock with largest generation number
        if self.nand_type == 'Wii':
            self.first_superblock_cluster = 0x7F00
        else:
            self.first_superblock_cluster = 0x7C00
        largest = -1
        self.superblock_off = 0
        with open(nand, 'rb') as f:
            for i in range(self.cluster_size * self.first_superblock_cluster, self.cluster_size * clusters_count, self.cluster_size * 16):
                f.seek(i)
                magic = f.read(4)
                if magic == b'SFFS' or magic == b'SFS!':
                    curr = readbe(f.read(4))
                    if curr > largest:
                        largest = curr
                        self.superblock_off = i
        if self.superblock_off == 0:
            raise Exception('Could not find superblock')

        self.fat_size = self.cluster_size * 4
        self.fat_off = self.superblock_off
        self.fst_off = self.fat_off + 0xC + self.fat_size

        self.files = {}
        self.dirs = [] # Save all dir paths in case of empty dir

        def extract_file(fst, entry, parent):
            name = fst.filename.decode("ascii").replace(':', '-')
            name2 = os.path.join(parent, name)
            if type(fst) == FSTEntryECC:
                size = (fst.filesize1 << 16) | fst.filesize2
            else:
                size = fst.filesize
            self.files[name2] = {
                'cluster': fst.sub,
                'size': size,
                # For HMAC calculations:
                'entry': entry,
                'fst': fst
            }

        def extract_dir(fst, parent):
            name = fst.filename.decode("ascii")
            name2 = os.path.join(parent, name)
            self.dirs.append(name2)
            if fst.sub != 0xFFFF: # Not an empty dir
                extract_fst(fst.sub, name2)

        def extract_fst(entry, parent):
            if self.file_type == 'No ECC':
                offset = entry * 0x20 # 0x20 is the length of 1 FST entry
            else:
                offset = entry * 0x20 + (entry // 64 * ecc_size) # Compensate for ECC every 64 FST entries

            f.seek(self.fst_off + offset)
            if self.file_type != 'No ECC' and (entry + 1) % 64 == 0: # Every 64th FST entry is interrupted by ECC
                fst = FSTEntryECC(f.read(0x20 + 0x40))
            else:
                fst = FSTEntry(f.read(0x20))

            if fst.sib != 0xFFFF:
                extract_fst(fst.sib, parent)

            if (fst.mode & 3) == 1:
                extract_file(fst, entry, parent)
            elif (fst.mode & 3) == 2:
                extract_dir(fst, parent)

        with open(nand, 'rb') as f:
            extract_fst(0, '')

    def get_cluster_data(self, f, entry):
        f.seek(self.cluster_size * entry)
        cluster = b''.join([f.read(self.page_size)[:0x800] for page in range(8)]) # Only take 0x800 bytes for each page_size since we don't want the ECC
        if entry < self.first_superblock_cluster:
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=b'\x00'*16)
            cluster = cipher.decrypt(cluster)
        return cluster

    def next_fat(self, f, fat): # Find next cluster in the chain
        fat += 6 # Compensate for 0xC bytes at beginning of superblock
        if self.file_type == 'No ECC':
            offset = fat * 2
        else:
            offset = fat * 2 + (fat // 0x400 * ecc_size) # Compensate for ECC every 0x400 FAT entries
        f.seek(self.fat_off + offset)
        return readbe(f.read(2))

    def extract(self):
        output_dir = 'nand/'
        f = open(self.nand, 'rb')
        for i in self.dirs:
            path = os.path.join(output_dir, i[1:]) # Ignore first char of the path, which is '/'
            if not os.path.isdir(path):
                os.makedirs(path, exist_ok=True)

        for path, info in self.files.items():
            fat = info['cluster']
            data = b''
            while fat < 0xFFF0:
                data += self.get_cluster_data(f, fat) # Read and decrypt cluster
                fat = self.next_fat(f, fat)

            g = open(os.path.join(output_dir, path[1:]), 'wb')
            g.write(data[:info['size']])
            g.close()

        f.close()
        print(f'Extracted to {output_dir}')

    def verify(self):
        def check_ecc_hmac(ecc_1, ecc_2, hmac_calculated):
            return ecc_1[0x1:0x15] == hmac_calculated and ecc_1[0x15:0x21] == hmac_calculated[:0xC] and ecc_2[0x1:0x9] == hmac_calculated[0xC:]

        hmac_superblocks = []
        hmac_files = []
        if self.file_type != 'No ECC':
            with open(self.nand, 'rb') as f:
                # HMACs for superblocks
                for i in range(self.first_superblock_cluster, clusters_count, 16):
                    superblock = b''.join([self.get_cluster_data(f, i + j) for j in range(16)])
                    extra = HMACMetaExtra(b'\x00' * 0x40)
                    extra.cluster = i
                    hmac_digest = hmac.new(key=self.hmac_key, msg=bytes(extra)+superblock, digestmod=hashlib.sha1)

                    f.seek(-0x40, 1)
                    ecc_2 = f.read(0x40) # ECC data for 8th page
                    f.seek(-(0x840 + 0x40), 1)
                    ecc_1 = f.read(0x40) # ECC data for 7th page
                    hmac_superblocks.append((i, check_ecc_hmac(ecc_1, ecc_2, hmac_digest.digest())))

                # HMACs for files
                for path, info in self.files.items():
                    fat = info['cluster']
                    i = 0
                    checks = []
                    while fat < 0xFFF0:
                        cluster = self.get_cluster_data(f, fat)
                        extra = HMACFileExtra(b'\x00' * 0x40)
                        extra.uid = info['fst'].uid
                        extra.filename = info['fst'].filename
                        extra.index = i
                        extra.fst_entry = info['entry']
                        extra.x3 = info['fst'].x3
                        hmac_digest = hmac.new(key=self.hmac_key, msg=bytes(extra)+cluster, digestmod=hashlib.sha1)

                        f.seek(-0x40, 1)
                        ecc_2 = f.read(0x40) # ECC data for 8th page
                        f.seek(-(0x840 + 0x40), 1)
                        ecc_1 = f.read(0x40) # ECC data for 7th page
                        checks.append(check_ecc_hmac(ecc_1, ecc_2, hmac_digest.digest()))

                        fat = self.next_fat(f, fat)
                        i += 1
                    hmac_files.append((path, all(checks)))

        if not (hmac_superblocks == [] and hmac_files == []):
            print("HMACs:")
        if hmac_superblocks != []:
            if all([i[1] for i in hmac_superblocks]):
                print(' > Superblocks: GOOD')
            else:
                print(f' > Superblocks: FAIL for superblocks beginning at these clusters: {" ".join([hex(i[0])[2:] for i in hmac_superblocks if not i[1]])}')
        if hmac_files != []:
            if all([i[1] for i in hmac_files]):
                print(' > Files:       GOOD')
            else:
                print(f' > Files:       FAIL for: {" ".join([i[0] for i in hmac_files if not i[1]])}')