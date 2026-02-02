from .common import *
from .keys import *

unused = 0xFFFFFFFF
block_size = 0x1000

class RomFSHdr(Structure):
    _pack_ = 1

    _fields_ = [
        ('magic', c_char * 4),
        ('magic_num', c_uint32),
        ('master_hash_size', c_uint32),
        ('lvl1_logical_offset', c_uint64),
        ('lvl1_hash_size', c_uint64),
        ('lvl1_block_size', c_uint32),
        ('reserved1', c_uint32),
        ('lvl2_logical_offset', c_uint64),
        ('lvl2_hash_size', c_uint64),
        ('lvl2_block_size', c_uint32),
        ('reserved2', c_uint32),
        ('lvl3_logical_offset', c_uint64),
        ('lvl3_size', c_uint64),
        ('lvl3_block_size', c_uint32),
        ('reserved3', c_uint32),
        ('hdr_size', c_uint32),
        ('optional_size', c_uint32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class RomFSL3Hdr(Structure):
    _pack_ = 1

    _fields_ = [
        ('hdr_len', c_uint32),
        ('dir_hash_off', c_uint32),
        ('dir_hash_len', c_uint32),
        ('dir_meta_off', c_uint32),
        ('dir_meta_len', c_uint32),
        ('file_hash_off', c_uint32),
        ('file_hash_len', c_uint32),
        ('file_meta_off', c_uint32),
        ('file_meta_len', c_uint32),
        ('file_data_off', c_uint32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class RomFSDirMetaRecord(Structure):
    _pack_ = 1

    _fields_ = [
        ('parent_off', c_uint32),
        ('next_dir_off', c_uint32),
        ('first_child_dir_off', c_uint32),
        ('first_file_off', c_uint32),
        ('hash_pointer', c_uint32),
        ('name_len', c_uint32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class RomFSFileMetaRecord(Structure):
    _pack_ = 1

    _fields_ = [
        ('parent_off', c_uint32),
        ('next_file_off', c_uint32),
        ('data_off', c_uint64),
        ('data_len', c_uint64),
        ('hash_pointer', c_uint32),
        ('name_len', c_uint32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

def get_hash_table_len(num):
    count = num
    if num < 3:
        count = 3
    elif num < 19:
        count |= 1
    else:
        while (count % 2 == 0
            or count % 3 == 0
            or count % 5 == 0
            or count % 7 == 0
            or count % 11 == 0
            or count % 13 == 0
            or count % 17 == 0):
            count += 1
    return count

def calc_path_hash(name, parent_off):
    h = parent_off ^ 123456789
    for j in range(len(name) // 2):
        i = j * 2
        h = (h >> 5) | (h << 27)
        h ^= (name[i]) | (name[i + 1] << 8)
        h &= 0xFFFFFFFF
    return h

class RomFSReader:
    def __init__(self, file, lvl3only=False):
        self.file = file
        self.lvl3only = lvl3only

        if not lvl3only:
            with open(file, 'rb') as f:
                self.hdr = RomFSHdr(f.read(0x5C))

            self.lvl1_block_size = 1 << self.hdr.lvl1_block_size
            self.lvl2_block_size = 1 << self.hdr.lvl2_block_size
            self.lvl3_block_size = 1 << self.hdr.lvl3_block_size

            # Get offsets for RomFS components
            hashes = {}
            curr = 0x60

            hashes['Master Hash'] = {
                'size': self.hdr.master_hash_size,
                'offset': curr
            }
            curr += hashes['Master Hash']['size']

            curr += align(curr, self.lvl3_block_size)
            self.lvl3_offset = curr
            curr += self.hdr.lvl3_size

            curr += align(curr, self.lvl1_block_size)
            hashes['Level 1'] = {
                'size': self.hdr.lvl1_hash_size,
                'offset': curr
            }
            curr += hashes['Level 1']['size']

            curr += align(curr, self.lvl2_block_size)
            hashes['Level 2'] = {
                'size': self.hdr.lvl2_hash_size,
                'offset': curr
            }
            curr += hashes['Level 2']['size']

            self.hashes = hashes
        else:
            self.lvl3_offset = 0

        # Parse level 3 (actual data)
        self.files = {}
        self.dirs = [] # Save all dir paths in case of empty dir

        def valid(a):
            return a != unused

        def extract_file(file_offset, parent_name):
            while valid(file_offset):
                f.seek(self.lvl3_offset + self.lvl3_hdr.file_meta_off + file_offset)
                file_meta = RomFSFileMetaRecord(f.read(0x20))
                name = f.read(file_meta.name_len).decode('utf-16le')
                name2 = os.path.join(parent_name, name)

                self.files[name2] = {
                    'size': file_meta.data_len,
                    'offset': self.lvl3_offset + self.lvl3_hdr.file_data_off + file_meta.data_off
                }
                file_offset = file_meta.next_file_off

        def extract_dir(dir_offset, parent_name):
            while valid(dir_offset):
                f.seek(self.lvl3_offset + self.lvl3_hdr.dir_meta_off + dir_offset)
                dir_meta = RomFSDirMetaRecord(f.read(0x18))
                name = f.read(dir_meta.name_len).decode('utf-16le')
                name2 = os.path.join(parent_name, name)
                self.dirs.append(name2)

                if valid(dir_meta.first_file_off):
                    extract_file(dir_meta.first_file_off, name2)
                if valid(dir_meta.first_child_dir_off):
                    extract_dir(dir_meta.first_child_dir_off, name2)
                dir_offset = dir_meta.next_dir_off

        with open(file, 'rb') as f:
            f.seek(self.lvl3_offset)
            self.lvl3_hdr = RomFSL3Hdr(f.read(0x28))
            extract_dir(0, '')

    def extract(self):
        output_dir = 'romfs/'
        f = open(self.file, 'rb')
        for i in self.dirs:
            path = os.path.join(output_dir, i)
            if not os.path.isdir(path):
                os.makedirs(path, exist_ok=True) # Same function as mkdir -p

        for path, info in self.files.items():
            f.seek(info['offset'])
            g = open(os.path.join(output_dir, path), 'wb')
            for data in read_chunks(f, info['size']):
                g.write(data)
            g.close()

        f.close()
        print(f'Extracted to {output_dir}')

    def verify(self):
        if not self.lvl3only:
            f = open(self.file, 'rb')

            hash_check = []
            hash_check_info = [
                ('Master Hash', self.hashes['Level 1']['offset'], self.lvl1_block_size), # Master hash verifies level 1
                ('Level 1', self.hashes['Level 2']['offset'], self.lvl2_block_size), # Level 1 verifies level 2
                ('Level 2', self.lvl3_offset, self.lvl3_block_size) # Level 2 verifies level 3
            ]
            for name, off, block_size in hash_check_info:
                f.seek(self.hashes[name]['offset'])
                hashes = f.read(self.hashes[name]['size'])
                num_blocks = len(hashes) // 0x20
                checks = []
                f.seek(off)

                for i in range(num_blocks):
                    h = hashlib.sha256()
                    h.update(f.read(block_size))
                    checks.append(h.digest() == hashes[i * 0x20:(i + 1) * 0x20])
                hash_check.append((name, all(checks)))

            f.close()
            print("Hashes:")
            for i in hash_check:
                print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

class RomFSBuilder:
    def __init__(self, romfs_dir='', out='romfs.bin'):
        '''
        romfs_dir: path to directory where objects inside will be added to romfs
        out: path to output file
        '''

        # Find total number of files and dirs to get length of file hash table and dir hash table
        num_files = 0
        num_dirs = 1
        for root, dirs, files in os.walk(romfs_dir):
            num_files += len(files)
            num_dirs += len(dirs)
        file_hash_table = [unused] * get_hash_table_len(num_files)
        dir_hash_table = [unused] * get_hash_table_len(num_dirs)

        # Create dir meta record for root dir
        dir_meta_table = []
        file_meta_table = []
        file_data = []
        dir_meta_off = file_meta_off = file_data_off = file_data_size = 0

        root_dir_meta = RomFSDirMetaRecord(b'\x00' * 0x18)
        root_dir_meta.next_dir_off = root_dir_meta.first_child_dir_off = root_dir_meta.first_file_off = unused
        hash_index = calc_path_hash(b'', 0) % len(dir_hash_table)
        root_dir_meta.hash_pointer = dir_hash_table[hash_index]
        dir_hash_table[hash_index] = dir_meta_off
        dir_meta_off += 0x18
        dir_meta_table.append([root_dir_meta, b''])

        # Recursively traverse romfs_dir to fill in dir meta, dir hash, file meta, file hash tables
        def add_dir_children(path, parent_dir_off, parent_dir_idx):
            nonlocal dir_meta_off, file_meta_off, file_data_off, file_data_size

            objs = os.listdir(path)
            files = []
            dirs = []
            for i in objs:
                path2 = os.path.join(path, i)
                if os.path.isfile(path2):
                    files.append(path2)
                elif os.path.isdir(path2):
                    dirs.append(path2)
            files.sort(key = lambda c: os.path.basename(c).upper())
            dirs.sort(key = lambda c: os.path.basename(c).upper())

            for i in range(len(files)):
                if i == 0: # set parent dir_meta's first_file_off
                    dir_meta_table[parent_dir_idx][0].first_file_off = file_meta_off

                file_meta = RomFSFileMetaRecord(b'\x00' * 0x20)
                file_meta.parent_off = parent_dir_off
                file_meta.data_off = file_data_off
                file_meta.data_len = os.path.getsize(files[i])

                utf16name = os.path.basename(files[i]).encode('utf_16_le')
                hash_index = calc_path_hash(utf16name, parent_dir_off) % len(file_hash_table)
                file_meta.hash_pointer = file_hash_table[hash_index]
                file_hash_table[hash_index] = file_meta_off # separate chaining hash table, newly added file/dir is added as head element of linked list

                file_meta.name_len = len(utf16name)
                file_meta_off += 0x20 + len(utf16name) + align(len(utf16name), 4)
                if i != len(files) - 1:
                    file_meta.next_file_off = file_meta_off
                else:
                    file_meta.next_file_off = unused
                file_data_off += file_meta.data_len + align(file_meta.data_len, 16)

                file_meta_table.append([file_meta, utf16name])
                file_data.append([files[i], file_meta.data_len])
                file_data_size += align(file_data_size, 16)
                file_data_size += file_meta.data_len

            child_dirs = []
            for i in range(len(dirs)):
                if i == 0: # set parent dir_meta's first_child_dir_off
                    dir_meta_table[parent_dir_idx][0].first_child_dir_off = dir_meta_off

                dir_meta = RomFSDirMetaRecord(b'\x00' * 0x18)
                dir_meta.first_child_dir_off = dir_meta.first_file_off = unused
                dir_meta.parent_off = parent_dir_off

                utf16name = os.path.basename(dirs[i]).encode('utf_16_le')
                hash_index = calc_path_hash(utf16name, parent_dir_off) % len(dir_hash_table)
                dir_meta.hash_pointer = dir_hash_table[hash_index]
                dir_hash_table[hash_index] = dir_meta_off

                child_dirs.append((dirs[i], dir_meta_off, len(dir_meta_table))) # current dir_meta will have index len(dir_meta_table) after it is appended
                dir_meta.name_len = len(utf16name)
                dir_meta_off += 0x18 + len(utf16name) + align(len(utf16name), 4)
                if i != len(dirs) - 1:
                    dir_meta.next_dir_off = dir_meta_off
                else:
                    dir_meta.next_dir_off = unused

                dir_meta_table.append([dir_meta, utf16name])

            for path, dir_off, dir_idx in child_dirs: # current dir's subdirs are all added to dir_meta_table before subdir's subdirs are added
                add_dir_children(path, dir_off, dir_idx)

        add_dir_children(romfs_dir, 0, 0)

        # Create level 3 header
        lvl3_hdr = RomFSL3Hdr(b'\x00' * 0x28)
        offset = 0x28
        lvl3_hdr.hdr_len = 0x28

        lvl3_hdr.dir_hash_off = offset
        lvl3_hdr.dir_hash_len = 4 * len(dir_hash_table)
        offset += lvl3_hdr.dir_hash_len

        lvl3_hdr.dir_meta_off = offset
        lvl3_hdr.dir_meta_len = dir_meta_off
        offset += lvl3_hdr.dir_meta_len

        lvl3_hdr.file_hash_off = offset
        lvl3_hdr.file_hash_len = 4 * len(file_hash_table)
        offset += lvl3_hdr.file_hash_len

        lvl3_hdr.file_meta_off = offset
        lvl3_hdr.file_meta_len = file_meta_off
        offset += lvl3_hdr.file_meta_len

        offset += align(offset, 16)
        lvl3_hdr.file_data_off = offset

        # Create RomFS header
        hdr = RomFSHdr(b'\x00' * 0x5C)
        hdr.magic = b'IVFC'
        hdr.magic_num = 65536
        hdr.lvl1_block_size = hdr.lvl2_block_size = hdr.lvl3_block_size = int(math.log2(block_size))

        hdr.lvl3_size = lvl3_hdr.file_data_off + file_data_size
        hdr.lvl2_hash_size = roundup(hdr.lvl3_size, block_size) // block_size * 0x20
        hdr.lvl1_hash_size = roundup(hdr.lvl2_hash_size, block_size) // block_size * 0x20
        hdr.master_hash_size = roundup(hdr.lvl1_hash_size, block_size) // block_size * 0x20

        hdr.lvl2_logical_offset = roundup(hdr.lvl1_logical_offset + hdr.lvl1_hash_size, block_size)
        hdr.lvl3_logical_offset = roundup(hdr.lvl2_logical_offset + hdr.lvl2_hash_size, block_size)
        hdr.hdr_size = 0x5C

        # Calculate offsets
        lvl3_off = roundup(0x60 + hdr.master_hash_size, block_size)
        lvl1_off = lvl3_off + roundup(hdr.lvl3_size, block_size)
        lvl2_off = lvl1_off + roundup(hdr.lvl1_hash_size, block_size)

        # Write RomFS header and level 3
        with open(out, 'wb') as f:
            f.write(bytes(hdr))
            f.write(b'\x00' * (lvl3_off - f.tell()))
            f.write(bytes(lvl3_hdr))

            for i in dir_hash_table:
                f.write(int32tobytes(i))

            for dir_meta, name in dir_meta_table:
                f.write(bytes(dir_meta))
                f.write(name)
                f.write(b'\x00' * align(len(name), 4))

            for i in file_hash_table:
                f.write(int32tobytes(i))

            for file_meta, name in file_meta_table:
                f.write(bytes(file_meta))
                f.write(name)
                f.write(b'\x00' * align(len(name), 4))

            for file, size in file_data:
                f.write(b'\x00' * align(f.tell(), 16))
                g = open(file, 'rb')
                for data in read_chunks(g, size):
                    f.write(data)
                g.close()

        # Calculate and write master hash, level 1, level 2
        hash_info = [ (lvl3_off, hdr.lvl2_hash_size, lvl2_off),
                      (lvl2_off, hdr.lvl1_hash_size, lvl1_off),
                      (lvl1_off, hdr.master_hash_size, 0x60) ]

        with open(out, 'r+b') as f:
            f.seek(lvl3_off + hdr.lvl3_size)
            f.write(b'\x00' * (lvl2_off + hdr.lvl2_hash_size - f.tell()))
            f.write(b'\x00' * align(f.tell(), block_size)) # padding after level 2
            for off_read, size, off_write in hash_info:
                for i in range(size // 0x20):
                    f.seek(off_read + i * block_size)
                    h = hashlib.sha256()
                    h.update(f.read(block_size))
                    f.seek(off_write + i * 0x20)
                    f.write(h.digest())
        print(f'Wrote to {out}')
