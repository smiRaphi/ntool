from .common import *
from .keys import *

class croHdr(Structure):
    _pack_ = 1

    _fields_ = [
        ('hdr_hash', c_uint8 * 0x20),
        ('sect0_hash', c_uint8 * 0x20),
        ('sect1_hash', c_uint8 * 0x20),
        ('sect2_hash', c_uint8 * 0x20),
        ('magic', c_char * 4),
        ('name_offset', c_uint32),
        ('next_cro', c_uint32),
        ('prev_cro', c_uint32),
        ('file_size', c_uint32),
        ('bss_size', c_uint32),
        ('unk1', c_uint32),
        ('unk2', c_uint32),
        ('segment_offset_nnroControlObject', c_uint32),
        ('segment_offset_OnLoad', c_uint32),
        ('segment_offset_OnExit', c_uint32),
        ('segment_offset_OnUnresolved', c_uint32),
        ('code_offset', c_uint32),
        ('code_size', c_uint32),
        ('data_offset', c_uint32),
        ('data_size', c_uint32),
        ('module_name_offset', c_uint32),
        ('module_name_size', c_uint32),
        ('segment_table_offset', c_uint32),
        ('segment_table_count', c_uint32),
        ('named_export_table_offset', c_uint32),
        ('named_export_table_count', c_uint32),
        ('indexed_export_table_offset', c_uint32),
        ('indexed_export_table_count', c_uint32),
        ('export_strings_offset', c_uint32),
        ('export_strings_size', c_uint32),
        ('export_tree_offset', c_uint32),
        ('export_tree_count', c_uint32),
        ('import_module_table_offset', c_uint32),
        ('import_module_table_count', c_uint32),
        ('import_patches_offset', c_uint32),
        ('import_patches_count', c_uint32),
        ('named_import_table_offset', c_uint32),
        ('named_import_table_count', c_uint32),
        ('indexed_import_table_offset', c_uint32),
        ('indexed_import_table_count', c_uint32),
        ('anonymous_import_table_offset', c_uint32),
        ('anonymous_import_table_count', c_uint32),
        ('import_strings_offset', c_uint32),
        ('import_strings_size', c_uint32),
        ('unk3_offset', c_uint32),
        ('unk3_count', c_uint32),
        ('relocation_patches_offset', c_uint32),
        ('relocation_patches_count', c_uint32),
        ('unk4_offset', c_uint32),
        ('unk4_count', c_uint32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class croReader:
    def __init__(self, file):
        self.file = file

        with open(file, 'rb') as f:
            self.hdr = croHdr(f.read(0x138))

    def verify(self):
        f = open(self.file, 'rb')

        hash_check = []
        hash_check_info = [ # (name, offset to read from, size, expected hash)
            ('Header', 0x80, 0x100, bytes(self.hdr.hdr_hash)),
            ('Section 0', self.hdr.code_offset, self.hdr.code_size, bytes(self.hdr.sect0_hash)),
            ('Section 1', self.hdr.module_name_offset, self.hdr.data_offset - self.hdr.module_name_offset, bytes(self.hdr.sect1_hash)),
            ('Section 2', self.hdr.data_offset, self.hdr.data_size, bytes(self.hdr.sect2_hash)),
        ]
        for name, off, size, hash_expected in hash_check_info:
            f.seek(off)
            h = hashlib.sha256()
            h.update(f.read(size))
            hash_check.append((name, h.digest() == hash_expected))

        f.close()
        print("Hashes:")
        for i in hash_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

    def regen_hash(self): # Overwrites existing file
        f = open(self.file, 'r+b')

        hash_info = [ # (name, offset to read from, size, offset to put hash)
            ('Header', 0x80, 0x100, 0),
            ('Section 0', self.hdr.code_offset, self.hdr.code_size, 0x20),
            ('Section 1', self.hdr.module_name_offset, self.hdr.data_offset - self.hdr.module_name_offset, 0x40),
            ('Section 2', self.hdr.data_offset, self.hdr.data_size, 0x60),
        ]
        for _, off, size, hash_off in hash_info:
            f.seek(off)
            h = hashlib.sha256()
            h.update(f.read(size))
            f.seek(hash_off)
            f.write(h.digest())

        f.close()
        print(f'{self.file} rehashed')
