from .common import *
from .keys import *

if platform.system() == 'Windows':
    tool = os.path.join(resources_dir, '3dstool.exe')
elif platform.system() == 'Linux':
    tool = os.path.join(resources_dir, '3dstool_linux')
elif platform.system() == 'Darwin':
    tool = os.path.join(resources_dir, '3dstool_macos')
else:
    raise Exception('Could not identify OS')

block_size = 0x200

class ExeFSFileHdr(Structure):
    _fields_ = [
        ('name', c_char * 8),
        ('offset', c_uint32),
        ('size', c_uint32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class ExeFSHdr(Structure):
    _pack_ = 1

    _fields_ = [
        ('file_headers', ExeFSFileHdr * 10),
        ('reserved', c_uint8 * 0x20),
        ('file_hashes', c_uint8 * 0x140),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class ExeFSReader:
    def __init__(self, file):
        self.file = file

        with open(file, 'rb') as f:
            self.hdr = ExeFSHdr(f.read(0x200))

        files = {}
        for i in range(10):
            file_hdr = self.hdr.file_headers[i]
            if file_hdr.size:
                files[f'{file_hdr.name.decode("utf-8")}.bin'] =  {
                    'size': file_hdr.size,
                    'offset': 0x200 + file_hdr.offset
                }
        self.files = files

    def extract(self, code_compressed=0):
        f = open(self.file, 'rb')
        for name, info in self.files.items():
            f.seek(info['offset'])
            g = open(name, 'wb')

            for data in read_chunks(f, info['size']):
                g.write(data)

            print(f'Extracted {name}')
            g.close()

            if name == '.code.bin' and code_compressed:
                proc = subprocess.Popen([tool, '-uvf', '.code.bin', '--compress-type', 'blz', '--compress-out', 'code-decompressed.bin'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result = proc.communicate()
                if result[0] == b'':
                    print('Decompressed to code-decompressed.bin')
                else:
                    print(result[0].decode('utf-8'))
        f.close()

    def verify(self):
        f = open(self.file, 'rb')

        hash_check = []
        hashes = [bytes(self.hdr.file_hashes[i * 0x20:(i + 1) * 0x20]) for i in range(10)]
        hashes.reverse()

        for i, (name, info) in enumerate(self.files.items()):
            f.seek(info['offset'])
            hash_check.append((name.replace('.bin', ''), Crypto.sha256(f, info['size']) == hashes[i]))

        f.close()
        print("Hashes:")
        for i in hash_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

class ExeFSBuilder:
    def __init__(self, exefs_dir='', code_compress=0, out='exefs.bin'):
        '''
        exefs_dir: path to directory containing files to be added to exefs (files must be named '.code.bin', 'banner.bin', 'icon.bin', 'logo.bin')
        code_compress: 0 or 1
        out: path to output file
        '''

        files = os.listdir(exefs_dir) # Contains filenames, not paths
        files.sort()
        hdr = ExeFSHdr(b'\x00' * 0x200)

        if files[0] == '.code.bin' and code_compress == 1:
            proc = subprocess.Popen([tool, '-zvf', os.path.join(exefs_dir, '.code.bin'), '--compress-type', 'blz', '--compress-out', os.path.join(exefs_dir, 'code-compressed.bin')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = proc.communicate()
            if result[0] == b'':
                files[0] = 'code-compressed.bin'
            else:
                print(result[0].decode('utf-8'))

        # Create ExeFS header
        hashes = []
        for i in range(len(files)):
            if files[i] == 'code-compressed.bin':
                hdr.file_headers[i].name = '.code'.encode('utf-8')
            else:
                hdr.file_headers[i].name = files[i].replace('.bin', '').encode('utf-8')
            hdr.file_headers[i].size = os.path.getsize(os.path.join(exefs_dir, files[i]))
            if i == 0:
                hdr.file_headers[i].offset = 0
            else:
                hdr.file_headers[i].offset = roundup(hdr.file_headers[i - 1].offset + hdr.file_headers[i - 1].size, block_size)

            f = open(os.path.join(exefs_dir, files[i]), 'rb')
            hashes.append(Crypto.sha256(f, hdr.file_headers[i].size))
            f.close()

        for _ in range(len(files), 10):
            hashes.append(b'\x00' * 0x20)
        hashes.reverse()
        hashes_all = b''.join(hashes)
        hdr.file_hashes = (c_uint8 * sizeof(hdr.file_hashes))(*hashes_all)

        # Write ExeFS
        f = open(out, 'wb')
        f.write(bytes(hdr))
        curr = 0x200
        for i in range(len(files)):
            g = open(os.path.join(exefs_dir, files[i]), 'rb')
            if curr < (hdr.file_headers[i].offset + 0x200):
                pad_size = hdr.file_headers[i].offset + 0x200 - curr
                f.write(b'\x00' * pad_size)
                curr += pad_size

            for data in read_chunks(g, hdr.file_headers[i].size):
                f.write(data)

            curr += hdr.file_headers[i].size
            g.close()

        f.write(b'\x00' * align(curr, block_size))
        f.close()
        if os.path.isfile(os.path.join(exefs_dir, 'code-compressed.bin')):
            os.remove(os.path.join(exefs_dir, 'code-compressed.bin'))
        print(f'Wrote to {out}')
