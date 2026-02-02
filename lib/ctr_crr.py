from .common import *
from .keys import *

class crrHdr(Structure):
    _pack_ = 1

    _fields_ = [
        ('magic', c_char * 4),
        ('reserved1', c_uint32),
        ('next_crr', c_uint32),
        ('prev_crr', c_uint32),
        ('debug_info_offset', c_uint32),
        ('debug_info_size', c_uint32),
        ('reserved2', c_uint64),
        ('unique_id_mask', c_uint32),
        ('unique_id_pattern', c_uint32),
        ('reserved3', c_uint8 * 0x18),
        ('crr_body_mod', c_uint8 * 0x100),
        ('sig', c_uint8 * 0x100),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class crrBodyHdr(Structure):
    _pack_ = 1

    _fields_ = [
        ('sig', c_uint8 * 0x100),
        ('unique_id', c_uint32),
        ('size', c_uint32),
        ('reserved1', c_uint64),
        ('hash_offset', c_uint32),
        ('hash_count', c_uint32),
        ('plain_offset', c_uint32),
        ('plain_size', c_uint32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class crrReader:
    def __init__(self, file, dev=0):
        self.file = file
        self.dev = dev

        with open(file, 'rb') as f:
            self.hdr = crrHdr(f.read(0x240))
            self.body_hdr = crrBodyHdr(f.read(0x120))

            f.seek(self.body_hdr.hash_offset)
            cro_hash_list = []
            for i in range(self.body_hdr.hash_count):
                cro_hash_list.append(f.read(0x20))
            self.cro_hash_list = cro_hash_list

        # If re-generating hash / want to verify CRO hashlist, place all CROs in the same directory as static.crr
        self.current_dir = os.path.dirname(os.path.abspath(self.file))
        self.cros = [i for i in os.listdir(self.current_dir) if i.endswith('.cro')]

        if len(self.cros) != 0 and len(self.cros) != self.body_hdr.hash_count:
            raise Exception(f'Expected {self.body_hdr.hash_count} CROs but found {len(self.cros)}')

    def regen_hash(self): # Overwrites existing file
        if len(self.cros) == 0:
            raise Exception('Please place all CROs in the same directory as static.crr')

        hashes = []
        for i in self.cros:
            with open(os.path.join(self.current_dir, i), 'rb') as g:
                h = hashlib.sha256()
                h.update(g.read(0x80))
                hashes.append(h.digest())
        hashes = [hex(readbe(i))[2:].zfill(64) for i in hashes]
        hashes.sort()
        hashes = [hextobytes(i) for i in hashes]

        with open(self.file, 'r+b') as f:
            f.seek(0x360)
            f.write(b''.join(hashes))
        print(f'{self.file} rehashed')

    def regen_sig(self, dev=0): # Overwrites existing file
        with open(self.file, 'r+b') as f:
            # Body sig
            f.seek(0x340)
            crr_body = f.read(self.body_hdr.plain_offset - 0x340)
            body_sig = Crypto.sign_rsa_sha256(CTR.crr_body_mod, CTR.crr_body_priv, crr_body)

            f.seek(0x40)
            f.write(CTR.crr_body_mod)
            f.seek(0x240)
            f.write(body_sig)

            if dev == 1: # Header sig
                f.seek(0x20)
                data = f.read(0x120)
                hdr_sig = Crypto.sign_rsa_sha256(CTR.crr_mod[1], CTR.crr_priv[1], data)
                f.seek(0x140)
                f.write(hdr_sig)

        print(f'{self.file} resigned')

    def verify(self):
        f = open(self.file, 'rb')

        hash_check = []
        if len(self.cros) != 0:
            hashes = []
            for i in self.cros: # Check if sha256 of first 0x80 bytes of cro exists in cro hashlist
                with open(os.path.join(self.current_dir, i), 'rb') as g:
                    h = hashlib.sha256()
                    h.update(g.read(0x80))
                    hashes.append(h.digest() in self.cro_hash_list)
            hash_check.append(('CRO Hashlist', all(hashes)))

        sig_check = []
        sig_check.append(('CRR Header', Crypto.verify_rsa_sha256(CTR.crr_mod[self.dev], bytes(self.hdr)[0x20:0x140], bytes(self.hdr.sig))))

        f.seek(0x340)
        crr_body = f.read(self.body_hdr.plain_offset - 0x340)
        sig_check.append(('CRR Body', Crypto.verify_rsa_sha256(bytes(self.hdr.crr_body_mod), crr_body, bytes(self.body_hdr.sig))))

        f.close()
        if hash_check != []:
            print("Hashes:")
            for i in hash_check:
                print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
        print("Signatures:")
        for i in sig_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
