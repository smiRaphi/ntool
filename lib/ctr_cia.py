from .common import *
from .keys import *
from .ctr_tik import signature_types, tikReader
from .ctr_tmd import TMDReader, TMDBuilder
from .ctr_ncch import NCCHReader

class CIAHdr(Structure):
    _fields_ = [
        ('hdr_size', c_uint32), # 0x2020 bytes
        ('type', c_uint16),
        ('format_ver', c_uint16),
        ('cert_chain_size', c_uint32),
        ('tik_size', c_uint32),
        ('tmd_size', c_uint32),
        ('meta_size', c_uint32),
        ('content_size', c_uint64),
        ('content_index', c_uint8 * 0x2000),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class CertificateInfo(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('issuer', c_char * 0x40),
        ('key_type', c_uint32),
        ('name', c_char * 0x40),
        ('expiration_time', c_int32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class RSA4096PubKey(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('mod', c_uint8 * 0x200),
        ('pub_exp', c_uint32),
        ('reserved', c_uint8 * 0x34),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class RSA2048PubKey(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('mod', c_uint8 * 0x100),
        ('pub_exp', c_uint32),
        ('reserved', c_uint8 * 0x34),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class CIAReader:
    def __init__(self, file, dev=0):
        self.file = file
        self.dev = dev

        with open(file, 'rb') as f:
            self.hdr = CIAHdr(f.read(0x2020))

        # Get offsets for CIA components
        curr = 0x2020
        files = {}
        files['cia_header.bin'] = {
            'size': 0x2020,
            'offset': 0,
            'crypt': 'none',
        }

        curr += align(curr, 64)
        files['cert.bin'] = {
            'size': self.hdr.cert_chain_size,
            'offset': curr,
            'crypt': 'none',
        }
        curr += self.hdr.cert_chain_size

        curr += align(curr, 64)
        files['tik'] = {
            'size': self.hdr.tik_size,
            'offset': curr,
            'crypt': 'none',
        }
        curr += self.hdr.tik_size

        curr += align(curr, 64)
        files['tmd'] = {
            'size': self.hdr.tmd_size,
            'offset': curr,
            'crypt': 'none',
        }
        curr += self.hdr.tmd_size

        curr += align(curr, 64)
        # Parse ticket to get titlekey (the AES-CBC key)
        with open(file, 'rb') as f:
            f.seek(files['tik']['offset'])
            with open('tik', 'wb') as g:
                g.write(f.read(files['tik']['size']))
            self.tik = tikReader('tik', dev)
            os.remove('tik')

        # Parse TMD to get content files offset, size, AES-CBC IV (if encrypted), hash
        with open(file, 'rb') as f:
            f.seek(files['tmd']['offset'])
            with open('tmd', 'wb') as g:
                g.write(f.read(files['tmd']['size']))
            self.tmd = TMDReader('tmd', dev)
            os.remove('tmd')

        for i in self.tmd.files.keys():
            content_index = int(i.split('.')[0], 16)
            if self.hdr.content_index[content_index // 8] & (0b10000000 >> (content_index % 8)): # Check if content file listed in TMD actually exists in CIA (e.g. in the case of incomplete DLC CIA)
                files[i] = self.tmd.files[i]
                curr += align(curr, 64)
                files[i]['offset'] = curr
                if 'key' in files[i].keys():
                    files[i]['key'] = self.tik.titlekey
                curr += files[i]['size']

        if self.hdr.meta_size:
            curr += align(curr, 64)
            files['meta.bin'] = {
                'size': self.hdr.meta_size,
                'offset': curr,
                'crypt': 'none',
            }
            curr += self.hdr.meta_size

        self.files = files

    def extract(self):
        f = open(self.file, 'rb')
        for name, info in self.files.items():
            f.seek(info['offset'])
            g = open(name, 'wb')

            if info['crypt'] == 'none':
                for data in read_chunks(f, info['size']):
                    g.write(data)
            elif info['crypt'] == 'normal':
                cipher = AES.new(info['key'], AES.MODE_CBC, iv=info['iv'])
                for data in read_chunks(f, info['size']):
                    g.write(cipher.decrypt(data))

            print(f'Extracted {name}')
            g.close()
        f.close()

    def decrypt(self):
        f = open(self.file, 'rb')
        g = open('decrypted.cia', 'wb')
        cur = 0
        for name, info in self.files.items():
            if cur < info['offset']: # Padding between CIA components
                pad_size = info['offset'] - cur
                g.write(b'\x00' * pad_size)
                cur += pad_size
            f.seek(info['offset'])

            if name == 'tmd': # Modify TMD to remove crypt flags
                with open('tmd', 'wb') as h:
                    h.write(f.read(info['size']))
                if self.dev == 0:
                    TMDBuilder('tmd', crypt=0)
                else:
                    TMDBuilder('tmd', crypt=0, regen_sig='dev')
                with open('tmd_new', 'rb') as h:
                    g.write(h.read())
                os.remove('tmd')
                os.remove('tmd_new')
            elif info['crypt'] == 'none':
                for data in read_chunks(f, info['size']):
                    g.write(data)
            elif info['crypt'] == 'normal':
                cipher = AES.new(info['key'], AES.MODE_CBC, iv=info['iv'])
                for data in read_chunks(f, info['size']):
                    g.write(cipher.decrypt(data))
            cur += info['size']

        f.close()
        g.close()
        print(f'Decrypted to decrypted.cia')

    def verify(self):
        f = open(self.file, 'rb')
        tmd = self.tmd.verify(no_print=1)
        hash_check = tmd[0]
        for name, info in self.files.items(): # Content files
            if name.endswith('nds') or name.endswith('ncch'):
                f.seek(info['offset'])
                name2 = '.'.join(name.split('.')[:-1]) # Remove extension so printout is short enough to be aligned
                if info['crypt'] == 'none':
                    hash_check.append((name2, Crypto.sha256(f, info['size']) == info['hash']))
                elif info['crypt'] == 'normal':
                    h = hashlib.sha256()
                    cipher = AES.new(info['key'], AES.MODE_CBC, iv=info['iv'])
                    for data in read_chunks(f, info['size']):
                        h.update(cipher.decrypt(data))
                    hash_check.append((name2, h.digest() == info['hash']))

        sig_check = []
        f.seek(self.files['cert.bin']['offset']) # CIA cert chain
        ca_mod = b''
        for i in range(3):
            sig_type = readbe(f.read(4))
            sig = f.read(signature_types[sig_type][0])
            f.read(signature_types[sig_type][1]) # advance pointer
            cert_info = CertificateInfo(f.read(0x88))
            if cert_info.key_type == 0:
                pubkey = RSA4096PubKey(f.read(0x238))
            elif cert_info.key_type == 1:
                pubkey = RSA2048PubKey(f.read(0x138))

            if i == 0:
                ca_mod = bytes(pubkey.mod) # store CA modulus to verify Ticket cert and TMD cert
                sig_check.append(('CIA Cert (CA)', Crypto.verify_rsa_sha256(CTR.root_mod[self.dev], bytes(cert_info) + bytes(pubkey), sig)))
            elif i == 1:
                sig_check.append(('CIA Cert (XS)', Crypto.verify_rsa_sha256(ca_mod, bytes(cert_info) + bytes(pubkey), sig)))
            elif i == 2:
                sig_check.append(('CIA Cert (CP)', Crypto.verify_rsa_sha256(ca_mod, bytes(cert_info) + bytes(pubkey), sig)))
        sig_check += self.tik.verify(no_print=1) + tmd[1]

        f.close()
        print('Hashes:')
        for i in hash_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
        print('Signatures:')
        for i in sig_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

    def __str__(self):
        enabled_content_idxs = []
        for i in range(0, 0x2000 * 8):
            if self.hdr.content_index[i // 8] & (0b10000000 >> (i % 8)):
                enabled_content_idxs.append(hex(i)[2:].zfill(4))

        contents = ''
        for i in enabled_content_idxs:
            contents += f'   > {i}\n'

        tik = ''.join(['  ' + i + '\n' for i in self.tik.__str__().split('\n')])
        tmd = ''.join(['  ' + i + '\n' for i in self.tmd.__str__().split('\n')])
        return (
            f'CIA:\n'
            f'  Enabled contents:\n'
            f'{contents}'
            f'Ticket:\n'
            f'{tik}'
            f'TMD:\n'
            f'{tmd[:-1]}' # Remove last '\n'
        )

class CIABuilder:
    def __init__(self, certs='', content_files=[], tik='', tmd='', meta=1, dev=0, out='new.cia'):
        '''
        certs: path to certs (if not provided, use existing ones (dev=1 will use dev certs))
        content_files: list containing filenames of content files, which must each be named '[content index in hex, 4 chars].[contentID in hex, 8 chars].[ncch/nds]'
        tik: path to ticket
        tmd: path to tmd
        meta: 0 or 1 (whether to generate meta section)
        dev: 0 or 1 (if 1, content files and ticket titlekey are dev-crypted)
        out: path to output file
        '''

        # Checks
        if content_files[0].endswith('nds') and meta:
            raise Exception('Cannot generate meta section for TWL CIA')

        # Create CIA header
        hdr = CIAHdr(b'\x00' * 0x2020)
        hdr.hdr_size = 0x2020
        hdr.cert_chain_size = 0xA00
        hdr.tik_size = os.path.getsize(tik)
        hdr.tmd_size = os.path.getsize(tmd)
        if meta:
            hdr.meta_size = 0x3AC0
        hdr.content_size = sum([os.path.getsize(i) for i in content_files])

        content_files.sort(key=lambda h: int(h.split('.')[0], 16)) # Sort list of content files by content index
        for i in content_files: # Enable content files present in content index
            content_index = int(i.split('.')[0], 16)
            hdr.content_index[content_index // 8] |= (0b10000000 >> (content_index % 8))

        tik_read = tikReader(tik, dev)
        tmd_read = TMDReader(tmd, dev)

        # Write CIA
        f = open(f'{out}', 'wb')
        f.write(bytes(hdr))

        curr = 0x2020
        alignment = align(curr, 64)
        if alignment:
            f.write(b'\x00' * alignment)
        curr += alignment
        if certs != '':
            with open(certs, 'rb') as g:
                f.write(g.read())
        elif dev == 0:
            with open(os.path.join(resources_dir, 'CA00000003.cert'), 'rb') as g:
                f.write(g.read())
            with open(os.path.join(resources_dir, 'XS0000000c.cert'), 'rb') as g:
                f.write(g.read())
            with open(os.path.join(resources_dir, 'CP0000000b.cert'), 'rb') as g:
                f.write(g.read())
        elif dev == 1:
            with open(os.path.join(resources_dir, 'CA00000004.cert'), 'rb') as g:
                f.write(g.read())
            with open(os.path.join(resources_dir, 'XS00000009.cert'), 'rb') as g:
                f.write(g.read())
            with open(os.path.join(resources_dir, 'CP0000000a.cert'), 'rb') as g:
                f.write(g.read())
        curr += hdr.cert_chain_size

        alignment = align(curr, 64)
        if alignment:
            f.write(b'\x00' * alignment)
        curr += alignment
        with open(tik, 'rb') as g:
            f.write(g.read())
        curr += hdr.tik_size

        alignment = align(curr, 64)
        if alignment:
            f.write(b'\x00' * alignment)
        curr += alignment
        with open(tmd, 'rb') as g:
            f.write(g.read())
        curr += hdr.tmd_size

        alignment = align(curr, 64)
        if alignment:
            f.write(b'\x00' * alignment)
        curr += alignment
        for i in content_files:
            tmd_info = tmd_read.files[i]
            g = open(i, 'rb')
            if 'key' in tmd_info.keys():
                cipher = AES.new(tik_read.titlekey, AES.MODE_CBC, iv=tmd_info['iv'])
                for data in read_chunks(g, tmd_info['size']):
                    f.write(cipher.encrypt(data))
            else:
                for data in read_chunks(g, tmd_info['size']):
                    f.write(data)
            g.close()
        curr += hdr.content_size

        if meta:
            ncch = NCCHReader(content_files[0], dev=dev)
            if 'exheader.bin' in ncch.files.keys():
                info = ncch.files['exheader.bin']
                g = open(content_files[0], 'rb')
                g.seek(info['offset'])
                if ncch.is_decrypted:
                    exheader = g.read(info['size'])
                else:
                    counter = Counter.new(128, initial_value=readbe(info['counter']))
                    cipher = AES.new(info['key'], AES.MODE_CTR, counter=counter)
                    exheader = cipher.decrypt(g.read(info['size']))

                info = ncch.files['exefs.bin']
                icon = b''
                for off, size, key, name in info['files']:
                    if name == 'icon':
                        g.seek(info['offset'] + off)
                        if ncch.is_decrypted:
                            icon = g.read(size)
                        else:
                            counter = Counter.new(128, initial_value=readbe(info['counter']) + (off // 16))
                            cipher = AES.new(info['key'][key], AES.MODE_CTR, counter=counter)
                            cipher.decrypt(b'\0' * (off % 16))
                            icon = cipher.decrypt(g.read(size))
                        break

                if icon == b'':
                    warnings.warn('Not generating meta section as could not find icon in ExeFS')
                    f.seek(0x14)
                    f.write(b'\x00' * 4) # Set meta size in header back to 0
                else:
                    alignment = align(curr, 64)
                    if alignment:
                        f.write(b'\x00' * alignment)
                    curr += alignment

                    f.write(exheader[0x40:0x40 + 0x180]) # TitleID dependency list
                    f.write(b'\x00' * 0x180)
                    f.write(exheader[0x208:0x208 + 0x4]) # Core version
                    f.write(b'\x00' * 0xFC)
                    f.write(icon)
                    curr += hdr.meta_size
                g.close()
            else:
                warnings.warn('Not generating meta section as NCCH does not have exheader')
                f.seek(0x14)
                f.write(b'\x00' * 4) # Set meta size in header back to 0

        f.close()
        print(f'Wrote to {out}')
