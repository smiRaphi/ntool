from .common import *
from .keys import *

class tikData(BigEndianStructure):
    _pack_ = 1

    _fields_ = [
        ('issuer', c_char * 0x40),
        ('ecc_pubkey', c_uint8 * 0x3C),
        ('format_ver', c_uint8),
        ('ca_crl_ver', c_uint8),
        ('signer_crl_ver', c_uint8),
        ('enc_titlekey', c_uint8 * 16),
        ('reserved1', c_uint8),
        ('ticketID', c_uint64),
        ('consoleID', c_uint32),
        ('titleID', c_uint8 * 8),
        ('reserved2', c_uint16),
        ('title_ver', c_uint16),
        ('reserved3', c_uint64),
        ('license_type', c_uint8),
        ('common_key_index', c_uint8),
        ('reserved4', c_uint8 * 0x2A),
        ('eshop_acc_id', c_uint8 * 4),
        ('reserved5', c_uint8),
        ('audit', c_uint8),
        ('reserved6', c_uint8 * 0x42),
        ('limits', c_uint8 * 0x40),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

signature_types = { # Each tuple is (signature size, size of padding after signature)
    # RSA_4096 SHA1 (unused on 3DS)
    0x00010000: (0x200, 0x3C),
    # RSA_2048 SHA1 (unused on 3DS)
    0x00010001: (0x100, 0x3C),
    # Elliptic Curve with SHA1 (unused on 3DS)
    0x00010002: (0x3C, 0x40),
    # RSA_4096 SHA256
    0x00010003: (0x200, 0x3C),
    # RSA_2048 SHA256
    0x00010004: (0x100, 0x3C),
    # ECDSA with SHA256
    0x00010005: (0x3C, 0x40),
}

class tikReader:
    def __init__(self, file, dev=0):
        self.file = file
        self.dev = dev

        with open(file, 'rb') as f:
            sig_type = readbe(f.read(4))
            self.sig = f.read(signature_types[sig_type][0])
            padding = f.read(signature_types[sig_type][1])
            self.data = tikData(f.read(0x164))
            self.content_index_hdr = f.read(0x28)
            self.content_index_offset = f.read(4)
            self.content_index = f.read(0x80)

        # Decrypt TitleKey
        normal_key = CTR.key_scrambler(CTR.KeyX0x3D[dev], CTR.KeyY0x3D[self.data.common_key_index][dev])
        cipher = AES.new(normal_key, AES.MODE_CBC, iv=bytes(self.data.titleID)+(b'\0'*8))
        self.titlekey = cipher.decrypt(bytes(self.data.enc_titlekey))

    def verify(self, no_print=0): # 'no_print' parameter to facilitate CIAReader.verify()
        sig_check = []
        sig_check.append(('Ticket', Crypto.verify_rsa_sha256(CTR.tik_mod[self.dev], bytes(self.data) + self.content_index_hdr + self.content_index_offset + self.content_index, self.sig)))

        if no_print == 0:
            print('Signatures:')
            for i in sig_check:
                print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

        return sig_check

    def __str__(self):
        enabled_content_idxs = []
        for i in range(0, 0x80 * 8):
            if self.content_index[i // 8] & (1 << (i % 8)):
                enabled_content_idxs.append(hex(i)[2:].zfill(4))

        contents = ''
        for i in enabled_content_idxs:
            contents += f' > {i}\n'
        contents = contents[:-1] # Remove last '\n'

        if self.content_index == b'\xff' * 0x80: # If all content indexes are enabled, make printout shorter
            contents = f' > 0000 \n   ...\n > 03ff'

        return (
            f'TitleKey:          {hex(readbe(self.data.enc_titlekey))[2:].zfill(32)} (decrypted: {hex(readbe(self.titlekey))[2:].zfill(32)})\n'
            f'TicketID:          {hex(self.data.ticketID)[2:].zfill(16)}\n'
            f'ConsoleID:         {hex(self.data.consoleID)[2:].zfill(8)}\n'
            f'TitleID:           {hex(readbe(bytes(self.data.titleID)))[2:].zfill(16)}\n'
            f'Title version:     {self.data.title_ver}\n'
            f'Common KeyY index: {self.data.common_key_index}\n'
            f'eShop account ID:  {hex(readle(bytes(self.data.eshop_acc_id)))[2:].zfill(8)}\n' # ctrtool shows this as LE
            f'Enabled contents:\n'
            f'{contents}'
        )

class tikBuilder:
    def __init__(self, tik='', titleID='', title_ver=-1, ticketID='', consoleID='', eshop_acc_id='', titlekey='', common_key_index=-1, regen_sig='', out='tik_new'):
        '''
        tik: path to ticket (if available)
        Following parameters are required if no ticket is provided; if both ticket and parameter is supplied, the parameter overrides the ticket
            - titleID: titleID in hex, e.g. '000400000FF3FF00'
            - title_ver: title version in decimal
            - ticketID, consoleID, eshop_acc_id: in hex
            - titlekey: decrypted title key in hex (if not provided, use titlekey generation algorithm)
            - common_key_index: 0 or 1 or 2 or 3 or 4 or 5
        regen_sig: '' or 'retail' (test keys) or 'dev'
        out: path to output file
        '''

        # Checks
        if titleID != '':
           if not all([i in string.hexdigits for i in titleID]) or len(titleID) != 16:
                raise Exception('Invalid TitleID')

        if titlekey != '':
           if not all([i in string.hexdigits for i in titlekey]) or len(titlekey) != 32:
                raise Exception('Invalid TitleKey')

        # Defaults
        if tik == '':
            if regen_sig == '':
                regen_sig = 'retail'
            if ticketID == '':
                ticketID = '0'
            if consoleID == '':
                consoleID = '0'
            if eshop_acc_id == '':
                eshop_acc_id = '0'
            if common_key_index == -1:
                common_key_index = 0

        # Create (or modify) ticket data
        if tik == '':
            data = tikData(b'\x00' * 0x164)
            data.format_ver = 1
            data.audit = 1

            if titlekey == '':
                titlekey = CTR.titlekey_gen(titleID, 'mypass')
        else:
            with open(tik, 'rb') as f:
                sig_type = readbe(f.read(4))
                sig = f.read(signature_types[sig_type][0])
                padding = f.read(signature_types[sig_type][1])
                data = tikData(f.read(0x164))
                content_index_hdr = f.read(0x28)
                content_index_offset = f.read(4)
                content_index = f.read(0x80)

        if tik == '' or regen_sig != '':
            data.issuer = b'Root-CA00000003-XS0000000c'
            if regen_sig == 'dev':
                data.issuer = b'Root-CA00000004-XS00000009'

        if ticketID != '':
            data.ticketID = int(ticketID, 16)

        if consoleID != '':
            data.consoleID = int(consoleID, 16)

        if titleID != '':
            titleID_bytes = int.to_bytes((int(titleID, 16)), 8, 'big')
            data.titleID = (c_uint8 * sizeof(data.titleID))(*titleID_bytes)

        if title_ver != -1:
            data.title_ver = title_ver

        if common_key_index != -1:
            data.common_key_index = common_key_index

        if eshop_acc_id != '':
            eshop_acc_id_bytes = int32tobytes(int(eshop_acc_id, 16))
            data.eshop_acc_id = (c_uint8 * sizeof(data.eshop_acc_id))(*eshop_acc_id_bytes)

        if titlekey != '': # Encrypt TitleKey
            if regen_sig == 'dev':
                dev = 1
            else:
                dev = 0
            normal_key = CTR.key_scrambler(CTR.KeyX0x3D[dev], CTR.KeyY0x3D[data.common_key_index][dev])
            cipher = AES.new(normal_key, AES.MODE_CBC, iv=bytes(data.titleID)+(b'\0'*8))
            enc_titlekey = cipher.encrypt(hextobytes(titlekey))
            data.enc_titlekey = (c_uint8 * sizeof(data.enc_titlekey))(*enc_titlekey)

        # Create content index
        if tik == '':
            content_index_hdr = hextobytes('00010014 000000AC 00000014 00010014 00000000 00000028 00000001 00000084 00000084 00030000'.strip())
            content_index_offset = b'\x00' * 4
            content_index = b'\xff' * 0x80 # Enable all content indexes

        # Write ticket
        if regen_sig == 'retail':
            sig = Crypto.sign_rsa_sha256(CTR.test_mod, CTR.test_priv, bytes(data) + content_index_hdr + content_index_offset + content_index)
        elif regen_sig == 'dev':
            sig = Crypto.sign_rsa_sha256(CTR.tik_mod[1], CTR.tik_priv[1], bytes(data) + content_index_hdr + content_index_offset + content_index)

        with open(f'{out}', 'wb') as f:
            f.write(int.to_bytes(0x00010004, 4, 'big'))
            f.write(sig)
            f.write(b'\x00' * 0x3C)
            f.write(bytes(data))
            f.write(content_index_hdr)
            f.write(content_index_offset)
            f.write(content_index)

        print(f'Wrote to {out}')
