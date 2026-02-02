from .common import *
from .keys import *
from .ctr_cia import CIAReader

class cntRecord(Structure):
    _pack_ = 1

    _fields_ = [
        ('offset', c_uint32),
        ('offset_end', c_uint32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class cntHdr(Structure):
    _pack_ = 1

    _fields_ = [
        ('magic', c_char * 4),
        ('unk', c_uint8 * 0xBFC),
        ('content_records', cntRecord * 0x100)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass

class cntReader:
    def __init__(self, cnt, cuplist=''): # files named 'Contents.cnt' and 'CupList' respectively
        self.cnt = cnt
        self.cuplist = cuplist
        files = {}

        if self.cuplist != '':
            with open(cuplist, 'rb') as f:
                cupdata = f.read()

            tidlist = []
            for i in range(0, 0x800, 8):
                if cupdata[i:i + 8] == b'\x00' * 8:
                    break
                tidlist.append(hex(readle(cupdata[i:i + 8]))[2:].zfill(16))
            self.tidlist = tidlist

            with open(cnt, 'rb') as f:
                self.cnt_hdr = cntHdr(f.read(0x1400))

            for i in range(len(tidlist)):
                files[f'{tidlist[i]}.cia'] = {
                    'size': self.cnt_hdr.content_records[i].offset_end - self.cnt_hdr.content_records[i].offset,
                    'offset': self.cnt_hdr.content_records[i].offset + 0xC00 # Offsets are relative from the start of the content records
                }
        else:
            with open(cnt, 'rb') as f:
                f.seek(0xC00)
                content_records = f.read(0x800)
                for i in range(0, 0x800, 8):
                    offset = readle(content_records[i:i + 4])
                    offset_end = readle(content_records[i + 4:i + 8])
                    if offset == 0:
                        break
                    files[f'{(i // 8) + 1}.cia'] = {
                        'size': offset_end - offset,
                        'offset': offset + 0xC00
                    }
        self.files = files

    def extract(self):
        output_dir = 'updates/'
        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)

        f = open(self.cnt, 'rb')
        for name, info in self.files.items():
            f.seek(info['offset'])
            g = open(os.path.join(output_dir, name), 'wb')
            for data in read_chunks(f, info['size']):
                g.write(data)
            g.close()

            # Rename CIAs if no cuplist
            if self.cuplist == '':
                cia = CIAReader(os.path.join(output_dir, name))
                titleID = cia.tmd.titleID
                os.rename(os.path.join(output_dir, name), f"{os.path.join(output_dir, titleID)}.cia")

        f.close()
        print(f'Extracted to {output_dir}')