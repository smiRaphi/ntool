from lib.common import *
from lib.keys import NTR, TWL
from lib.ctr_cia import CIAReader, CIABuilder
from lib.ctr_cci import CCIReader, CCIBuilder
from lib.ctr_ncch import NCCHReader, NCCHBuilder
from lib.ctr_exefs import ExeFSReader, ExeFSBuilder
from lib.ctr_romfs import RomFSReader, RomFSBuilder
from lib.ctr_crr import crrReader
from lib.ctr_tmd import TMDReader, TMDBuilder
from lib.ctr_tik import tikReader, tikBuilder
from lib.ctr_cdn import CDNReader, CDNBuilder
from lib.ctr_cnt import cntReader
from lib.ntr_twl_srl import SRLReader, get_rsa_key_idx

def srl_retail2dev(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_dev.srl'

    srl = SRLReader(path, dev=0)
    shutil.copyfile(path, 'tmp.nds')

    if srl.media == 'Game card' and srl.secure_area_status == 'decrypted': # Encrypt NTR secure area for decrypted game card SRLs
        with open(path, 'rb') as f:
            f.seek(0x4000)
            secure_area = f.read(2048)
            secure_area_enc = srl.encrypt_secure_area(secure_area, NTR.blowfish_key)
        with open('tmp.nds', 'r+b') as f:
            f.seek(0x4000)
            f.write(secure_area_enc)

    if srl.modcrypted: # Decrypt modcrypt regions and re-encrypt with dev key
        srl.decrypt_modcrypt()
        f = open('decrypted.nds', 'rb')
        key = bytes(srl.hdr)[:16][::-1]
        for i in srl.modcrypt:
            g = open('tmp.nds', 'r+b')
            f.seek(i['offset'])
            g.seek(i['offset'])

            counter = Counter.new(128, initial_value=readbe(i['counter']))
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            for data in read_chunks(f, i['size']):
                g.write(TWL.aes_ctr(cipher, data))
            g.close()
        f.close()
        os.remove('decrypted.nds')

    if srl.hdr.unit_code == 2 or srl.hdr.unit_code == 3 or (srl.hdr.unit_code == 0 and srl.hdr_ext.flags != 0): # Set DeveloperApp flag
        srl.hdr_ext.flags |= (1 << 7)
        with open('tmp.nds', 'r+b') as f:
            f.seek(0x1BF)
            f.write(int8tobytes(srl.hdr_ext.flags))

    if not (srl.hdr.unit_code == 0 and readbe(srl.hdr_ext.sig) == 0): # Re-generate header signature
        idx = get_rsa_key_idx(srl.hdr, srl.hdr_ext)
        n = TWL.rsa_key_mod[idx]
        d = TWL.rsa_key_priv[idx]

        f = open('tmp.nds', 'rb')
        sha1_calculated = Crypto.sha1(f, 0xE00)
        f.close()
        sha1_padded = b'\x00\x01' + b'\xff' * 105 + b'\x00' + sha1_calculated
        enc = pow(readbe(sha1_padded), readbe(d[1]), readbe(n[1])).to_bytes(0x80, 'big')
        with open('tmp.nds', 'r+b') as f:
            f.seek(0xF80)
            f.write(enc)

    if srl.media == 'Game card': # Re-generate undumpable area i.e. KeyTables for game card SRLs
        srl = SRLReader('tmp.nds', dev=1)
        srl.regen_undumpable()
        os.remove('tmp.nds')
        shutil.move('new.nds', out)
    else:
        shutil.move('tmp.nds', out)

def cia_dev2retail(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_retail.cia'

    cia = CIAReader(path, dev=1)
    cia.extract()

    cf = list(cia.files.keys())
    cf.remove('cia_header.bin')
    cf.remove('cert.bin')
    cf.remove('tik')
    cf.remove('tmd')
    if 'meta.bin' in cf:
        meta = 1
        cf.remove('meta.bin')
    else:
        meta = 0

    for i in cf:
        if i.endswith('.ncch'):
            ncch = NCCHReader(i, dev=1)
            ncch.extract() # NOTE: no need to resign CRR since CRR body sig will pass (all that matters)
            ncch_header = 'ncch_header.bin'
            if os.path.isfile('exheader.bin'):
                exheader = 'exheader.bin'
            else:
                exheader = ''
            if os.path.isfile('logo.bin'):
                logo = 'logo.bin'
            else:
                logo = ''
            if os.path.isfile('plain.bin'):
                plain = 'plain.bin'
            else:
                plain = ''
            if os.path.isfile('exefs.bin'):
                exefs = 'exefs.bin'
            else:
                exefs = ''
            if os.path.isfile('romfs.bin'):
                romfs = 'romfs.bin'
            else:
                romfs = ''
            os.remove(i)
            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='Secure1', regen_sig='retail', dev=0, out=i)
            for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
                if j != '':
                    os.remove(j)

    tmd = TMDReader('tmd', dev=1)
    TMDBuilder(content_files=cf, content_files_dev=0, titleID=tmd.titleID, title_ver=tmd.hdr.title_ver, save_data_size=tmd.hdr.save_data_size, priv_save_data_size=tmd.hdr.priv_save_data_size, twl_flag=tmd.hdr.twl_flag, crypt=0, regen_sig='retail')
    os.remove('tmd')

    tik = tikReader('tik', dev=1)
    tikBuilder(tik='tik', titlekey=hex(readbe(tik.titlekey))[2:].zfill(32), regen_sig='retail') # Use original (decrypted) titlekey
    os.remove('tik')

    CIABuilder(content_files=cf, tik='tik_new', tmd='tmd_new', meta=meta, dev=0, out=out)

    for i in cf + ['tmd_new', 'tik_new', 'cia_header.bin', 'cert.bin', 'meta.bin']:
        if os.path.isfile(i):
            os.remove(i)

def cia_retail2dev(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_dev.cia'

    cia = CIAReader(path, dev=0)
    cia.extract()

    cf = list(cia.files.keys())
    cf.remove('cia_header.bin')
    cf.remove('cert.bin')
    cf.remove('tik')
    cf.remove('tmd')
    if 'meta.bin' in cf:
        meta = 1
        cf.remove('meta.bin')
    else:
        meta = 0

    for i in cf:
        if i.endswith('.ncch'):
            ncch = NCCHReader(i, dev=0)
            ncch.extract()
            ncch_header = 'ncch_header.bin'
            if os.path.isfile('exheader.bin'):
                exheader = 'exheader.bin'
            else:
                exheader = ''
            if os.path.isfile('logo.bin'):
                logo = 'logo.bin'
            else:
                logo = ''
            if os.path.isfile('plain.bin'):
                plain = 'plain.bin'
            else:
                plain = ''
            if os.path.isfile('exefs.bin'):
                exefs = 'exefs.bin'
            else:
                exefs = ''
            if os.path.isfile('romfs.bin'):
                romfs = 'romfs.bin'
                romfs_rdr = RomFSReader('romfs.bin')
                if '.crr/static.crr' in romfs_rdr.files.keys() or '.crr\\static.crr' in romfs_rdr.files.keys():
                    romfs_rdr.extract()
                    crr = crrReader('romfs/.crr/static.crr')
                    crr.regen_sig(dev=1)
                    os.remove('romfs.bin')
                    RomFSBuilder(romfs_dir='romfs/', out='romfs.bin')
                    shutil.rmtree('romfs/')
            else:
                romfs = ''
            os.remove(i)
            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='Secure1', regen_sig='dev', dev=1, out=i)
            for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
                if j != '':
                    os.remove(j)

    tmd = TMDReader('tmd', dev=0)
    TMDBuilder(content_files=cf, content_files_dev=1, titleID=tmd.titleID, title_ver=tmd.hdr.title_ver, save_data_size=tmd.hdr.save_data_size, priv_save_data_size=tmd.hdr.priv_save_data_size, twl_flag=tmd.hdr.twl_flag, crypt=1, regen_sig='dev')
    os.remove('tmd')

    tik = tikReader('tik', dev=0)
    tikBuilder(tik='tik', titlekey=hex(readbe(tik.titlekey))[2:].zfill(32), regen_sig='dev') # Use original (decrypted) titlekey
    os.remove('tik')

    CIABuilder(content_files=cf, tik='tik_new', tmd='tmd_new', meta=meta, dev=1, out=out)

    for i in cf + ['tmd_new', 'tik_new', 'cia_header.bin', 'cert.bin', 'meta.bin']:
        if os.path.isfile(i):
            os.remove(i)

def cci_dev2retail(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_retail.3ds'

    cci = CCIReader(path, dev=1)
    cci.extract()

    parts = list(cci.files.keys())
    parts.remove('cci_header.bin')
    parts.remove('card_info.bin')
    parts.remove('mastering_info.bin')
    parts.remove('initialdata.bin')
    if 'card_device_info.bin' in parts:
        parts.remove('card_device_info.bin')

    for i in parts:
        if i.endswith('.ncch'):
            ncch = NCCHReader(i, dev=1)
            ncch.extract() # NOTE: no need to resign CRR since CRR body sig will pass (all that matters)
            ncch_header = 'ncch_header.bin'
            if os.path.isfile('exheader.bin'):
                exheader = 'exheader.bin'
            else:
                exheader = ''
            if os.path.isfile('logo.bin'):
                logo = 'logo.bin'
            else:
                logo = ''
            if os.path.isfile('plain.bin'):
                plain = 'plain.bin'
            else:
                plain = ''
            if os.path.isfile('exefs.bin'):
                exefs = 'exefs.bin'
            else:
                exefs = ''
            if os.path.isfile('romfs.bin'):
                romfs = 'romfs.bin'
            else:
                romfs = ''
            os.remove(i)
            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='Secure1', regen_sig='retail', dev=0, out=i)
            for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
                if j != '':
                    os.remove(j)

    CCIBuilder(cci_header='cci_header.bin', card_info='card_info.bin', mastering_info='mastering_info.bin', initialdata='', card_device_info='', ncchs=parts, cardbus_crypto='Secure0', regen_sig='retail', dev=0, gen_card_device_info=0, out=out)

    for i in parts + ['cci_header.bin', 'card_info.bin', 'mastering_info.bin', 'initialdata.bin', 'card_device_info.bin']:
        if os.path.isfile(i):
            os.remove(i)

def cci_retail2dev(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_dev.3ds'

    cci = CCIReader(path, dev=0)
    cci.extract()

    parts = list(cci.files.keys())
    parts.remove('cci_header.bin')
    parts.remove('card_info.bin')
    parts.remove('mastering_info.bin')
    parts.remove('initialdata.bin')
    if 'card_device_info.bin' in parts:
        parts.remove('card_device_info.bin')

    for i in parts:
        if i.endswith('.ncch'):
            ncch = NCCHReader(i, dev=0)
            ncch.extract()
            ncch_header = 'ncch_header.bin'
            if os.path.isfile('exheader.bin'):
                exheader = 'exheader.bin'
            else:
                exheader = ''
            if os.path.isfile('logo.bin'):
                logo = 'logo.bin'
            else:
                logo = ''
            if os.path.isfile('plain.bin'):
                plain = 'plain.bin'
            else:
                plain = ''
            if os.path.isfile('exefs.bin'):
                exefs = 'exefs.bin'
            else:
                exefs = ''
            if os.path.isfile('romfs.bin'):
                romfs = 'romfs.bin'
                romfs_rdr = RomFSReader('romfs.bin')
                if '.crr/static.crr' in romfs_rdr.files.keys() or '.crr\\static.crr' in romfs_rdr.files.keys():
                    romfs_rdr.extract()
                    crr = crrReader('romfs/.crr/static.crr')
                    crr.regen_sig(dev=1)
                    os.remove('romfs.bin')
                    RomFSBuilder(romfs_dir='romfs/', out='romfs.bin')
                    shutil.rmtree('romfs/')
            else:
                romfs = ''
            os.remove(i)
            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='Secure1', regen_sig='dev', dev=1, out=i)
            for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
                if j != '':
                    os.remove(j)

    CCIBuilder(cci_header='cci_header.bin', card_info='card_info.bin', mastering_info='mastering_info.bin', initialdata='', card_device_info='', ncchs=parts, cardbus_crypto='fixed', regen_sig='dev', dev=1, gen_card_device_info=1, out=out)

    for i in parts + ['cci_header.bin', 'card_info.bin', 'mastering_info.bin', 'initialdata.bin', 'card_device_info.bin']:
        if os.path.isfile(i):
            os.remove(i)

def ncch_extractall(path, dev=0):
    name = os.path.splitext(os.path.basename(path))[0]
    os.mkdir(name)

    ncch = NCCHReader(path, dev)
    ncch.extract()
    exefs_code_compress = 0
    for i in ['ncch_header.bin', 'exheader.bin', 'logo.bin', 'plain.bin', 'exefs.bin', 'romfs.bin']:
        if os.path.isfile(i):
            if i == 'exheader.bin':
                with open(i, 'rb') as f:
                    f.seek(0xD)
                    flag = readle(f.read(1))
                    if flag & 1:
                        exefs_code_compress = 1

            shutil.move(i, os.path.join(name, i))

    os.chdir(name)
    # Extract ExeFS
    if os.path.isfile('exefs.bin'):
        exefs = ExeFSReader('exefs.bin')
        exefs.extract(code_compressed=exefs_code_compress)
        os.mkdir('exefs')
        for i in exefs.files.keys():
            shutil.move(i, os.path.join('exefs', i))
        if exefs_code_compress:
            os.remove(os.path.join('exefs', '.code.bin'))
            shutil.move('code-decompressed.bin', os.path.join('exefs', '.code.bin'))

    # Extract RomFS
    if os.path.isfile('romfs.bin'):
        romfs = RomFSReader('romfs.bin')
        romfs.extract()

    os.chdir('..')

def macos_clean(path):
    proc = subprocess.call(['dot_clean', path], stdout=None, stderr=None)
    proc = subprocess.call(['find', path, '-type', 'f', '-name', '.DS_Store', '-exec', 'rm', '{}', ';'], stdout=None, stderr=None)

def ncch_rebuildall(path, dev=0):
    os.chdir(path)
    name = os.path.basename(os.getcwd())
    out = f'{name}.ncch'

    if os.path.isdir('exefs/'):
        if platform.system() == 'Darwin':
            macos_clean('exefs/')
        if os.path.isfile('exefs.bin'):
            os.remove('exefs.bin')

        exefs_code_compress = 0
        if os.path.isfile('exheader.bin'):
            with open('exheader.bin', 'rb') as f:
                f.seek(0xD)
                flag = readle(f.read(1))
                if flag & 1:
                    exefs_code_compress = 1

        ExeFSBuilder(exefs_dir='exefs/', code_compress=exefs_code_compress)

    if os.path.isdir('romfs/'):
        if platform.system() == 'Darwin':
            macos_clean('romfs/')
        if os.path.isfile('romfs.bin'):
            os.remove('romfs.bin')
        RomFSBuilder(romfs_dir='romfs/')

    ncch_header = 'ncch_header.bin'
    if os.path.isfile('exheader.bin'):
        exheader = 'exheader.bin'
    else:
        exheader = ''
    if os.path.isfile('logo.bin'):
        logo = 'logo.bin'
    else:
        logo = ''
    if os.path.isfile('plain.bin'):
        plain = 'plain.bin'
    else:
        plain = ''
    if os.path.isfile('exefs.bin'):
        exefs = 'exefs.bin'
    else:
        exefs = ''
    if os.path.isfile('romfs.bin'):
        romfs = 'romfs.bin'
    else:
        romfs = ''
    NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, dev=dev, out=out)
    if not os.path.isfile(f'../{out}'):
        shutil.move(out, f'../{out}')
    else:
        shutil.move(out, f'../{name} (new).ncch')
    os.chdir('..')

def cci_extractall(path, dev=0):
    name = os.path.splitext(os.path.basename(path))[0]
    os.mkdir(name)

    cci = CCIReader(path, dev)
    cci.extract()

    for i in cci.files.keys():
        shutil.move(i, os.path.join(name, i))

        if i.endswith('.ncch'):
            os.chdir(name)
            ncch_extractall(i)
            os.chdir('..')

def cci_rebuildall(path, dev=0):
    os.chdir(path)
    name = os.path.basename(os.getcwd())
    out = f'{name}.3ds'

    ncchs = []
    card_device_info = ''
    if os.path.isfile('card_device_info.bin'):
        card_device_info = 'card_device_info.bin'

    for i in os.listdir('.'):
        if os.path.isdir(i):
            ncchs.append(f'{i}.ncch')
            if os.path.isfile(f'{i}.ncch'):
                os.remove(f'{i}.ncch')
            ncch_rebuildall(i, dev)

    CCIBuilder(cci_header='cci_header.bin', card_info='card_info.bin', mastering_info='mastering_info.bin', initialdata='initialdata.bin', card_device_info=card_device_info, ncchs=ncchs, dev=dev, out=out)
    if not os.path.isfile(f'../{out}'):
        shutil.move(out, f'../{out}')
    else:
        shutil.move(out, f'../{name} (new).3ds')
    os.chdir('..')

def cia_extractall(path, dev=0):
    name = os.path.splitext(os.path.basename(path))[0]
    os.mkdir(name)

    cia = CIAReader(path, dev)
    cia.extract()

    for i in cia.files.keys():
        shutil.move(i, os.path.join(name, i))

        if i.endswith('.ncch'):
            os.chdir(name)
            ncch_extractall(i)
            os.chdir('..')

def cia_rebuildall(path, dev=0):
    os.chdir(path)
    name = os.path.basename(os.getcwd())
    out = f'{name}.cia'

    cf = []
    meta = 0
    if os.path.isfile('meta.bin'):
        meta = 1

    for i in os.listdir('.'):
        if os.path.isdir(i) or (os.path.isfile(i) and i.endswith('.nds')):
            if os.path.isdir(i):
                cf.append(f'{i}.ncch')
                if os.path.isfile(f'{i}.ncch'):
                    os.remove(f'{i}.ncch')
                ncch_rebuildall(i, dev)
            else:
                cf.append(i)

    CIABuilder(certs='cert.bin', content_files=cf, tik='tik', tmd='tmd', meta=meta, dev=dev, out=out)
    if not os.path.isfile(f'../{out}'):
        shutil.move(out, f'../{out}')
    else:
        shutil.move(out, f'../{name} (new).cia')
    os.chdir('..')

def cci2cia(path, out='', cci_dev=0, cia_dev=0):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_conv.cia'

    cci = CCIReader(path, cci_dev)
    cci.extract()

    ncchs = [i for i in cci.files.keys() if i.endswith('.ncch')]
    for i in ['content6.update_n3ds.ncch', 'content7.update_o3ds.ncch']:
        if i in ncchs:
            ncchs.remove(i)
            os.remove(i)

    if cia_dev == 0:
        regen_sig = 'retail'
    else:
        regen_sig = 'dev'

    for i in ncchs:
        n = NCCHReader(i, dev=cci_dev)
        n.extract()
        os.remove(i)

        if i.startswith('content0'):
            with open('exheader.bin', 'r+b') as f:
                f.seek(0xD)
                flag = readle(f.read(1))
                f.seek(0xD)
                f.write(int8tobytes(flag | 2)) # Set SDApplication bit

        ncch_header = 'ncch_header.bin'
        if os.path.isfile('exheader.bin'):
            exheader = 'exheader.bin'
        else:
            exheader = ''
        if os.path.isfile('logo.bin'):
            logo = 'logo.bin'
        else:
            logo = ''
        if os.path.isfile('plain.bin'):
            plain = 'plain.bin'
        else:
            plain = ''
        if os.path.isfile('exefs.bin'):
            exefs = 'exefs.bin'
        else:
            exefs = ''
        if os.path.isfile('romfs.bin'):
            romfs = 'romfs.bin'
        else:
            romfs = ''
        NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, regen_sig=regen_sig, dev=cia_dev, out=i)
        for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
            if j != '':
                os.remove(j)

    cf = []
    d = {
        'content0.game.ncch': '0000.00000000.ncch',
        'content1.manual.ncch': '0001.00000001.ncch',
        'content2.dlp.ncch': '0002.00000002.ncch'
    }
    for i in ncchs:
        cf.append(d[i])
        shutil.move(i, d[i])

    TMDBuilder(content_files=cf, content_files_dev=cia_dev, titleID=hex(readle(cci.hdr.mediaID))[2:].zfill(16), title_ver=0, crypt=0, regen_sig=regen_sig, out='tmd')
    tikBuilder(titleID=hex(readle(cci.hdr.mediaID))[2:].zfill(16), title_ver=0, regen_sig=regen_sig, out='tik')

    CIABuilder(content_files=cf, tik='tik', tmd='tmd', meta=1, dev=cia_dev, out=out)

    for i in ['cci_header.bin', 'card_info.bin', 'mastering_info.bin', 'initialdata.bin', 'card_device_info.bin', 'tmd', 'tik'] + cf:
        if os.path.exists(i):
            os.remove(i)

import zipfile
def cdn2cia(path, out='', title_ver='', cdn_dev=0, cia_dev=0):
    if os.path.isfile(path):
        try: zipf = zipfile.ZipFile(path)
        except: raise ValueError('Path is a file but not a ZIP file.')
        name = os.path.splitext(os.path.basename(path))[0]
        tmpd = os.path.abspath('tmp' + os.urandom(6).hex())
        os.mkdir(tmpd)
        zipf.extractall(tmpd)
        zipf.close()
        os.chdir(tmpd)
    else:
        tmpd = None
        os.chdir(path)
        name = os.path.basename(os.getcwd())

    content_files = []
    tmds = []
    tmd = ''
    tik = ''
    for i in os.listdir('.'):
        if i.startswith('tmd.') or i == 'tmd':
            tmds.append(i)
        elif i == 'cetk':
            tik = i
        elif i.startswith('0'):
            content_files.append(i)

    if len(tmds) == 1: # If only one tmd in CDN dir, use it
        tmd = tmds[0]
    else:
        tmds.sort(key=lambda h: int(os.path.splitext(h)[1].strip('.') or 0))
        if title_ver == '': # If title version not provided, use latest one
            tmd = tmds[-1]
        else:
            tmd = f'tmd.{title_ver}'

    if cia_dev == 0:
        regen_sig = 'retail'
    else:
        regen_sig = 'dev'

    t = TMDReader(tmd)
    if out == '':
        out = f'{name}.{t.hdr.title_ver}.cia'

    cdn = CDNReader(content_files=content_files, tmd=tmd, tik=tik, dev=cdn_dev)
    cdn.extract()
    cf = [i for i in os.listdir('.') if i.endswith('.ncch') or i.endswith('.nds')]
    tmd += '.extracted'

    if tik == '':
        tikBuilder(titleID=t.titleID, title_ver=t.hdr.title_ver, titlekey=hex(readbe(cdn.titlekey))[2:].zfill(32), regen_sig=regen_sig, out='tik')
        tik = 'tik'
    else:
        tik += '.extracted'

    meta = 1
    if t.titleID[3:5] == '48':
        meta = 0
    CIABuilder(content_files=cf, tik=tik, tmd=tmd, meta=meta, dev=cia_dev, out='tmp.cia')
    for i in cf + [tmd, tik]:
        os.remove(i)

    shutil.move('tmp.cia', '../tmp.cia')
    os.chdir('..')
    shutil.move('tmp.cia', out)

    if tmpd:
        shutil.rmtree(tmpd)

def cia2cdn(path, out='', titlekey='', cia_dev=0):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = name

    cia = CIAReader(path, cia_dev)
    cia.extract()
    for i in ['cia_header.bin', 'cert.bin', 'meta.bin']:
        if os.path.isfile(i):
            os.remove(i)

    tik = 'tik'
    tik_read = tikReader(tik)
    if not tik_read.verify()[0][1]: # Ticket has invalid sig
        tik = ''

    cf = [i for i in os.listdir('.') if i.endswith('.ncch') or i.endswith('.nds')]
    CDNBuilder(content_files=cf, tik=tik, tmd='tmd', titlekey=titlekey, out=out)

    for i in ['tik', 'tmd'] + cf:
        if os.path.isfile(i):
            os.remove(i)

def csu2retailcias(path, out=''):
    if out == '':
        out = 'updates_retail/'

    cci = CCIReader(path, dev=1)
    cci.extract()

    n = NCCHReader('content0.game.ncch', dev=1)
    n.extract()
    romfs = RomFSReader('romfs.bin')
    romfs.extract()

    cnt = cntReader('romfs/contents/Contents.cnt', 'romfs/contents/CupList')
    cnt.extract()

    for i in ['cci_header.bin', 'card_info.bin', 'mastering_info.bin', 'initialdata.bin', 'card_device_info.bin', 'content0.game.ncch', 'ncch_header.bin', 'exheader.bin', 'logo.bin', 'plain.bin', 'exefs.bin', 'romfs.bin']:
        if os.path.exists(i):
            os.remove(i)
    shutil.rmtree('romfs/')

    if not os.path.isdir(out):
        os.mkdir(out)
    for i in os.listdir('updates/'):
        cia_dev2retail(path=os.path.join('updates/', i), out=os.path.join(out, i))
    shutil.rmtree('updates/')
