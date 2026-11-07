# Font subsets for report.html: LXGW WenKai (Chinese, digits) + IM Fell English (Latin italics),
# same faces as the schedule site. Regular carries the 3755 common GB2312 level-1 characters so
# names edited in names.json still render; Medium only what the template/names use.
# Run once (needs fonttools + brotli): python fonts.py
import os
from fontTools.ttLib import TTFont
from fontTools import subset

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, '_fonts')
text = open(os.path.join(ROOT, 'analyze.js'), encoding='utf-8').read()
text += open(os.path.join(ROOT, 'names.json'), encoding='utf-8').read()
ascii_ = set(chr(c) for c in range(0x20, 0x7f))
punct = set('，。、；：？！“”‘’（）《》【】—…·％／～　零一二三四五六七八九十▸◀→←')
level1 = set()
for hi in range(0xB0, 0xD8):
    for lo in range(0xA1, 0xFF):
        try: level1.add(bytes([hi, lo]).decode('gb2312'))
        except UnicodeDecodeError: pass
used = set(text) | ascii_ | punct

def build(src, chars, out):
    f = TTFont(os.path.join(SRC, src))
    o = subset.Options(); o.flavor = 'woff2'; o.layout_features = ['kern', 'liga', 'onum', 'pnum', 'lnum', 'calt']; o.notdef_outline = True
    s = subset.Subsetter(o); s.populate(text=''.join(sorted(chars))); s.subset(f)
    f.flavor = 'woff2'; p = os.path.join(ROOT, 'assets', out); f.save(p)
    print(out, len(chars), 'chars', round(os.path.getsize(p) / 1024), 'KB')

build('LXGWWenKai-Regular.ttf', used | level1, 'wk-400.woff2')
build('LXGWWenKai-Medium.ttf', used, 'wk-500.woff2')
build('IMFeENrm28P.ttf', ascii_ | set('–—’“”'), 'fell-r.woff2')
build('IMFeENit28P.ttf', ascii_ | set('–—’“”'), 'fell-i.woff2')
