#
###############################################################################################
# ___  ___    ___    ___   _  _      ___ __  __ _____  ___   ___    ___  _____   ___   ___ #
#| __|| _ )  / _ \  / _ \ | |/      | __|\ \/ /|_   _|| _ \ / _ \  / __||_   _| / _ \ | _ \#
#| _| | _ \ | (_) || (_) ||   <     | _|  >  <   | |  |   // /_\ \| (__   | |  | (_) ||   /#
#|___||___/  \___/  \___/ |_|\_     |___|/_/\_\  |_|  |_|_\\_/ \_/ \___|  |_|   \___/ |_|_\#
###########################################################################################
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import zipfile
import xml.etree.ElementTree as ET
import os
import re
import html
from pathlib import Path
import base64
from io import BytesIO
from PIL import Image, ImageTk, ImageDraw
import struct

def _u16be(b, off):
    return struct.unpack_from(">H", b, off)[0]

def _u32be(b, off):
    return struct.unpack_from(">I", b, off)[0]

def _parse_pdb_records(data):
    if len(data) < 78:
        raise ValueError("File too small to be a valid PDB/MOBI")
    num_records = _u16be(data, 76)
    rec_list_off = 78
    need = rec_list_off + num_records * 8
    if len(data) < need:
        raise ValueError("Corrupt PDB: record list truncated")
    offsets = []
    for i in range(num_records):
        off = _u32be(data, rec_list_off + i * 8)
        offsets.append(off)
    recs = []
    for i, off in enumerate(offsets):
        end = offsets[i + 1] if i + 1 < len(offsets) else len(data)
        if off > end or end > len(data):
            raise ValueError("Corrupt PDB: invalid record offsets")
        recs.append(data[off:end])
    return recs

def _find_mobi_headers(rec0):
    if len(rec0) < 16:
        raise ValueError("Invalid MOBI: record 0 too small")
    compression = _u16be(rec0, 0)
    text_length = _u32be(rec0, 4)
    text_record_count = _u16be(rec0, 8)
    mobi_pos = rec0.find(b"MOBI")
    if mobi_pos < 0:
        raise ValueError("Not a MOBI: missing MOBI header signature")
    if len(rec0) < mobi_pos + 8:
        raise ValueError("Invalid MOBI: truncated MOBI header")
    mobi_header_len = _u32be(rec0, mobi_pos + 4)
    encoding = None
    if mobi_header_len >= 16 and len(rec0) >= mobi_pos + 16:
        encoding = _u32be(rec0, mobi_pos + 12)
    return {
        "compression": compression,
        "text_length": text_length,
        "text_record_count": text_record_count,
        "encoding": encoding,
    }

def _palmdoc_decompress(comp):
    out = bytearray()
    i = 0
    n = len(comp)
    while i < n:
        c = comp[i]
        i += 1
        if c == 0x00:
            out.append(0x00)
            continue
        if 0x01 <= c <= 0x08:
            if i + c > n:
                break
            out.extend(comp[i:i + c])
            i += c
            continue
        if 0x09 <= c <= 0x7F:
            out.append(c)
            continue
        if 0x80 <= c <= 0xBF:
            if i >= n:
                break
            c2 = comp[i]
            i += 1
            dist = ((c & 0x3F) << 8) | c2
            length = (dist & 0x07) + 3
            dist >>= 3
            if dist == 0:
                continue
            if dist > len(out):
                continue
            start = len(out) - dist
            for _ in range(length):
                out.append(out[start])
                start += 1
            continue
        out.append(0x20)
        out.append(c ^ 0x80)
    return bytes(out)

def _decode_mobi_bytes(b, encoding_code):
    if encoding_code == 65001:
        return b.decode("utf-8", errors="replace")
    if encoding_code == 1252:
        return b.decode("cp1252", errors="replace")
    try:
        return b.decode("utf-8", errors="strict")
    except Exception:
        return b.decode("cp1252", errors="replace")

class Icons:
    @staticmethod
    def create_folder_icon():
        img = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.rectangle([2, 6, 18, 17], fill='#F59E0B', outline='#D97706')
        draw.polygon([(2, 6), (7, 6), (9, 4), (14, 4), (14, 6)], fill='#FBBF24', outline='#D97706')
        return img

    @staticmethod
    def create_refresh_icon():
        img = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.arc([3, 3, 17, 17], 30, 330, fill='#10B981', width=2)
        draw.polygon([(15, 2), (18, 7), (12, 7)], fill='#10B981')
        return img

    @staticmethod
    def create_export_icon():
        img = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.rectangle([4, 8, 16, 18], fill='#3B82F6', outline='#2563EB')
        draw.polygon([(10, 2), (15, 7), (12, 7), (12, 10), (8, 10), (8, 7), (5, 7)], fill='#10B981', outline='#059669')
        return img

    @staticmethod
    def create_file_icon(color):
        img = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.polygon([(3, 1), (13, 1), (17, 5), (17, 19), (3, 19)], fill='#FFFFFF', outline='#6B7280')
        draw.polygon([(13, 1), (13, 5), (17, 5)], fill='#E5E7EB', outline='#6B7280')
        draw.rectangle([5, 10, 15, 12], fill=color)
        draw.rectangle([5, 14, 12, 16], fill=color)
        return img

    @staticmethod
    def create_nav_icon(direction):
        img = Image.new('RGBA', (24, 24), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        color = '#3B82F6'
        if direction == 'first':
            draw.rectangle([5, 6, 8, 18], fill=color)
            draw.polygon([(10, 12), (18, 6), (18, 18)], fill=color)
        elif direction == 'prev':
            draw.polygon([(8, 12), (18, 5), (18, 19)], fill=color)
        elif direction == 'next':
            draw.polygon([(16, 12), (6, 5), (6, 19)], fill=color)
        elif direction == 'last':
            draw.rectangle([16, 6, 19, 18], fill=color)
            draw.polygon([(14, 12), (6, 6), (6, 18)], fill=color)
        return img

    @staticmethod
    def create_search_icon():
        img = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.ellipse([2, 2, 12, 12], fill='#E0E7FF', outline='#6366F1', width=2)
        draw.line([(11, 11), (17, 17)], fill='#6366F1', width=3)
        return img

    @staticmethod
    def create_chapter_icon():
        img = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.rectangle([3, 2, 17, 18], fill='#FEF3C7', outline='#F59E0B')
        draw.line([(5, 6), (15, 6)], fill='#D97706', width=1)
        draw.line([(5, 9), (15, 9)], fill='#D97706', width=1)
        draw.line([(5, 12), (12, 12)], fill='#D97706', width=1)
        return img

    @staticmethod
    def create_refresh_icon():
        img = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.arc([3, 3, 17, 17], 30, 330, fill='#10B981', width=2)
        draw.polygon([(15, 2), (18, 6), (14, 7)], fill='#10B981')
        return img


class LightTheme:
    BG = "#F8FAFC"
    BG_SECONDARY = "#FFFFFF"
    BG_TERTIARY = "#F1F5F9"
    FG = "#1E293B"
    FG_DIM = "#64748B"
    ACCENT = "#3B82F6"
    ACCENT_HOVER = "#2563EB"
    BORDER = "#E2E8F0"
    SUCCESS = "#10B981"
    ERROR = "#EF4444"
    TEXT_BG = "#FFFFFF"
    SELECTION = "#BFDBFE"
    HEADER_BG = "#F1F5F9"


SUPPORTED_FORMATS = {
    'All Supported': ['*.epub', '*.docx', '*.html', '*.htm', '*.rtf', '*.mobi', '*.prc'],
    'EPUB': ['*.epub'],
    'DOCX': ['*.docx'],
    'HTML': ['*.html', '*.htm'],
    'RTF': ['*.rtf'],
    'MOBI': ['*.mobi', '*.prc'],
        }


FILE_COLORS = {
    '.epub': '#8B5CF6',
    '.docx': '#3B82F6',
    '.html': '#F59E0B',
    '.htm': '#F59E0B',
    '.rtf': '#10B981',
    '.mobi': '#EC4899',
    '.prc': '#EC4899',
    }

class DocumentParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.text = ""
        self.lines = []
        self.chapters = []
        self.ext = Path(filepath).suffix.lower()

    def parse(self):
        try:
            if self.ext == '.epub':
                return self._parse_epub()
            elif self.ext == '.docx':
                return self._parse_docx()
            elif self.ext in ('.html', '.htm'):
                return self._parse_html()
            elif self.ext == '.rtf':
                return self._parse_rtf()

            elif self.ext in ('.mobi', '.prc'):
                return self._parse_mobi()
            else:
                return False

        except Exception as e:
            print(f"Error parsing {self.filepath}: {e}")
            return False

    def _parse_epub(self):
        with zipfile.ZipFile(self.filepath, 'r') as zf:
            content_files = self._get_epub_content_files(zf)
            all_lines = []
            for cf in content_files:
                try:
                    raw = zf.read(cf).decode('utf-8', errors='ignore')
                    self._extract_chapters_from_html(raw, len(all_lines))
                    text = self._html_to_text(raw)
                    if text.strip():
                        file_lines = text.split('\n')
                        all_lines.extend(file_lines)
                except Exception:
                    continue
            self.lines = all_lines
            self.text = '\n'.join(all_lines)
        return True

    def _get_epub_content_files(self, zf):
        content_files = []
        opf_path = None
        for name in zf.namelist():
            if name.endswith('.opf'):
                opf_path = name
                break
        if not opf_path:
            for name in zf.namelist():
                if name.endswith('container.xml'):
                    try:
                        container = zf.read(name).decode('utf-8', errors='ignore')
                        root = ET.fromstring(container)
                        for elem in root.iter():
                            if 'rootfile' in elem.tag:
                                opf_path = elem.get('full-path')
                                break
                    except Exception:
                        pass
                    break
        if opf_path:
            try:
                opf_content = zf.read(opf_path).decode('utf-8', errors='ignore')
                opf_root = ET.fromstring(opf_content)
                opf_dir = os.path.dirname(opf_path)
                spine_idrefs = []
                manifest_items = {}
                for elem in opf_root.iter():
                    if 'item' in elem.tag:
                        item_id = elem.get('id')
                        href = elem.get('href')
                        media_type = elem.get('media-type', '')
                        if item_id and href:
                            manifest_items[item_id] = (href, media_type)
                    elif 'itemref' in elem.tag:
                        idref = elem.get('idref')
                        if idref:
                            spine_idrefs.append(idref)
                for idref in spine_idrefs:
                    if idref in manifest_items:
                        href, media_type = manifest_items[idref]
                        if 'html' in media_type or 'xml' in media_type:
                            # full_path = os.path.join(opf_dir, href).replace('\\', '/')
                            # full_path = os.path.normpath(full_path).replace('\\', '/')
                            if opf_dir:
                                full_path = opf_dir + '/' + href
                            else:
                                full_path = href
                            full_path = full_path.replace('\\', '/')
                            while '//' in full_path:
                                full_path = full_path.replace('//', '/')
                            if full_path.startswith('/'):
                                full_path = full_path[1:]
                            namelist = [n.replace('\\', '/') for n in zf.namelist()]
                            if full_path in namelist:
                                content_files.append(full_path)
                            else:
                                for name in namelist:
                                    if name.endswith(href) or href in name:
                                        content_files.append(name)
                                        break
                            content_files.append(full_path)
            except Exception:
                pass
        if not content_files:
            for name in zf.namelist():
                lower = name.lower()
                if lower.endswith(('.xhtml', '.html', '.htm', '.xml')):
                    if 'toc' not in lower and 'nav' not in lower:
                        content_files.append(name)
            content_files.sort()
        return content_files

    def _parse_docx(self):
        with zipfile.ZipFile(self.filepath, 'r') as zf:
            all_lines = []
            if 'word/document.xml' in zf.namelist():
                raw = zf.read('word/document.xml').decode('utf-8', errors='ignore')
                root = ET.fromstring(raw)
                ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
                for para in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
                    para_text = []
                    for text_elem in para.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t'):
                        if text_elem.text:
                            para_text.append(text_elem.text)
                    line = ''.join(para_text).strip()
                    if line:
                        style = para.find('.//w:pStyle', ns)
                        if style is not None:
                            style_val = style.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}val', '')
                            if 'Heading' in style_val or 'heading' in style_val or 'Title' in style_val:
                                if self._is_valid_chapter(line):
                                    self.chapters.append({'title': line, 'line': len(all_lines)})
                        all_lines.append(line)
            self.lines = all_lines
            self.text = '\n'.join(all_lines)
        return True

    def _parse_html(self):
        with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.read()
        self._extract_chapters_from_html(raw, 0)
        self.text = self._html_to_text(raw)
        self.lines = self.text.split('\n')
        return True

    def _parse_mobi(self):
        with open(self.filepath, 'rb') as f:
            data = f.read()

        recs = _parse_pdb_records(data)
        if not recs:
            raise ValueError("No records found")

        headers = _find_mobi_headers(recs[0])
        comp = headers["compression"]
        text_records = headers["text_record_count"]
        encoding = headers["encoding"]

        if comp not in (1, 2):
            raise ValueError(f"Unsupported compression: {comp}")

        start_idx = 1
        end_idx = start_idx + text_records
        if end_idx > len(recs):
            raise ValueError("Invalid MOBI: text record count exceeds records")

        chunks = []
        for r in recs[start_idx:end_idx]:
            if comp == 1:
                chunks.append(r)
            else:
                chunks.append(_palmdoc_decompress(r))

        raw_bytes = b"".join(chunks)

        tlen = headers["text_length"]
        if tlen and tlen < len(raw_bytes):
            raw_bytes = raw_bytes[:tlen]

        raw_text = _decode_mobi_bytes(raw_bytes, encoding)
        self.text = self._mobi_to_text(raw_text)
        self.lines = [line for line in self.text.split('\n') if line.strip()]
        self._extract_mobi_chapters()
        return True

    def _mobi_to_text(self, raw):
        s = raw
        s = s.replace("&nbsp;", " ")
        s = s.replace("&amp;", "&")
        s = s.replace("&lt;", "<")
        s = s.replace("&gt;", ">")
        s = s.replace("&quot;", "\"")
        s = s.replace("&#39;", "'")
        s = s.replace("&mdash;", "—")
        s = s.replace("&ndash;", "–")
        s = s.replace("&hellip;", "…")
        s = s.replace("&rsquo;", "'")
        s = s.replace("&lsquo;", "'")
        s = s.replace("&rdquo;", """)
        s = s.replace("&ldquo;", """)

        out = []
        in_tag = False
        for ch in s:
            if ch == "<":
                in_tag = True
                continue
            if ch == ">":
                in_tag = False
                out.append(" ")
                continue
            if not in_tag:
                out.append(ch)
        s = "".join(out)

        lines = []
        for ln in s.replace("\r", "\n").split("\n"):
            ln = ' '.join(ln.split()).strip()
            if ln:
                lines.append(ln)

        return '\n'.join(lines)

    def _extract_mobi_chapters(self):
        chapter_patterns = [
            r'^chapter\s+\d+',
            r'^chapter\s+(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty)',
            r'^chapter\s+[ivxlcdm]+',
            r'^part\s+\d+',
            r'^part\s+(one|two|three|four|five|six|seven|eight|nine|ten)',
            r'^part\s+[ivxlcdm]+',
            r'^prologue',
            r'^epilogue',
        ]

        for i, line in enumerate(self.lines):
            line_stripped = line.strip()
            lower = line_stripped.lower()

            for pattern in chapter_patterns:
                if re.match(pattern, lower):
                    self.chapters.append({'title': line_stripped, 'line': i})
                    break

    def _parse_rtf(self):
        with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.read()
        text = self._rtf_to_text(raw)
        self.lines = text.split('\n')
        self.text = text
        self._extract_chapters_from_text()
        return True



    def _parse_rtf(self):
        with open(self.filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        self.text = self._extract_rtf_text(content)
        self.lines = [line for line in self.text.split('\n') if line.strip()]
        self._extract_rtf_chapters()
        return True

    def _extract_rtf_text(self, rtf_content):
        rtf_content = re.sub(r'\{\\pict[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'\{\\object[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'\{\\shp[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'\{\\themedata[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'\{\\colorschememapping[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'\{\\datastore[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'\{\\fonttbl[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'\{\\colortbl[^{}]*\}', '', rtf_content)
        rtf_content = re.sub(r'\{\\stylesheet[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'\{\\info[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'\{\\\*\\[a-z]+[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', rtf_content, flags=re.DOTALL)
        rtf_content = re.sub(r'[0-9a-fA-F]{100,}', '', rtf_content)

        text = ""
        i = 0
        n = len(rtf_content)

        while i < n:
            c = rtf_content[i]

            if c == '\\':
                i += 1
                if i >= n:
                    break

                if rtf_content[i] in '\\{}':
                    text += rtf_content[i]
                    i += 1
                    continue

                if rtf_content[i] == "'":
                    i += 1
                    if i + 1 < n:
                        try:
                            hex_val = rtf_content[i:i + 2]
                            text += chr(int(hex_val, 16))
                        except:
                            pass
                        i += 2
                    continue

                start = i
                while i < n and rtf_content[i].isalpha():
                    i += 1
                word = rtf_content[start:i]

                param_str = ''
                while i < n and (rtf_content[i].isdigit() or rtf_content[i] == '-'):
                    param_str += rtf_content[i]
                    i += 1

                if i < n and rtf_content[i] == ' ':
                    i += 1

                if word == 'par':
                    text += '\n'
                elif word == 'line':
                    text += '\n'
                elif word == 'tab':
                    text += '\t'
                elif word == 'u' and param_str:
                    try:
                        code = int(param_str)
                        if code < 0:
                            code += 65536
                        if 0 < code < 0x110000:
                            text += chr(code)
                    except:
                        pass
                continue

            elif c == '{':
                i += 1
                continue

            elif c == '}':
                i += 1
                continue

            elif c.isprintable() and 31 < ord(c) < 127:
                text += c
                i += 1

            elif ord(c) > 127:
                i += 1

            else:
                i += 1

        lines = []
        for line in text.split('\n'):
            line = line.strip()
            if line and len(line) > 1:
                if not re.match(r'^[0-9a-fA-F]+$', line):
                    lines.append(line)

        return '\n'.join(lines)

    def _extract_rtf_chapters(self):
        for i, line in enumerate(self.lines):
            line_stripped = line.strip()
            lower = line_stripped.lower()

            is_chapter = False

            if any(lower.startswith(p) for p in ["chapter ", "chapter:", "part ", "part:", "prologue", "epilogue"]):
                is_chapter = True
            elif re.match(r'^(chapter|part)\s+[ivxlcdm\d]+', lower):
                is_chapter = True
            elif re.match(r'^(chapter|part)\s+(one|two|three|four|five|six|seven|eight|nine|ten)', lower):
                is_chapter = True

            if is_chapter:
                if self._is_valid_chapter(line_stripped):
                    self.chapters.append({'title': line_stripped, 'line': i})

        print(f"Found {len(self.chapters)} chapters")  # Debug

    def _extract_chapters_from_html(self, raw_html, line_offset):
        matches = re.finditer(r'<h([12])[^>]*>(.*?)</h\1>', raw_html, re.DOTALL | re.IGNORECASE)
        temp_text = raw_html
        for match in matches:
            title = re.sub(r'<[^>]+>', '', match.group(2))
            title = html.unescape(title)
            title = ' '.join(title.split()).strip()
            if title and len(title) > 1:
                if self._is_valid_chapter(title):
                    before_match = temp_text[:match.start()]
                    before_text = self._html_to_text(before_match)
                    line_num = line_offset + len([l for l in before_text.split('\n') if l.strip()])
                    self.chapters.append({'title': title, 'line': line_num})

    def _is_valid_chapter(self, title):
        title_lower = title.lower().strip()

        false_positives = [
            'author', 'by ', 'written by', 'copyright', '©', 'all rights reserved',
            'publisher', 'published by', 'printing', 'edition', 'isbn',
            'dedication', 'dedicated to', 'acknowledgment', 'acknowledgement',
            'table of contents', 'contents', 'index', 'bibliography', 'references',
            'about the author', 'about author', 'biography', 'also by',
            'other books', 'books by', 'works by', 'titles by',
            'cover', 'title page', 'half title', 'frontispiece',
            'epigraph', 'disclaimer', 'note to reader', 'editor',
            'translator', 'illustrator', 'designer', 'jacket',
            'www.', 'http', '.com', '.org', '.net', '@',
            'email', 'contact', 'address', 'phone', 'fax',
            'printed in', 'made in', 'manufactured',
            'first published', 'originally published', 'reprinted',
            'paperback', 'hardcover', 'ebook', 'e-book', 'kindle',
            'library of congress', 'cataloging', 'catalogue', 'prologue', 'TOC',
            'foreword', 'preface', 'introduction'
        ]

        for fp in false_positives:
            if fp in title_lower:
                return False

        if re.match(r'^[a-z\s\.\,\-]+$', title_lower):
            words = title_lower.split()
            if len(words) <= 4:
                if not self._is_chapter_pattern(title):
                    name_pattern = r'^[A-Z][a-z]+(\s+[A-Z]\.?)?(\s+[A-Z][a-z]+)+$'
                    if re.match(name_pattern, title):
                        return False

        if self._is_chapter_pattern(title):
            return True

        if len(title) < 2:
            return False

        if re.match(r'^\d{4}$', title):
            return False

        if re.match(r'^[\d\s\-\.\,\(\)]+$', title):
            return False

        return True

    def _is_chapter_pattern(self, title):
        title_check = title.strip()

        patterns = [
            r'^chapter\s+\d+',
            r'^chapter\s+(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty)',
            r'^chapter\s+[ivxlcdm]+',
            r'^ch\.?\s*\d+',
            r'^part\s+\d+',
            r'^part\s+(one|two|three|four|five|six|seven|eight|nine|ten)',
            r'^part\s+[ivxlcdm]+',
            r'^section\s+\d+',
            r'^book\s+\d+',
            r'^book\s+(one|two|three|four|five|six|seven|eight|nine|ten)',
            r'^volume\s+\d+',
            r'^act\s+\d+',
            r'^act\s+[ivxlcdm]+',
            r'^scene\s+\d+',
            r'^\d+\.\s+\w+',
            r'^[ivxlcdm]+\.\s+\w+',
            r'^prologue',
            r'^epilogue',
            r'^afterword',
            r'^conclusion',
            r'^appendix',
        ]

        for pattern in patterns:
            if re.match(pattern, title_check, re.IGNORECASE):
                return True

        return False

    def _html_to_text(self, raw_html):
        raw_html = re.sub(r'<style[^>]*>.*?</style>', '', raw_html, flags=re.DOTALL | re.IGNORECASE)
        raw_html = re.sub(r'<script[^>]*>.*?</script>', '', raw_html, flags=re.DOTALL | re.IGNORECASE)
        raw_html = re.sub(r'<(p|div|br|h[1-6]|li|tr)[^>]*>', '\n', raw_html, flags=re.IGNORECASE)
        raw_html = re.sub(r'<[^>]+>', '', raw_html)
        text = html.unescape(raw_html)
        lines = []
        for line in text.split('\n'):
            line = ' '.join(line.split())
            if line:
                lines.append(line)
        return '\n'.join(lines)

    def get_line_count(self):
        return len(self.lines)

    def get_page(self, page_num, lines_per_page=50):
        start = page_num * lines_per_page
        end = start + lines_per_page
        return '\n'.join(self.lines[start:end])

    def get_total_pages(self, lines_per_page=50):
        if not self.lines:
            return 0
        return (len(self.lines) + lines_per_page - 1) // lines_per_page


    def get_chapters(self):
        return self.chapters


class ExportDialog(tk.Toplevel):
    def __init__(self, parent, file_data, icons):
        super().__init__(parent)
        self.title("Export Options")
        self.geometry("520x550")
        self.configure(bg=LightTheme.BG)
        self.transient(parent)
        self.grab_set()
        self.file_data = file_data
        self.icons = icons
        self.result = None
        self._build_ui()
        self._center_window()

    def _center_window(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        main_frame = tk.Frame(self, bg=LightTheme.BG, padx=25, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_frame = tk.Frame(main_frame, bg=LightTheme.BG)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        tk.Label(title_frame, image=self.icons['export'], bg=LightTheme.BG).pack(side=tk.LEFT, padx=(0, 10))
        tk.Label(title_frame, text="Export Documents", font=("Segoe UI", 16, "bold"), fg=LightTheme.FG,
                 bg=LightTheme.BG).pack(side=tk.LEFT)

        filter_frame = tk.LabelFrame(main_frame, text="Filters", font=("Segoe UI", 10, "bold"), fg=LightTheme.FG,
                                     bg=LightTheme.BG, bd=1, relief=tk.SOLID)
        filter_frame.pack(fill=tk.X, pady=(0, 15))
        filter_inner = tk.Frame(filter_frame, bg=LightTheme.BG, padx=15, pady=10)
        filter_inner.pack(fill=tk.X)

        row1 = tk.Frame(filter_inner, bg=LightTheme.BG)
        row1.pack(fill=tk.X, pady=5)
        tk.Label(row1, text="File Size (KB):", font=("Segoe UI", 10), fg=LightTheme.FG, bg=LightTheme.BG, width=12,
                 anchor=tk.W).pack(side=tk.LEFT)
        tk.Label(row1, text="Min:", font=("Segoe UI", 9), fg=LightTheme.FG_DIM, bg=LightTheme.BG).pack(side=tk.LEFT,
                                                                                                       padx=(5, 2))
        self.size_min = tk.Entry(row1, width=10, font=("Segoe UI", 10), relief=tk.SOLID, bd=1)
        self.size_min.pack(side=tk.LEFT)
        self.size_min.insert(0, "0")
        tk.Label(row1, text="Max:", font=("Segoe UI", 9), fg=LightTheme.FG_DIM, bg=LightTheme.BG).pack(side=tk.LEFT,
                                                                                                       padx=(15, 2))
        self.size_max = tk.Entry(row1, width=10, font=("Segoe UI", 10), relief=tk.SOLID, bd=1)
        self.size_max.pack(side=tk.LEFT)
        self.size_max.insert(0, "999999")

        row2 = tk.Frame(filter_inner, bg=LightTheme.BG)
        row2.pack(fill=tk.X, pady=5)
        tk.Label(row2, text="Line Count:", font=("Segoe UI", 10), fg=LightTheme.FG, bg=LightTheme.BG, width=12,
                 anchor=tk.W).pack(side=tk.LEFT)
        tk.Label(row2, text="Min:", font=("Segoe UI", 9), fg=LightTheme.FG_DIM, bg=LightTheme.BG).pack(side=tk.LEFT,
                                                                                                       padx=(5, 2))
        self.line_min = tk.Entry(row2, width=10, font=("Segoe UI", 10), relief=tk.SOLID, bd=1)
        self.line_min.pack(side=tk.LEFT)
        self.line_min.insert(0, "0")
        tk.Label(row2, text="Max:", font=("Segoe UI", 9), fg=LightTheme.FG_DIM, bg=LightTheme.BG).pack(side=tk.LEFT,
                                                                                                       padx=(15, 2))
        self.line_max = tk.Entry(row2, width=10, font=("Segoe UI", 10), relief=tk.SOLID, bd=1)
        self.line_max.pack(side=tk.LEFT)
        self.line_max.insert(0, "9999999")

        row3 = tk.Frame(filter_inner, bg=LightTheme.BG)
        row3.pack(fill=tk.X, pady=5)
        tk.Label(row3, text="Filename:", font=("Segoe UI", 10), fg=LightTheme.FG, bg=LightTheme.BG, width=12,
                 anchor=tk.W).pack(side=tk.LEFT)
        self.pattern = tk.Entry(row3, font=("Segoe UI", 10), relief=tk.SOLID, bd=1)
        self.pattern.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        self.pattern.insert(0, ".*")

        btn_filter = tk.Button(filter_inner, text="Apply Filter", font=("Segoe UI", 10), bg=LightTheme.ACCENT,
                               fg="white", relief=tk.FLAT, padx=15, pady=5, cursor="hand2", command=self._preview)
        btn_filter.pack(pady=(10, 5))

        list_frame = tk.LabelFrame(main_frame, text="Matching Files", font=("Segoe UI", 10, "bold"), fg=LightTheme.FG,
                                   bg=LightTheme.BG, bd=1, relief=tk.SOLID)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        list_inner = tk.Frame(list_frame, bg=LightTheme.BG, padx=10, pady=10)
        list_inner.pack(fill=tk.BOTH, expand=True)

        self.preview_list = tk.Listbox(list_inner, selectmode=tk.EXTENDED, font=("Segoe UI", 10), relief=tk.SOLID, bd=1,
                                       highlightthickness=0, activestyle='none', selectbackground=LightTheme.SELECTION,
                                       selectforeground=LightTheme.FG)
        scrollbar = tk.Scrollbar(list_inner, orient=tk.VERTICAL, command=self.preview_list.yview)
        self.preview_list.configure(yscrollcommand=scrollbar.set)
        self.preview_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = tk.Frame(main_frame, bg=LightTheme.BG)
        btn_frame.pack(fill=tk.X)

        btn_all = tk.Button(btn_frame, text="Export All Matching", font=("Segoe UI", 10), bg=LightTheme.SUCCESS,
                            fg="white", relief=tk.FLAT, padx=15, pady=8, cursor="hand2", command=self._export_all)
        btn_all.pack(side=tk.LEFT, padx=(0, 10))

        btn_selected = tk.Button(btn_frame, text="Export Selected", font=("Segoe UI", 10), bg=LightTheme.ACCENT,
                                 fg="white", relief=tk.FLAT, padx=15, pady=8, cursor="hand2",
                                 command=self._export_selected)
        btn_selected.pack(side=tk.LEFT)

        btn_cancel = tk.Button(btn_frame, text="Cancel", font=("Segoe UI", 10), bg=LightTheme.BG_TERTIARY,
                               fg=LightTheme.FG, relief=tk.FLAT, padx=15, pady=8, cursor="hand2", command=self.destroy)
        btn_cancel.pack(side=tk.RIGHT)

        self._preview()

    def _get_matching_files(self):
        try:
            size_min = float(self.size_min.get()) * 1024
            size_max = float(self.size_max.get()) * 1024
            line_min = int(self.line_min.get())
            line_max = int(self.line_max.get())
            pattern = re.compile(self.pattern.get(), re.IGNORECASE)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid filter: {e}")
            return []
        matching = []
        for filepath, data in self.file_data.items():
            size = data['size']
            lines = data['lines']
            name = os.path.basename(filepath)
            if size_min <= size <= size_max:
                if line_min <= lines <= line_max:
                    if pattern.search(name):
                        matching.append(filepath)
        return matching

    def _preview(self):
        self.preview_list.delete(0, tk.END)
        matching = self._get_matching_files()
        for fp in matching:
            self.preview_list.insert(tk.END, os.path.basename(fp))
        self.matching_files = matching

    def _export_all(self):
        if not self.matching_files:
            messagebox.showinfo("Info", "No files match the filters")
            return
        self.result = self.matching_files
        self.destroy()

    def _export_selected(self):
        selection = self.preview_list.curselection()
        if not selection:
            messagebox.showinfo("Info", "No files selected")
            return
        self.result = [self.matching_files[i] for i in selection]
        self.destroy()


class SearchDialog(tk.Toplevel):
    def __init__(self, parent, doc_data, current_file, on_result_click):
        super().__init__(parent)
        self.title("Search")
        self.geometry("600x500")
        self.configure(bg=LightTheme.BG)
        self.transient(parent)

        self.doc_data = doc_data
        self.current_file = current_file
        self.on_result_click = on_result_click
        self.results = []

        self._build_ui()
        self._center_window()

    def _center_window(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        main_frame = tk.Frame(self, bg=LightTheme.BG, padx=20, pady=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = tk.Label(main_frame, text="🔍 Search Documents", font=("Segoe UI", 14, "bold"), fg=LightTheme.FG,
                               bg=LightTheme.BG)
        title_label.pack(anchor=tk.W, pady=(0, 15))

        search_frame = tk.Frame(main_frame, bg=LightTheme.BG)
        search_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(search_frame, text="Search:", font=("Segoe UI", 10), fg=LightTheme.FG, bg=LightTheme.BG).pack(
            side=tk.LEFT, padx=(0, 5))
        self.search_entry = tk.Entry(search_frame, font=("Segoe UI", 11), relief=tk.SOLID, bd=1)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        self.search_entry.bind('<Return>', self._do_search)
        self.search_entry.focus_set()

        btn_search = tk.Button(search_frame, text="Search", font=("Segoe UI", 10), bg=LightTheme.ACCENT, fg="white",
                               relief=tk.FLAT, padx=15, pady=5, cursor="hand2", command=self._do_search)
        btn_search.pack(side=tk.LEFT, padx=(10, 0))

        options_frame = tk.Frame(main_frame, bg=LightTheme.BG)
        options_frame.pack(fill=tk.X, pady=(0, 10))

        self.scope_var = tk.StringVar(value="current")
        rb_current = tk.Radiobutton(options_frame, text="Current file", variable=self.scope_var, value="current",
                                    font=("Segoe UI", 10), fg=LightTheme.FG, bg=LightTheme.BG,
                                    activebackground=LightTheme.BG, selectcolor=LightTheme.BG)
        rb_current.pack(side=tk.LEFT, padx=(0, 15))
        rb_all = tk.Radiobutton(options_frame, text="All files", variable=self.scope_var, value="all",
                                font=("Segoe UI", 10), fg=LightTheme.FG, bg=LightTheme.BG,
                                activebackground=LightTheme.BG, selectcolor=LightTheme.BG)
        rb_all.pack(side=tk.LEFT, padx=(0, 15))

        self.case_var = tk.BooleanVar(value=False)
        cb_case = tk.Checkbutton(options_frame, text="Case sensitive", variable=self.case_var, font=("Segoe UI", 10),
                                 fg=LightTheme.FG, bg=LightTheme.BG, activebackground=LightTheme.BG,
                                 selectcolor=LightTheme.BG)
        cb_case.pack(side=tk.LEFT)

        self.whole_word_var = tk.BooleanVar(value=False)
        cb_whole = tk.Checkbutton(options_frame, text="Whole word", variable=self.whole_word_var, font=("Segoe UI", 10),
                                  fg=LightTheme.FG, bg=LightTheme.BG, activebackground=LightTheme.BG,
                                  selectcolor=LightTheme.BG)
        cb_whole.pack(side=tk.LEFT, padx=(15, 0))

        self.result_count_label = tk.Label(main_frame, text="", font=("Segoe UI", 9), fg=LightTheme.FG_DIM,
                                           bg=LightTheme.BG)
        self.result_count_label.pack(anchor=tk.W, pady=(0, 5))

        result_frame = tk.Frame(main_frame, bg=LightTheme.BG)
        result_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('file', 'line', 'text')
        self.result_tree = ttk.Treeview(result_frame, columns=columns, show='headings')
        self.result_tree.heading('file', text='File')
        self.result_tree.heading('line', text='Line')
        self.result_tree.heading('text', text='Match')
        self.result_tree.column('file', width=150, minwidth=100)
        self.result_tree.column('line', width=60, minwidth=40, anchor=tk.E)
        self.result_tree.column('text', width=350, minwidth=200)

        result_scroll = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=result_scroll.set)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        result_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_tree.bind('<Double-1>', self._on_result_double_click)
        self.result_tree.bind('<Return>', self._on_result_double_click)

        btn_frame = tk.Frame(main_frame, bg=LightTheme.BG)
        btn_frame.pack(fill=tk.X, pady=(15, 0))

        btn_goto = tk.Button(btn_frame, text="Go to Selected", font=("Segoe UI", 10), bg=LightTheme.SUCCESS, fg="white",
                             relief=tk.FLAT, padx=15, pady=6, cursor="hand2", command=self._goto_selected)
        btn_goto.pack(side=tk.LEFT)

        btn_close = tk.Button(btn_frame, text="Close", font=("Segoe UI", 10), bg=LightTheme.BG_TERTIARY,
                              fg=LightTheme.FG, relief=tk.FLAT, padx=15, pady=6, cursor="hand2", command=self.destroy)
        btn_close.pack(side=tk.RIGHT)

    def _do_search(self, event=None):
        query = self.search_entry.get().strip()
        if not query:
            return

        self.result_tree.delete(*self.result_tree.get_children())
        self.results = []

        case_sensitive = self.case_var.get()
        whole_word = self.whole_word_var.get()
        scope = self.scope_var.get()

        if scope == "current":
            if self.current_file and self.current_file in self.doc_data:
                files_to_search = {self.current_file: self.doc_data[self.current_file]}
            else:
                self.result_count_label.config(text="No file selected")
                return
        else:
            files_to_search = self.doc_data

        if whole_word:
            if case_sensitive:
                pattern = re.compile(r'\b' + re.escape(query) + r'\b')
            else:
                pattern = re.compile(r'\b' + re.escape(query) + r'\b', re.IGNORECASE)

        for filepath, data in files_to_search.items():
            parser = data['parser']
            filename = os.path.basename(filepath)

            for i, line in enumerate(parser.lines):
                if whole_word:
                    match = pattern.search(line)
                else:
                    if case_sensitive:
                        match = query in line
                    else:
                        match = query.lower() in line.lower()

                if match:
                    display_text = line[:80] + "..." if len(line) > 80 else line
                    result = {
                        'filepath': filepath,
                        'filename': filename,
                        'line_num': i,
                        'text': line,
                        'display_text': display_text
                    }
                    self.results.append(result)
                    self.result_tree.insert('', tk.END, iid=str(len(self.results) - 1),
                                            values=(filename, i + 1, display_text))

        self.result_count_label.config(text=f"Found {len(self.results)} match(es)")

    def _on_result_double_click(self, event):
        self._goto_selected()

    def _goto_selected(self):
        selection = self.result_tree.selection()
        if not selection:
            return
        idx = int(selection[0])
        if idx < len(self.results):
            result = self.results[idx]
            self.on_result_click(result['filepath'], result['line_num'], self.search_entry.get().strip(), self.case_var.get(), self.whole_word_var.get())

class DocumentConverterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Document to Text Converter")
        self.root.geometry("1300x900")
        self.root.configure(bg=LightTheme.BG)
        self.root.minsize(1000, 700)

        self.doc_data = {}
        self.current_file = None
        self.current_page = 0
        self.current_folder = None
        self.lines_per_page = 50
        self.current_format = 'All Supported'
        self.lazy_loading = False
        self.all_files = []
        self.loaded_count = 0
        self.page_size = 50

        self._load_icons()
        self._configure_styles()
        self._build_ui()
        self._center_window()

    def _center_window(self):
        self.root.update_idletasks()
        w = 1300
        h = 900
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _load_icons(self):
        self.icons = {}
        self.icons['folder'] = ImageTk.PhotoImage(Icons.create_folder_icon())
        self.icons['export'] = ImageTk.PhotoImage(Icons.create_export_icon())
        self.icons['chapter'] = ImageTk.PhotoImage(Icons.create_chapter_icon())
        self.icons['refresh'] = ImageTk.PhotoImage(Icons.create_refresh_icon())
        self.icons['search'] = ImageTk.PhotoImage(Icons.create_search_icon())
        self.icons['nav_first'] = ImageTk.PhotoImage(Icons.create_nav_icon('first'))
        self.icons['nav_prev'] = ImageTk.PhotoImage(Icons.create_nav_icon('prev'))
        self.icons['nav_next'] = ImageTk.PhotoImage(Icons.create_nav_icon('next'))
        self.icons['nav_last'] = ImageTk.PhotoImage(Icons.create_nav_icon('last'))
        self.icons['refresh'] = ImageTk.PhotoImage(Icons.create_refresh_icon())
        self.file_icons = {}
        for ext, color in FILE_COLORS.items():
            self.file_icons[ext] = ImageTk.PhotoImage(Icons.create_file_icon(color))

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        # style.configure("Treeview", background=LightTheme.TEXT_BG, foreground=LightTheme.FG,
        #                 fieldbackground=LightTheme.TEXT_BG, borderwidth=0, font=("Segoe UI", 10), rowheight=26)
        style.configure("Treeview", background=LightTheme.TEXT_BG, foreground=LightTheme.FG,
                        fieldbackground=LightTheme.TEXT_BG, borderwidth=1, font=("Segoe UI", 10), rowheight=28)
        style.configure("Treeview.Heading", background=LightTheme.HEADER_BG, foreground=LightTheme.FG, borderwidth=1,
                        relief="solid", font=("Segoe UI", 10, "bold"), padding=(5, 8))
        style.configure("Treeview.Heading", background=LightTheme.HEADER_BG, foreground=LightTheme.FG, borderwidth=0,
                        font=("Segoe UI", 10, "bold"), padding=(5, 8))
        style.map("Treeview", background=[("selected", LightTheme.SELECTION)], foreground=[("selected", LightTheme.FG)])
        style.map("Treeview.Heading", background=[("active", LightTheme.HEADER_BG)])
        style.configure("TCombobox", padding=5)
        style.map("TCombobox", fieldbackground=[("readonly", LightTheme.TEXT_BG)],
                  selectbackground=[("readonly", LightTheme.SELECTION)])
        self.file_type_tags = {}
        for ext, color in FILE_COLORS.items():
            tag_name = f"tag_{ext.replace('.', '')}"
            self.file_type_tags[ext] = tag_name

    def _build_ui(self):
        main_container = tk.Frame(self.root, bg=LightTheme.BG)
        main_container.pack(fill=tk.BOTH, expand=True)

        toolbar = tk.Frame(main_container, bg=LightTheme.BG_SECONDARY, height=50, bd=1, relief=tk.SOLID)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        toolbar.pack_propagate(False)

        toolbar_inner = tk.Frame(toolbar, bg=LightTheme.BG_SECONDARY)
        toolbar_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=8)

        btn_open = tk.Button(toolbar_inner, text=" Open Folder", image=self.icons['folder'], compound=tk.LEFT,
                             font=("Segoe UI", 10), bg=LightTheme.ACCENT, fg="white", relief=tk.FLAT, padx=12, pady=4,
                             cursor="hand2", command=self._browse_folder)
        btn_open.pack(side=tk.LEFT)

        sep1 = tk.Frame(toolbar_inner, width=1, bg=LightTheme.BORDER)
        sep1.pack(side=tk.LEFT, fill=tk.Y, padx=15)

        tk.Label(toolbar_inner, text="Format:", font=("Segoe UI", 10), fg=LightTheme.FG,
                 bg=LightTheme.BG_SECONDARY).pack(side=tk.LEFT, padx=(0, 5))
        self.format_var = tk.StringVar(value='All Supported')
        self.format_combo = ttk.Combobox(toolbar_inner, textvariable=self.format_var,
                                         values=list(SUPPORTED_FORMATS.keys()), state='readonly', width=14,
                                         font=("Segoe UI", 10))
        self.format_combo.pack(side=tk.LEFT)
        self.format_combo.bind('<<ComboboxSelected>>', self._on_format_change)
        btn_refresh = tk.Button(toolbar_inner, image=self.icons['refresh'], bg=LightTheme.BG_SECONDARY, relief=tk.FLAT,
                                bd=1, width=28, height=24, cursor="hand2", command=self._refresh_folder)
        btn_refresh.pack(side=tk.LEFT, padx=(10, 0))

        sep2 = tk.Frame(toolbar_inner, width=1, bg=LightTheme.BORDER)



        sep2 = tk.Frame(toolbar_inner, width=1, bg=LightTheme.BORDER)
        sep2.pack(side=tk.LEFT, fill=tk.Y, padx=15)

        btn_export_sel = tk.Button(toolbar_inner, text=" Export Selected", image=self.icons['export'], compound=tk.LEFT,
                                   font=("Segoe UI", 10), bg=LightTheme.SUCCESS, fg="white", relief=tk.FLAT, padx=12,
                                   pady=4, cursor="hand2", command=self._export_current)
        btn_export_sel.pack(side=tk.LEFT, padx=(0, 10))

        btn_export_all = tk.Button(toolbar_inner, text=" Export All...", image=self.icons['export'], compound=tk.LEFT,
                                   font=("Segoe UI", 10), bg="#8B5CF6", fg="white", relief=tk.FLAT, padx=12, pady=4,
                                   cursor="hand2", command=self._show_export_dialog)
        btn_export_all.pack(side=tk.LEFT)

        sep3 = tk.Frame(toolbar_inner, width=1, bg=LightTheme.BORDER)
        sep3.pack(side=tk.LEFT, fill=tk.Y, padx=15)

        btn_search = tk.Button(toolbar_inner, text=" Search", image=self.icons['search'], compound=tk.LEFT,
                               font=("Segoe UI", 10), bg="#E0E7FF", fg="#4338CA", relief=tk.FLAT, padx=12, pady=4,
                               cursor="hand2", command=self._show_search_dialog)
        btn_search.pack(side=tk.LEFT)

        content = tk.Frame(main_container, bg=LightTheme.BG)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.left_panel = tk.Frame(content, bg=LightTheme.BG_SECONDARY, width=420, bd=1, relief=tk.SOLID)
        self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 5))
        self.left_panel.pack_propagate(False)

        folder_header = tk.Frame(self.left_panel, bg=LightTheme.HEADER_BG, height=35, bd=1, relief=tk.SOLID,
                                 highlightbackground=LightTheme.BORDER, highlightthickness=1)
        folder_header.pack(fill=tk.X)
        folder_header.pack_propagate(False)
        tk.Label(folder_header, text="📂", font=("Segoe UI", 12), bg=LightTheme.HEADER_BG).pack(side=tk.LEFT,
                                                                                               padx=(10, 5), pady=5)
        self.folder_label = tk.Label(folder_header, text="No folder selected", font=("Segoe UI", 10),
                                     fg=LightTheme.FG_DIM, bg=LightTheme.HEADER_BG, anchor=tk.W)
        self.folder_label.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=5)

        summary_frame = tk.Frame(self.left_panel, bg=LightTheme.BG_TERTIARY, height=28)
        summary_frame.pack(fill=tk.X)
        summary_frame.pack_propagate(False)
        self.summary_label = tk.Label(summary_frame, text="0 files | 0 lines | 0 MB", font=("Segoe UI", 9),
                                      fg=LightTheme.FG_DIM, bg=LightTheme.BG_TERTIARY)
        self.summary_label.pack(side=tk.LEFT, padx=10, pady=4)

        file_list_frame = tk.Frame(self.left_panel, bg=LightTheme.BG_SECONDARY)
        file_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ('name', 'type', 'size', 'lines')
        self.file_tree = ttk.Treeview(file_list_frame, columns=columns, show='headings', style="Treeview")
        self.file_tree.heading('name', text='Name')
        self.file_tree.heading('type', text='Type')
        self.file_tree.heading('size', text='Size')
        self.file_tree.heading('lines', text='Lines')
        self.file_tree.column('name', width=160, minwidth=100)
        self.file_tree.column('type', width=50, minwidth=40, anchor=tk.CENTER)
        self.file_tree.column('size', width=65, minwidth=50, anchor=tk.E)
        self.file_tree.column('lines', width=65, minwidth=50, anchor=tk.E)

        file_scroll = ttk.Scrollbar(file_list_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=file_scroll.set)
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        file_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_tree.bind('<<TreeviewSelect>>', self._on_file_select)

        self.chapter_header = tk.Frame(self.left_panel, bg=LightTheme.HEADER_BG, height=35, bd=1, relief=tk.SOLID,
                                       highlightbackground=LightTheme.BORDER, highlightthickness=1)
        self.chapter_header.pack(fill=tk.X)
        self.chapter_header.pack_propagate(False)
        tk.Label(self.chapter_header, image=self.icons['chapter'], bg=LightTheme.HEADER_BG).pack(side=tk.LEFT,
                                                                                                 padx=(10, 5), pady=5)
        tk.Label(self.chapter_header, text="Chapters", font=("Segoe UI", 10, "bold"), fg=LightTheme.FG,
                 bg=LightTheme.HEADER_BG).pack(side=tk.LEFT, pady=5)
        self.chapter_count_label = tk.Label(self.chapter_header, text="(0)", font=("Segoe UI", 9), fg=LightTheme.FG_DIM,
                                            bg=LightTheme.HEADER_BG)
        self.chapter_count_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.chapter_list_frame = tk.Frame(self.left_panel, bg=LightTheme.BG_SECONDARY, height=180)
        self.chapter_list_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        self.chapter_list_frame.pack_propagate(False)

        chapter_columns = ('title', 'line')
        self.chapter_tree = ttk.Treeview(self.chapter_list_frame, columns=chapter_columns, show='headings',
                                         style="Treeview")
        self.chapter_tree.heading('title', text='Title')
        self.chapter_tree.heading('line', text='Line')
        self.chapter_tree.column('title', width=260, minwidth=150)
        self.chapter_tree.column('line', width=60, minwidth=40, anchor=tk.E)

        chapter_scroll = ttk.Scrollbar(self.chapter_list_frame, orient=tk.VERTICAL, command=self.chapter_tree.yview)
        self.chapter_tree.configure(yscrollcommand=chapter_scroll.set)
        self.chapter_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        chapter_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.chapter_tree.bind('<<TreeviewSelect>>', self._on_chapter_select)

        right_panel = tk.Frame(content, bg=LightTheme.BG_SECONDARY, bd=1, relief=tk.SOLID)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        doc_header = tk.Frame(right_panel, bg=LightTheme.HEADER_BG, height=35)
        doc_header.pack(fill=tk.X)
        doc_header.pack_propagate(False)
        tk.Label(doc_header, text="📄", font=("Segoe UI", 12), bg=LightTheme.HEADER_BG).pack(side=tk.LEFT, padx=(10, 5),
                                                                                            pady=5)
        self.doc_title_label = tk.Label(doc_header, text="No document selected", font=("Segoe UI", 10, "bold"),
                                        fg=LightTheme.FG, bg=LightTheme.HEADER_BG, anchor=tk.W)
        self.doc_title_label.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=5)
        self.doc_info_label = tk.Label(doc_header, text="", font=("Segoe UI", 9), fg=LightTheme.FG_DIM,
                                       bg=LightTheme.HEADER_BG)
        self.doc_info_label.pack(side=tk.RIGHT, padx=10, pady=5)

        text_frame = tk.Frame(right_panel, bg=LightTheme.BG_SECONDARY)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.text_widget = tk.Text(text_frame, wrap=tk.WORD, state=tk.DISABLED, font=("Consolas", 11),
                                   bg=LightTheme.TEXT_BG, fg=LightTheme.FG, relief=tk.SOLID, bd=1, padx=15, pady=10,
                                   selectbackground=LightTheme.SELECTION, highlightthickness=0)
        text_scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.text_widget.yview)
        self.text_widget.configure(yscrollcommand=text_scroll.set)
        self.text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        nav_frame = tk.Frame(right_panel, bg=LightTheme.BG_TERTIARY, height=45)
        nav_frame.pack(fill=tk.X)
        nav_frame.pack_propagate(False)

        nav_inner = tk.Frame(nav_frame, bg=LightTheme.BG_TERTIARY)
        nav_inner.pack(pady=8)

        btn_first = tk.Button(nav_inner, image=self.icons['nav_first'], bg=LightTheme.BG_SECONDARY, relief=tk.FLAT,
                              bd=1, width=28, height=24, cursor="hand2", command=self._first_page)
        btn_first.pack(side=tk.LEFT, padx=2)
        btn_prev = tk.Button(nav_inner, image=self.icons['nav_prev'], bg=LightTheme.BG_SECONDARY, relief=tk.FLAT, bd=1,
                             width=28, height=24, cursor="hand2", command=self._prev_page)
        btn_prev.pack(side=tk.LEFT, padx=2)

        self.page_label = tk.Label(nav_inner, text="Page 0 / 0", font=("Segoe UI", 10), fg=LightTheme.FG,
                                   bg=LightTheme.BG_TERTIARY, width=14)
        self.page_label.pack(side=tk.LEFT, padx=15)

        btn_next = tk.Button(nav_inner, image=self.icons['nav_next'], bg=LightTheme.BG_SECONDARY, relief=tk.FLAT, bd=1,
                             width=28, height=24, cursor="hand2", command=self._next_page)
        btn_next.pack(side=tk.LEFT, padx=2)
        btn_last = tk.Button(nav_inner, image=self.icons['nav_last'], bg=LightTheme.BG_SECONDARY, relief=tk.FLAT, bd=1,
                             width=28, height=24, cursor="hand2", command=self._last_page)
        btn_last.pack(side=tk.LEFT, padx=2)

        tk.Label(nav_inner, text="Go to:", font=("Segoe UI", 9), fg=LightTheme.FG_DIM, bg=LightTheme.BG_TERTIARY).pack(
            side=tk.LEFT, padx=(20, 5))
        self.page_entry = tk.Entry(nav_inner, width=5, font=("Segoe UI", 10), relief=tk.SOLID, bd=1, justify=tk.CENTER)
        self.page_entry.pack(side=tk.LEFT)
        self.page_entry.bind('<Return>', self._goto_page)
        btn_go = tk.Button(nav_inner, text="Go", font=("Segoe UI", 9), bg=LightTheme.ACCENT, fg="white", relief=tk.FLAT,
                           padx=10, pady=2, cursor="hand2", command=self._goto_page)
        btn_go.pack(side=tk.LEFT, padx=(5, 0))

        status_bar = tk.Frame(main_container, bg=LightTheme.HEADER_BG, height=28)
        status_bar.pack(fill=tk.X, padx=10, pady=(0, 10))
        status_bar.pack_propagate(False)

        self.status_label = tk.Label(status_bar, text="Ready", font=("Segoe UI", 9), fg=LightTheme.FG_DIM,
                                     bg=LightTheme.HEADER_BG, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, padx=10, fill=tk.Y)

        tk.Label(status_bar, text="eBook Converter v1.0", font=("Segoe UI", 9), fg=LightTheme.FG_DIM,
                 bg=LightTheme.HEADER_BG).pack(side=tk.RIGHT, padx=10)


    def _on_format_change(self, event=None):
        self.current_format = self.format_var.get()
        if hasattr(self, 'current_folder') and self.current_folder:
            self._refresh_folder()

    def _refresh_folder(self):
        if not hasattr(self, 'current_folder') or not self.current_folder:
            return

        folder = self.current_folder

        self.doc_data.clear()
        self.file_tree.delete(*self.file_tree.get_children())
        self.current_file = None
        self._clear_preview()
        self._remove_file_pagination()

        patterns = SUPPORTED_FORMATS.get(self.current_format, ['*.*'])
        all_files = []
        for p in patterns:
            all_files.extend(Path(folder).glob(p))
        all_files = list(set(all_files))
        all_files.sort(key=lambda x: x.name.lower())

        if not all_files:
            self.all_files = []
            self._update_summary()
            self.status_label.config(text=f"No {self.current_format} files found")
            return

        self.all_files = all_files
        self.file_page_start = 0

        if len(all_files) > self.page_size:
            self.lazy_loading = True
            self._add_file_pagination()
            self._load_file_page()
        else:
            self.lazy_loading = False
            self._load_all_files(all_files)

        self._update_summary()

    def _browse_folder(self):
        folder = filedialog.askdirectory(title="Select folder containing documents")
        if not folder:
            return
        self.current_folder = folder
        self.folder_label.config(text=folder)
        self.doc_data.clear()
        self.file_tree.delete(*self.file_tree.get_children())
        self.current_file = None
        self._clear_preview()
        self._remove_file_pagination()

        patterns = SUPPORTED_FORMATS.get(self.current_format, ['*.*'])
        all_files = []
        for p in patterns:
            all_files.extend(Path(folder).glob(p))
        all_files = list(set(all_files))
        all_files.sort(key=lambda x: x.name.lower())

        if not all_files:
            messagebox.showinfo("Info", f"No {self.current_format} files found")
            self._update_summary()
            return

        self.all_files = all_files
        self.file_page_start = 0

        if len(all_files) > self.page_size:
            self.lazy_loading = True
            self._add_file_pagination()
            self._load_file_page()
        else:
            self.lazy_loading = False
            self._load_all_files(all_files)

        self._update_summary()

    def _load_all_files(self, files):
        self.status_label.config(text=f"Loading {len(files)} files...")
        self.root.update()

        for i, file_path in enumerate(files):
            self._load_single_file(file_path)
            self.status_label.config(text=f"Loading... {i + 1}/{len(files)}")
            self.root.update()

        self.status_label.config(text=f"Loaded {len(self.doc_data)} files")

    def _load_next_batch(self):
        start = self.loaded_count
        end = min(start + self.page_size, len(self.all_files))

        if start >= len(self.all_files):
            return

        self.status_label.config(text=f"Loading files {start + 1} to {end}...")
        self.root.update()

        for i in range(start, end):
            file_path = self.all_files[i]
            self._load_single_file(file_path)
            self.status_label.config(text=f"Loading... {i + 1}/{len(self.all_files)}")
            self.root.update()

        self.loaded_count = end
        remaining = len(self.all_files) - self.loaded_count

        if remaining > 0:
            self.status_label.config(
                text=f"Loaded {self.loaded_count}/{len(self.all_files)} files. {remaining} remaining.")
        else:
            self.status_label.config(text=f"Loaded all {len(self.all_files)} files")
            self._remove_load_more_button()

        self._update_summary()

    def _load_single_file(self, file_path):
        parser = DocumentParser(str(file_path))
        try:
            result = parser.parse()
        except Exception as e:
            print(f"Parse error {file_path.name}: {e}")
            result = False

        if result:
            size = file_path.stat().st_size
            lines = parser.get_line_count()
            self.doc_data[str(file_path)] = {
                'parser': parser,
                'size': size,
                'lines': lines,
                'chapters': parser.get_chapters()
            }
            ext = file_path.suffix.lower()
            ext_display = ext.upper().replace('.', '')
            size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.1f} MB"
            name = file_path.stem
            if len(name) > 25:
                name = name[:22] + "..."
            item_id = self.file_tree.insert('', tk.END, iid=str(file_path),
                                            values=(name, ext_display, size_str, f"{lines:,}"))
            if ext in FILE_COLORS:
                self.file_tree.tag_configure(ext, foreground=FILE_COLORS[ext])
                self.file_tree.item(item_id, tags=(ext,))
        else:
            print(f"Skipped: {file_path.name}")

    def _add_file_pagination(self):
        if hasattr(self, 'file_nav_frame') and self.file_nav_frame:
            return

        self.file_nav_frame = tk.Frame(self.left_panel, bg=LightTheme.BG_TERTIARY, height=40)
        self.file_nav_frame.pack(fill=tk.X, padx=5, pady=5)
        self.file_nav_frame.pack_propagate(False)

        nav_inner = tk.Frame(self.file_nav_frame, bg=LightTheme.BG_TERTIARY)
        nav_inner.pack(pady=6)

        btn_first = tk.Button(nav_inner, image=self.icons['nav_first'], bg=LightTheme.BG_SECONDARY, relief=tk.FLAT,
                              bd=1, width=24, height=20, cursor="hand2", command=self._file_first_page)
        btn_first.pack(side=tk.LEFT, padx=2)
        btn_prev = tk.Button(nav_inner, image=self.icons['nav_prev'], bg=LightTheme.BG_SECONDARY, relief=tk.FLAT, bd=1,
                             width=24, height=20, cursor="hand2", command=self._file_prev_page)
        btn_prev.pack(side=tk.LEFT, padx=2)

        self.file_page_label = tk.Label(nav_inner, text="1 / 1", font=("Segoe UI", 9), fg=LightTheme.FG,
                                        bg=LightTheme.BG_TERTIARY, width=10)
        self.file_page_label.pack(side=tk.LEFT, padx=8)

        btn_next = tk.Button(nav_inner, image=self.icons['nav_next'], bg=LightTheme.BG_SECONDARY, relief=tk.FLAT, bd=1,
                             width=24, height=20, cursor="hand2", command=self._file_next_page)
        btn_next.pack(side=tk.LEFT, padx=2)
        btn_last = tk.Button(nav_inner, image=self.icons['nav_last'], bg=LightTheme.BG_SECONDARY, relief=tk.FLAT, bd=1,
                             width=24, height=20, cursor="hand2", command=self._file_last_page)
        btn_last.pack(side=tk.LEFT, padx=2)

        self._update_file_page_label()

    def _remove_file_pagination(self):
        if hasattr(self, 'file_nav_frame') and self.file_nav_frame:
            self.file_nav_frame.destroy()
            self.file_nav_frame = None

    def _get_total_file_pages(self):
        return (len(self.all_files) + self.page_size - 1) // self.page_size

    def _get_current_file_page(self):
        return self.loaded_count // self.page_size

    def _update_file_page_label(self):
        if hasattr(self, 'file_page_label') and self.file_page_label:
            current = (self.file_page_start // self.page_size) + 1
            total = self._get_total_file_pages()
            self.file_page_label.config(text=f"{current} / {total}")

    def _file_first_page(self):
        self.file_page_start = 0
        self._load_file_page()

    def _file_prev_page(self):
        if self.file_page_start >= self.page_size:
            self.file_page_start -= self.page_size
            self._load_file_page()

    def _file_next_page(self):
        if self.file_page_start + self.page_size < len(self.all_files):
            self.file_page_start += self.page_size
            self._load_file_page()

    def _file_last_page(self):
        total_pages = self._get_total_file_pages()
        self.file_page_start = (total_pages - 1) * self.page_size
        self._load_file_page()

    def _load_file_page(self):
        self.file_tree.delete(*self.file_tree.get_children())

        start = self.file_page_start
        end = min(start + self.page_size, len(self.all_files))

        self.status_label.config(text=f"Loading files {start + 1} to {end}...")
        self.root.update()

        for i in range(start, end):
            file_path = self.all_files[i]
            fp_str = str(file_path)

            if fp_str not in self.doc_data:
                parser = DocumentParser(fp_str)
                try:
                    result = parser.parse()
                except Exception as e:
                    print(f"Parse error {file_path.name}: {e}")
                    result = False

                if result:
                    size = file_path.stat().st_size
                    lines = parser.get_line_count()
                    self.doc_data[fp_str] = {
                        'parser': parser,
                        'size': size,
                        'lines': lines,
                        'chapters': parser.get_chapters()
                    }

            if fp_str in self.doc_data:
                data = self.doc_data[fp_str]
                size = data['size']
                lines = data['lines']
                ext = file_path.suffix.lower()
                ext_display = ext.upper().replace('.', '')
                size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.1f} MB"
                name = file_path.stem
                if len(name) > 25:
                    name = name[:22] + "..."
                item_id = self.file_tree.insert('', tk.END, iid=fp_str,
                                                values=(name, ext_display, size_str, f"{lines:,}"))
                if ext in FILE_COLORS:
                    self.file_tree.tag_configure(ext, foreground=FILE_COLORS[ext])
                    self.file_tree.item(item_id, tags=(ext,))

        self._update_file_page_label()
        self._update_summary()
        self.status_label.config(text=f"Showing files {start + 1} to {end} of {len(self.all_files)}")

    def _update_summary(self):
        count = len(self.doc_data)
        total_lines = sum(d['lines'] for d in self.doc_data.values())
        total_size = sum(d['size'] for d in self.doc_data.values())
        size_str = f"{total_size / 1024 / 1024:.1f} MB" if total_size > 1024 * 1024 else f"{total_size / 1024:.1f} KB"

        if self.lazy_loading and self.all_files:
            total = len(self.all_files)
            self.summary_label.config(text=f"{count}/{total} files | {total_lines:,} lines | {size_str}")
        else:
            self.summary_label.config(text=f"{count} files | {total_lines:,} lines | {size_str}")

    def _on_file_select(self, event):
        selection = self.file_tree.selection()
        if not selection:
            return
        filepath = selection[0]
        if filepath not in self.doc_data:
            return
        self.current_file = filepath
        self.current_page = 0
        self._update_chapters()
        self._update_preview()

    def _on_chapter_select(self, event):
        self.root.after(10, self._handle_chapter_select)

    def _handle_chapter_select(self):
        selection = self.chapter_tree.selection()
        if not selection:
            return
        if not self.current_file:
            return

        try:
            idx = int(selection[0])
        except ValueError:
            return

        data = self.doc_data.get(self.current_file)
        if not data:
            return

        chapters = data.get('chapters', [])
        if idx >= len(chapters):
            return

        line_num = chapters[idx]['line']
        new_page = line_num // self.lines_per_page

        if new_page != self.current_page:
            self.current_page = new_page
            self._update_preview()

        line_in_page = line_num % self.lines_per_page

        self.text_widget.tag_remove('chapter_highlight', '1.0', tk.END)
        self.text_widget.tag_configure('chapter_highlight', background='#BBF7D0', foreground='#166534')

        start_pos = f"{line_in_page + 1}.0"
        end_pos = f"{line_in_page + 1}.end"

        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.tag_add('chapter_highlight', start_pos, end_pos)
        self.text_widget.see(start_pos)
        self.text_widget.config(state=tk.DISABLED)


    def _update_chapters(self):
        # print("_update_chapters called")
        self.chapter_tree.delete(*self.chapter_tree.get_children())
        if not self.current_file:
            self.chapter_count_label.config(text="(0)")
            return
        data = self.doc_data[self.current_file]
        chapters = data.get('chapters', [])
        # print(f"Chapters to display: {len(chapters)}")
        for i, ch in enumerate(chapters):
            title = ch['title']
            line = ch['line']
            # print(f"  {i}: {title} @ line {line}")
            if len(title) > 40:
                title = title[:37] + "..."
            self.chapter_tree.insert('', tk.END, iid=str(i), values=(title, line + 1))
        self.chapter_count_label.config(text=f"({len(chapters)})")
        # print("_update_chapters done")





    def _update_preview(self):
        if not self.current_file:
            return
        self.text_widget.tag_remove('search_highlight', '1.0', tk.END)
        self.text_widget.tag_remove('chapter_highlight', '1.0', tk.END)
        data = self.doc_data[self.current_file]
        parser = data['parser']
        total_pages = parser.get_total_pages(self.lines_per_page)
        page_text = parser.get_page(self.current_page, self.lines_per_page)

        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.delete('1.0', tk.END)
        self.text_widget.insert('1.0', page_text)
        self.text_widget.config(state=tk.DISABLED)

        self.page_label.config(text=f"Page {self.current_page + 1} / {total_pages}")

        filename = os.path.basename(self.current_file)
        self.doc_title_label.config(text=filename)

        size = data['size']
        size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.1f} MB"
        chapters_count = len(data.get('chapters', []))
        self.doc_info_label.config(text=f"{data['lines']:,} lines | {size_str} | {chapters_count} chapters")

        self.status_label.config(text=f"Viewing: {filename}")


    def _clear_preview(self):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.delete('1.0', tk.END)
        self.text_widget.config(state=tk.DISABLED)
        self.page_label.config(text="Page 0 / 0")
        self.doc_title_label.config(text="No document selected")
        self.doc_info_label.config(text="")
        self.chapter_tree.delete(*self.chapter_tree.get_children())
        self.chapter_count_label.config(text="(0)")


    def _first_page(self):
        if not self.current_file:
            return
        self.current_page = 0
        self._update_preview()


    def _prev_page(self):
        if not self.current_file:
            return
        if self.current_page > 0:
            self.current_page -= 1
            self._update_preview()


    def _next_page(self):
        if not self.current_file:
            return
        parser = self.doc_data[self.current_file]['parser']
        total_pages = parser.get_total_pages(self.lines_per_page)
        if self.current_page < total_pages - 1:
            self.current_page += 1
            self._update_preview()


    def _last_page(self):
        if not self.current_file:
            return
        parser = self.doc_data[self.current_file]['parser']
        total_pages = parser.get_total_pages(self.lines_per_page)
        self.current_page = max(0, total_pages - 1)
        self._update_preview()


    def _goto_page(self, event=None):
        if not self.current_file:
            return
        try:
            page = int(self.page_entry.get()) - 1
        except ValueError:
            return
        parser = self.doc_data[self.current_file]['parser']
        total_pages = parser.get_total_pages(self.lines_per_page)
        if 0 <= page < total_pages:
            self.current_page = page
            self._update_preview()


    def _export_current(self):
        if not self.current_file:
            messagebox.showinfo("Info", "No file selected")
            return
        output_path = filedialog.asksaveasfilename(
            title="Save as Text",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=os.path.splitext(os.path.basename(self.current_file))[0] + ".txt"
        )
        if not output_path:
            return
        try:
            parser = self.doc_data[self.current_file]['parser']
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(parser.text)
            self.status_label.config(text=f"Exported: {os.path.basename(output_path)}")
            messagebox.showinfo("Success", f"Exported to {output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")


    def _show_export_dialog(self):
        if not self.doc_data:
            messagebox.showinfo("Info", "No files loaded")
            return
        file_data = {fp: {'size': d['size'], 'lines': d['lines']} for fp, d in self.doc_data.items()}
        dialog = ExportDialog(self.root, file_data, self.icons)
        self.root.wait_window(dialog)
        if dialog.result:
            self._export_files(dialog.result)

    def _show_search_dialog(self):
        if not self.doc_data:
            messagebox.showinfo("Info", "No files loaded")
            return
        SearchDialog(self.root, self.doc_data, self.current_file, self._on_search_result)

    def _on_search_result(self, filepath, line_num, query, case_sensitive, whole_word):
        if filepath != self.current_file:
            self.current_file = filepath
            for item in self.file_tree.get_children():
                if item == filepath:
                    self.file_tree.selection_set(item)
                    self.file_tree.see(item)
                    break
            self._update_chapters()

        self.current_page = line_num // self.lines_per_page
        self._update_preview()
        self._highlight_search(query, case_sensitive, whole_word)

    def _highlight_search(self, query, case_sensitive, whole_word):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.tag_remove('search_highlight', '1.0', tk.END)

        if not query:
            self.text_widget.config(state=tk.DISABLED)
            return

        self.text_widget.tag_configure('search_highlight', background='#FBBF24', foreground='#1E293B')

        content = self.text_widget.get('1.0', tk.END)

        if whole_word:
            if case_sensitive:
                pattern = re.compile(r'\b' + re.escape(query) + r'\b')
            else:
                pattern = re.compile(r'\b' + re.escape(query) + r'\b', re.IGNORECASE)

            for match in pattern.finditer(content):
                start_pos = f"1.0+{match.start()}c"
                end_pos = f"1.0+{match.end()}c"
                self.text_widget.tag_add('search_highlight', start_pos, end_pos)
        else:
            if case_sensitive:
                search_content = content
                search_query = query
            else:
                search_content = content.lower()
                search_query = query.lower()

            start_idx = 0
            while True:
                pos = search_content.find(search_query, start_idx)
                if pos == -1:
                    break
                start_pos = f"1.0+{pos}c"
                end_pos = f"1.0+{pos + len(query)}c"
                self.text_widget.tag_add('search_highlight', start_pos, end_pos)
                start_idx = pos + 1

        first = self.text_widget.tag_ranges('search_highlight')
        if first:
            self.text_widget.see(first[0])

        self.text_widget.config(state=tk.DISABLED)


    def _export_files(self, filepaths):
        output_dir = filedialog.askdirectory(title="Select output folder")
        if not output_dir:
            return
        exported = 0
        errors = []
        for i, fp in enumerate(filepaths):
            if fp not in self.doc_data:
                continue
            parser = self.doc_data[fp]['parser']
            base_name = os.path.splitext(os.path.basename(fp))[0]
            out_path = os.path.join(output_dir, f"{base_name}.txt")
            try:
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(parser.text)
                exported += 1
                self.status_label.config(text=f"Exporting... {i + 1}/{len(filepaths)}")
                self.root.update()
            except Exception as e:
                errors.append(f"{base_name}: {e}")

        msg = f"Exported {exported} file(s) to {output_dir}"
        if errors:
            msg += f"\n\nErrors:\n" + "\n".join(errors[:5])
        self.status_label.config(text=f"Export complete: {exported} files")
        messagebox.showinfo("Export Complete", msg)


if __name__ == "__main__":
    root = tk.Tk()
    app = DocumentConverterApp(root)
    root.mainloop()
