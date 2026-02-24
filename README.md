
# eBook Extractor & Converter

A professional desktop application for extracting, viewing, and converting text from multiple eBook and document formats with advanced search and chapter navigation capabilities.

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-GPL--2.0-orange)

## Features

### Supported Formats

- **EPUB** (.epub) - Full support with chapter detection
- **MOBI/PRC** (.mobi, .prc) - Kindle format with PalmDOC decompression
- **DOCX** (.docx) - Microsoft Word documents
- **HTML** (.html, .htm) - Web pages and HTML documents
- **RTF** (.rtf) - Rich Text Format with advanced text extraction

### Core Functionality

- **Batch Processing**: Load entire folders of mixed document formats
- **Smart Pagination**: Browse long documents with 50 lines per page
- **Chapter Detection**: Automatic extraction of book chapters, parts, and sections
- **File Filtering**: Filter by format type (EPUB, DOCX, HTML, RTF, MOBI)
- **Lazy Loading**: Efficient handling of folders with 1000+ files (50 files per page)
- **Professional UI**: Modern, clean interface with custom icons and color-coded file types

### Advanced Search

- **Full-Text Search**: Search across current file or all loaded documents
- **Search Options**:
  - Case-sensitive matching
  - Whole word matching
  - Scope selection (current file or all files)
- **Live Results**: Interactive results tree with double-click navigation
- **Context Preview**: See matching lines with 80-character preview
- **Jump to Match**: Instantly navigate to search results with highlighting

### Chapter Navigation

- **Auto-Detection**: Recognizes multiple chapter patterns:
  - "Chapter 1", "Chapter One", "Chapter I"
  - "Part 1", "Part One", "Part I"
  - "Prologue", "Epilogue", "Afterword"
  - Numbered sections (1., I., etc.)
- **Chapter List**: Browse all detected chapters in sidebar
- **Quick Navigation**: Click any chapter to jump to that location
- **Visual Highlighting**: Selected chapters highlighted in green

### Export Features

- **Single File Export**: Save current document as plain text
- **Bulk Export**: Export multiple files with advanced filtering
- **Export Filters**:
  - File size range (KB)
  - Line count range
  - Filename pattern (regex)
  - Live preview of matching files
- **Batch Processing**: Export all matching files with progress tracking
- **Smart Naming**: Preserves original filenames with .txt extension

### Format-Specific Features

**EPUB**
- OPF manifest parsing
- Spine-based reading order
- Multi-file HTML extraction
- Metadata preservation

**MOBI/PRC**
- PDB record structure parsing
- PalmDOC decompression (Type 2)
- Automatic encoding detection (UTF-8/CP1252)
- HTML tag stripping

**DOCX**
- XML document parsing
- Heading style detection
- Paragraph extraction
- Typography preservation

**HTML**
- Tag stripping with whitespace normalization
- Style and script removal
- Entity decoding
- Chapter extraction from H1/H2 tags

**RTF**
- Advanced RTF control word parsing
- Unicode character support (\u control)
- Embedded object removal
- Font table and color table stripping
- Hex data filtering

## Installation

### Requirements

- Python 3.7 or higher
- tkinter (usually included with Python)
- PIL/Pillow (for icons)

### Dependencies
```bash
pip install Pillow
```

### Quick Start
```bash
# Clone the repository
git clone https://github.com/shuvrobasu/ebook_conver_extract.git

# Navigate to directory
cd ebook-extractor

# Install dependencies
pip install Pillow

# Run the application
python ebook_extractor.py
```

## Usage

### Loading Documents

**Open Folder**
```
Click "Open Folder" button or use toolbar
Select folder containing eBooks/documents
```

**Format Filter**
- Use the format dropdown to filter by type
- Options: All Supported, EPUB, DOCX, HTML, RTF, MOBI
- Click refresh icon to reload with new filter

**File Navigation** (for 50+ files)
- Use navigation arrows to browse file pages
- Shows 50 files per page for performance

### Reading Documents

**Select a File**
- Click any file in the left panel
- Document loads in main text area
- Chapters appear in bottom-left panel

**Navigate Pages**
- Use arrow buttons: ⏮ ◄ ► ⏭
- Or enter page number and click "Go"
- Shows 50 lines per page

**Jump to Chapter**
- Click any chapter in chapter list
- Automatically navigates to chapter location
- Chapter line highlighted in green

### Searching

**Open Search Dialog**
```
Click "Search" button in toolbar
```

**Search Options**
- **Scope**: Current file or All files
- **Case sensitive**: Match exact case
- **Whole word**: Match complete words only
- Enter search term and press Enter or click Search

**Navigate Results**
- Double-click any result to jump to location
- Or select result and click "Go to Selected"
- Search terms highlighted in yellow

### Exporting

**Export Current File**
```
Click "Export Selected" button
Choose save location
File saved as .txt
```

**Export Multiple Files**
```
Click "Export All..." button
Set filters:
  - File size: Min/Max in KB
  - Line count: Min/Max lines
  - Filename pattern: Regex (e.g., ".*novel.*")
Click "Apply Filter" to preview matches
Select "Export All Matching" or "Export Selected"
Choose output folder
```

## Chapter Detection Patterns

The application automatically detects chapters using these patterns:

### Standard Patterns
- `Chapter 1`, `Chapter 2`, etc.
- `Chapter One`, `Chapter Two`, etc.
- `Chapter I`, `Chapter II`, etc. (Roman numerals)
- `Ch. 1`, `Ch 1`

### Parts and Sections
- `Part 1`, `Part One`, `Part I`
- `Section 1`
- `Book 1`, `Book One`
- `Volume 1`

### Special Sections
- `Prologue`
- `Epilogue`
- `Afterword`
- `Conclusion`
- `Appendix`

### Numbered Formats
- `1. Title`
- `I. Title`

### False Positive Filtering

The application **excludes** common false positives:
- Author information
- Copyright pages
- Publisher information
- Table of contents
- Dedication/acknowledgments
- ISBN/edition info
- Contact information
- Foreword/Preface/Introduction

## File Type Color Coding

Files are color-coded in the file list:

| Format | Color | Hex |
|--------|-------|-----|
| EPUB | Purple | #8B5CF6 |
| DOCX | Blue | #3B82F6 |
| HTML/HTM | Orange | #F59E0B |
| RTF | Green | #10B981 |
| MOBI/PRC | Pink | #EC4899 |

## Performance

### Optimizations

- **Lazy Loading**: Loads files in batches of 50
- **Pagination**: Both file list and document viewer paginated
- **Efficient Parsing**: Format-specific optimized parsers
- **Memory Management**: Documents parsed on-demand
- **Responsive UI**: Non-blocking file loading with progress updates

### Tested Limits

- ✅ 1000+ files in single folder
- ✅ 10MB+ individual documents
- ✅ Books with 500+ chapters
- ✅ Full-text search across 100+ documents
- ✅ MOBI files with PalmDOC compression

## Technical Details

### Architecture
```
DocumentConverterApp (Main Class)
|
+-- UI Components
|   |
|   +-- Toolbar (Open, Filter, Export, Search)
|   +-- Left Panel
|   |   +-- File List (Treeview with pagination)
|   |   +-- Chapter List (Treeview)
|   |   +-- Summary Bar
|   |
|   +-- Right Panel
|       +-- Document Viewer (Text widget)
|       +-- Navigation Controls
|       +-- Page Entry
|
+-- Parsers (DocumentParser)
|   |
|   +-- EPUB Parser
|   |   +-- OPF manifest parsing
|   |   +-- Spine extraction
|   |   +-- Multi-file HTML assembly
|   |
|   +-- MOBI Parser
|   |   +-- PDB record parsing
|   |   +-- PalmDOC decompression
|   |   +-- Encoding detection
|   |
|   +-- DOCX Parser
|   |   +-- XML extraction
|   |   +-- Paragraph assembly
|   |   +-- Heading detection
|   |
|   +-- HTML Parser
|   |   +-- Tag stripping
|   |   +-- Entity decoding
|   |   +-- Chapter extraction
|   |
|   +-- RTF Parser
|       +-- Control word parsing
|       +-- Unicode handling
|       +-- Object filtering
|
+-- Dialog Windows
    |
    +-- ExportDialog
    |   +-- Filter controls
    |   +-- Preview list
    |   +-- Batch export
    |
    +-- SearchDialog
        +-- Query input
        +-- Options (case, whole word, scope)
        +-- Results tree
        +-- Navigation
```

### Code Structure

- **Main Application**: `DocumentConverterApp` - GUI and coordination
- **Document Parser**: `DocumentParser` - Format detection and parsing
- **Export Dialog**: `ExportDialog` - Batch export with filtering
- **Search Dialog**: `SearchDialog` - Full-text search interface
- **Icons**: `Icons` class - Custom icon generation using PIL
- **Theme**: `LightTheme` class - Color constants

### Key Technologies

- **GUI**: tkinter with ttk for modern widgets
- **Icons**: PIL/Pillow for custom icon generation
- **EPUB**: zipfile + XML parsing
- **MOBI**: Binary PDB parsing + PalmDOC decompression
- **DOCX**: zipfile + XML parsing
- **HTML**: Regex-based tag stripping
- **RTF**: Custom RTF control word parser

## Troubleshooting

### MOBI Files Won't Load

**Issue**: MOBI file fails to parse  
**Solution**: File may use DRM or compression type not supported. Try converting with Calibre first.

### Missing Chapters

**Issue**: Book chapters not detected  
**Solution**: Book may use non-standard chapter formatting. Chapters can still be browsed via pagination.

### Large File Slow to Load

**Issue**: Multi-MB EPUB file loads slowly  
**Solution**: Normal for large books. Wait for loading progress. Consider splitting large anthologies.

### Search Returns No Results

**Issue**: Search finds nothing despite text being visible  
**Solution**: Check case-sensitive and whole-word options. Try broader search terms.

### RTF Displays Garbled Text

**Issue**: RTF text appears corrupted  
**Solution**: File may contain embedded objects or use advanced RTF features. Try exporting from source application as plain RTF.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Enter` | Execute search / Go to page |
| `Double-Click` | Jump to search result / Select chapter |

## Known Limitations

- **DRM Protection**: Cannot read DRM-protected eBooks
- **MOBI Compression**: Only supports PalmDOC (Type 2) compression
- **RTF Images**: Embedded images are removed during extraction
- **PDF Files**: Not currently supported
- **AZW3 Format**: Not currently supported (use MOBI instead)

## Future Enhancements

Potential improvements for future versions:

- PDF support
- AZW3 format support
- Metadata editing
- Export to multiple formats (HTML, EPUB, Markdown)
- Custom chapter pattern configuration
- Bookmark system
- Dark theme
- Font size adjustment
- Export with formatting preservation

## Contributing

Contributions welcome! Areas for enhancement:

- Additional format support (PDF, AZW3, FB2)
- Improved chapter detection algorithms
- Metadata extraction and display
- Export format options
- Unit tests for parsers

## License

GNU General Public License v2.0 (GPL-2.0)

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

## Acknowledgments

- Built for processing eBook libraries and digital document collections
- PalmDOC decompression algorithm based on Kindle MOBI format specification
- Chapter detection patterns refined through testing with Project Gutenberg books

## Screenshots

*Coming soon*

## Contact

Issues and feature requests: [GitHub Issues](https://github.com/shuvrobasu/ebook_convert_extract/issues)

---

**Made with ❤️ for book lovers and digital library enthusiasts**
