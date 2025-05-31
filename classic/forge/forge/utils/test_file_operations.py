import io
import json
import logging
import os.path
import tempfile
from pathlib import Path
from xml.etree import ElementTree

import docx
import pytest
import yaml
from bs4 import BeautifulSoup

import zipfile # For checking __cause__ in DOCX test
from docx.opc.exceptions import PackageNotFoundError # For checking __cause__ in DOCX test
from xml.etree.ElementTree import ParseError as StdlibParseError # For XML test

try:
    from lxml.etree import XMLSyntaxError as LxmlXMLSyntaxError # For XML test
except ImportError:
    LxmlXMLSyntaxError = None

from pylatexenc.latexwalker import LatexWalkerParseError # For LaTeX tests
from charset_normalizer.errors import CharsetNormalizerError # For TXTParser test
from unittest.mock import patch # For TXTParser test

from .file_operations import (
    CustomDocxParsingError,
    CustomPdfParsingError,
    CustomYamlParsingError,
    CustomXmlParsingError,
    CustomLatexParsingError, # Import for LaTeX tests
    CustomTextDecodingError, # Import for LaTeX tests
    decode_textual_file,
    is_file_binary_fn,
)

logger = logging.getLogger(__name__)

plain_text_str = "Hello, world!"


def mock_text_file():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write(plain_text_str)
    return f.name


def mock_csv_file():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
        f.write(plain_text_str)
    return f.name


def mock_pdf_file():
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pdf") as f:
        # Create a new PDF and add a page with the text plain_text_str
        # Write the PDF header
        f.write(b"%PDF-1.7\n")
        # Write the document catalog
        f.write(b"1 0 obj\n")
        f.write(b"<< /Type /Catalog /Pages 2 0 R >>\n")
        f.write(b"endobj\n")
        # Write the page object
        f.write(b"2 0 obj\n")
        f.write(
            b"<< /Type /Page /Parent 1 0 R /Resources << /Font << /F1 3 0 R >> >> "
            b"/MediaBox [0 0 612 792] /Contents 4 0 R >>\n"
        )
        f.write(b"endobj\n")
        # Write the font object
        f.write(b"3 0 obj\n")
        f.write(
            b"<< /Type /Font /Subtype /Type1 /Name /F1 /BaseFont /Helvetica-Bold >>\n"
        )
        f.write(b"endobj\n")
        # Write the page contents object
        f.write(b"4 0 obj\n")
        f.write(b"<< /Length 25 >>\n")
        f.write(b"stream\n")
        f.write(b"BT\n/F1 12 Tf\n72 720 Td\n(Hello, world!) Tj\nET\n")
        f.write(b"endstream\n")
        f.write(b"endobj\n")
        # Write the cross-reference table
        f.write(b"xref\n")
        f.write(b"0 5\n")
        f.write(b"0000000000 65535 f \n")
        f.write(b"0000000017 00000 n \n")
        f.write(b"0000000073 00000 n \n")
        f.write(b"0000000123 00000 n \n")
        f.write(b"0000000271 00000 n \n")
        f.write(b"trailer\n")
        f.write(b"<< /Size 5 /Root 1 0 R >>\n")
        f.write(b"startxref\n")
        f.write(b"380\n")
        f.write(b"%%EOF\n")
        f.write(b"\x00")
    return f.name


def mock_docx_file():
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".docx") as f:
        document = docx.Document()
        document.add_paragraph(plain_text_str)
        document.save(f.name)
    return f.name


def mock_json_file():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump({"text": plain_text_str}, f)
    return f.name


def mock_xml_file():
    root = ElementTree.Element("text")
    root.text = plain_text_str
    tree = ElementTree.ElementTree(root)
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".xml") as f:
        tree.write(f)
    return f.name


def mock_yaml_file():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as f:
        yaml.dump({"text": plain_text_str}, f)
    return f.name


def mock_html_file():
    html = BeautifulSoup(
        "<html>"
        "<head><title>This is a test</title></head>"
        f"<body><p>{plain_text_str}</p></body>"
        "</html>",
        "html.parser",
    )
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".html") as f:
        f.write(str(html))
    return f.name


def mock_md_file():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".md") as f:
        f.write(f"# {plain_text_str}!\n")
    return f.name


def mock_latex_file():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".tex") as f:
        latex_str = (
            r"\documentclass{article}"
            r"\begin{document}"
            f"{plain_text_str}"
            r"\end{document}"
        )
        f.write(latex_str)
    return f.name


respective_file_creation_functions = {
    ".txt": mock_text_file,
    ".csv": mock_csv_file,
    ".pdf": mock_pdf_file,
    ".docx": mock_docx_file,
    ".json": mock_json_file,
    ".xml": mock_xml_file,
    ".yaml": mock_yaml_file,
    ".html": mock_html_file,
    ".md": mock_md_file,
    ".tex": mock_latex_file,
}
binary_files_extensions = [".pdf", ".docx"]


@pytest.mark.parametrize(
    "file_extension, c_file_creator",
    respective_file_creation_functions.items(),
)
def test_parsers(file_extension, c_file_creator):
    created_file_path = Path(c_file_creator())
    with open(created_file_path, "rb") as file:
        loaded_text = decode_textual_file(file, os.path.splitext(file.name)[1], logger)

        assert plain_text_str in loaded_text

        should_be_binary = file_extension in binary_files_extensions
        assert should_be_binary == is_file_binary_fn(file)

    created_file_path.unlink()  # cleanup


CHUNK_SIZE = 4096


def test_is_file_binary_fn_null_byte_within_chunk():
    """Test with a null byte within the first CHUNK_SIZE bytes."""
    content = b"abc\x00def"
    file = io.BytesIO(content)
    initial_pos = file.tell()
    assert is_file_binary_fn(file) is True
    assert file.tell() == initial_pos


def test_is_file_binary_fn_null_byte_outside_chunk():
    """Test with a null byte outside the first CHUNK_SIZE bytes."""
    content = b"a" * (CHUNK_SIZE + 10) + b"\x00" + b"b" * 10
    file = io.BytesIO(content)
    initial_pos = file.tell()
    assert is_file_binary_fn(file) is False
    assert file.tell() == initial_pos


def test_is_file_binary_fn_no_null_byte():
    """Test with no null bytes, content shorter than CHUNK_SIZE."""
    content = b"abcdef" * 100  # Ensure it's substantial but < CHUNK_SIZE
    file = io.BytesIO(content)
    initial_pos = file.tell()
    assert is_file_binary_fn(file) is False
    assert file.tell() == initial_pos


def test_is_file_binary_fn_empty_file():
    """Test with an empty file."""
    content = b""
    file = io.BytesIO(content)
    initial_pos = file.tell()
    assert is_file_binary_fn(file) is False
    assert file.tell() == initial_pos


def test_is_file_binary_fn_pointer_reset_with_initial_offset():
    """Test that the file pointer resets correctly when the initial position is not 0."""
    content = b"aaaaa\x00bbbb"  # Null byte at index 5
    file = io.BytesIO(content)
    initial_pos = 5
    file.seek(initial_pos)
    assert is_file_binary_fn(file) is True
    assert file.tell() == initial_pos


def test_pdf_parser_malformed_file():
    """Tests that PDFParser raises CustomPdfParsingError for a malformed PDF."""
    malformed_content = b"This is definitely not a PDF file. %PDF-fake"
    # Using BytesIO to simulate a file stream
    pdf_stream = io.BytesIO(malformed_content)
    pdf_stream.name = "not_a_real.pdf"  # Provide a name for error message context

    with pytest.raises(CustomPdfParsingError) as excinfo:
        decode_textual_file(pdf_stream, ".pdf", logger)

    # Optionally, check the error message for specifics
    assert "Error reading PDF file 'not_a_real.pdf'" in str(excinfo.value)
    # And check that the cause is PdfReadError from pypdf
    # (Assuming pypdf.errors.PdfReadError is the expected underlying error)
    # This requires pypdf to be imported or its error type.
    # from pypdf.errors import PdfReadError # Would be needed if checking cause type directly
    # For now, checking the message is a good start.
    # If pypdf is imported in file_operations, we can be more specific.
    # Let's assume pypdf.errors.PdfReadError is the cause, which is typical.
    import pypdf # Import for type checking the cause

    assert isinstance(excinfo.value.__cause__, pypdf.errors.PdfReadError)


def test_docx_parser_malformed_file():
    """Tests that DOCXParser raises CustomDocxParsingError for a malformed DOCX."""
    malformed_content = b"This is definitely not a DOCX file."
    # Using BytesIO to simulate a file stream
    docx_stream = io.BytesIO(malformed_content)
    docx_stream.name = "not_a_real.docx"  # Provide a name for error message context

    with pytest.raises(CustomDocxParsingError) as excinfo:
        decode_textual_file(docx_stream, ".docx", logger)

    # Optionally, check the error message for specifics
    assert "Error parsing DOCX file 'not_a_real.docx'" in str(excinfo.value)
    # Check that the cause is one of the expected underlying errors
    assert isinstance(excinfo.value.__cause__, (PackageNotFoundError, zipfile.BadZipFile))


def test_yaml_parser_malformed_file():
    """Tests that YAMLParser raises CustomYamlParsingError for a malformed YAML."""
    # Using an unclosed quote and inconsistent indentation to create invalid YAML
    malformed_content = b"key: 'value\n  sub_key: [unclosed_list\n an_indented_key_without_proper_parent: true"
    yaml_stream = io.BytesIO(malformed_content)
    yaml_stream.name = "malformed.yaml"

    with pytest.raises(CustomYamlParsingError) as excinfo:
        decode_textual_file(yaml_stream, ".yaml", logger)

    assert "Error parsing YAML file 'malformed.yaml'" in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, yaml.YAMLError)


def test_xml_parser_malformed_file():
    """Tests that XMLParser raises CustomXmlParsingError for a malformed XML."""
    malformed_content = b"<root><unclosed_tag></root>" # Invalid XML
    xml_stream = io.BytesIO(malformed_content)
    xml_stream.name = "not_a_real.xml"

    with pytest.raises(CustomXmlParsingError) as excinfo:
        decode_textual_file(xml_stream, ".xml", logger)

    cause = excinfo.value.__cause__
    possible_causes = [StdlibParseError]
    if LxmlXMLSyntaxError: # If lxml was imported
        possible_causes.append(LxmlXMLSyntaxError)
    assert isinstance(cause, tuple(possible_causes))
    assert "Error parsing XML" in str(excinfo.value) # Check part of the message
    assert "not_a_real.xml" in str(excinfo.value)


def test_latex_parser_unicode_decode_error():
    """Tests that LaTeXParser raises CustomTextDecodingError for invalid UTF-8 bytes."""
    # These bytes are invalid UTF-8 (specifically, an orphaned continuation byte)
    malformed_content = b"\x80" 
    latex_stream = io.BytesIO(malformed_content)
    latex_stream.name = "invalid_encoding.tex"

    with pytest.raises(CustomTextDecodingError) as excinfo:
        decode_textual_file(latex_stream, ".tex", logger)

    assert "Error decoding LaTeX file 'invalid_encoding.tex' as UTF-8" in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, UnicodeDecodeError)


def test_latex_parser_malformed_structure():
    """Tests that LaTeXParser raises CustomLatexParsingError for malformed LaTeX structure."""
    # Malformed LaTeX: an unclosed command or environment
    malformed_content = br"\documentclass{article}\begin{document}\mycommand{" 
    latex_stream = io.BytesIO(malformed_content)
    latex_stream.name = "malformed_structure.tex"

    with pytest.raises(CustomLatexParsingError) as excinfo:
        decode_textual_file(latex_stream, ".tex", logger)

    assert "Error parsing LaTeX structure in file 'malformed_structure.tex'" in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, LatexWalkerParseError)


def test_txt_parser_charset_normalizer_error():
    """Tests TXTParser error handling when charset_normalizer.from_bytes fails."""
    txt_stream = io.BytesIO(b"some text data")
    txt_stream.name = "charset_error_test.txt"
    
    mock_error_message = "simulated charset_normalizer failure"

    # Patch where charset_normalizer.from_bytes is used in file_operations.py
    with patch('classic.forge.forge.utils.file_operations.charset_normalizer.from_bytes') as mock_from_bytes:
        mock_from_bytes.side_effect = CharsetNormalizerError(mock_error_message)

        with pytest.raises(CustomTextDecodingError) as excinfo:
            decode_textual_file(txt_stream, ".txt", logger)

    assert isinstance(excinfo.value.__cause__, CharsetNormalizerError)
    assert "Charset normalization error for 'charset_error_test.txt'" in str(excinfo.value)
    assert mock_error_message in str(excinfo.value)
