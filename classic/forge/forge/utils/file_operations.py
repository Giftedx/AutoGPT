import json
import logging
import zipfile # Added for DOCX parsing errors
from abc import ABC, abstractmethod
from typing import BinaryIO
from xml.etree.ElementTree import ParseError as StdlibParseError

import charset_normalizer
from charset_normalizer.errors import CharsetNormalizerError # For TXTParser
import docx
import pypdf
import yaml
from bs4 import BeautifulSoup
from pylatexenc.latex2text import LatexNodes2Text
from pylatexenc.latexwalker import LatexWalkerParseError # For LaTeXParser

try:
    from lxml.etree import XMLSyntaxError as LxmlXMLSyntaxError
except ImportError:
    LxmlXMLSyntaxError = None  # lxml not available

logger = logging.getLogger(__name__)


class CustomFileParsingError(Exception):
    """Base class for custom file parsing errors."""
    pass


class CustomPdfParsingError(CustomFileParsingError):
    """Raised when there's an error parsing a PDF file."""
    pass


class CustomDocxParsingError(CustomFileParsingError):
    """Raised when there's an error parsing a DOCX file."""
    pass


class CustomYamlParsingError(CustomFileParsingError):
    """Raised when there's an error parsing a YAML file."""
    pass


class CustomXmlParsingError(CustomFileParsingError):
    """Raised when there's an error parsing an XML file."""
    pass


class CustomLatexParsingError(CustomFileParsingError):
    """Raised when there's an error parsing a LaTeX file's structure."""
    pass


class CustomTextDecodingError(CustomFileParsingError):
    """Raised when there's an error decoding text from a file (e.g., encoding issues)."""
    pass


class ParserStrategy(ABC):
    @abstractmethod
    def read(self, file: BinaryIO) -> str:
        ...


# Basic text file reading
class TXTParser(ParserStrategy):
    def read(self, file: BinaryIO) -> str:
        filename = getattr(file, 'name', 'file')
        try:
            file_bytes = file.read()
            charset_match_obj = charset_normalizer.from_bytes(file_bytes)
            charset_match = charset_match_obj.best()

            logger.debug(
                f"Reading {filename} "
                f"with encoding '{charset_match.encoding if charset_match else None}'"
            )
            return str(charset_match) # This will be "None" if no match
        except CharsetNormalizerError as e:
            raise CustomTextDecodingError(f"Charset normalization error for '{filename}': {e}") from e
        except Exception as e: # Catch any other truly unexpected error
            raise CustomTextDecodingError(f"Unexpected error reading text file '{filename}': {e}") from e


# Reading text from binary file using pdf parser
class PDFParser(ParserStrategy):
    def read(self, file: BinaryIO) -> str:
        filename = getattr(file, 'name', 'file') # Get filename for error context
        try:
            parser = pypdf.PdfReader(file)
            text_parts = [] # More efficient to join later
            for page_idx in range(len(parser.pages)):
                text_parts.append(parser.pages[page_idx].extract_text())
            return "".join(text_parts)
        except pypdf.errors.PdfReadError as e:
            raise CustomPdfParsingError(f"Error reading PDF file '{filename}': {e}") from e
        except pypdf.errors.DependencyError as e: # Catching another specific pypdf error
            raise CustomPdfParsingError(f"PDF parsing dependency error for '{filename}': {e}") from e


# Reading text from binary file using docs parser
class DOCXParser(ParserStrategy):
    def read(self, file: BinaryIO) -> str:
        filename = getattr(file, 'name', 'file') # Get filename for error context
        try:
            doc_file = docx.Document(file)
            text_parts = []
            for para in doc_file.paragraphs:
                text_parts.append(para.text)
            return "".join(text_parts)
        except docx.opc.exceptions.PackageNotFoundError as e:
            raise CustomDocxParsingError(f"Error parsing DOCX file '{filename}' (not a valid package): {e}") from e
        except zipfile.BadZipFile as e: # DOCX files are zip files
            raise CustomDocxParsingError(f"Error parsing DOCX file '{filename}' (invalid ZIP format): {e}") from e


# Reading as dictionary and returning string format
class JSONParser(ParserStrategy):
    def read(self, file: BinaryIO) -> str:
        data = json.load(file)
        text = str(data)
        return text


class XMLParser(ParserStrategy):
    def read(self, file: BinaryIO) -> str:
        filename = getattr(file, 'name', 'file')
        try:
            # Ensure 'xml' features are used by BeautifulSoup for XML parsing.
            # Using 'lxml-xml' or 'xml' as the parser feature.
            # If lxml is installed, BeautifulSoup might use it by default for .xml,
            # otherwise it falls back to Python's built-in XML parser.
            # Specifying "xml" ensures it uses Python's built-in parser if lxml isn't chosen by BS.
            soup = BeautifulSoup(file, "xml")
            text = soup.get_text()
            return text
        except StdlibParseError as e: # Python's built-in XML parser error
            raise CustomXmlParsingError(f"Error parsing XML (stdlib): {filename} - {e}") from e
        except Exception as e: # Catch other potential errors
            if LxmlXMLSyntaxError and isinstance(e, LxmlXMLSyntaxError): # Check for lxml error
                raise CustomXmlParsingError(f"Error parsing XML (lxml): {filename} - {e}") from e
            # If it's not an Lxml error (or lxml not installed) and not StdlibParseError,
            # it's an unexpected error during parsing. Wrap it.
            raise CustomXmlParsingError(f"Unexpected error parsing XML: {filename} - {e}") from e


# Reading as dictionary and returning string format
class YAMLParser(ParserStrategy):
    def read(self, file: BinaryIO) -> str:
        filename = getattr(file, 'name', 'file') # Get filename for error context
        try:
            data = yaml.load(file, Loader=yaml.SafeLoader)
            text = str(data) # Convert loaded YAML data to string
            return text
        except yaml.YAMLError as e:
            raise CustomYamlParsingError(f"Error parsing YAML file '{filename}': {e}") from e


class HTMLParser(ParserStrategy):
    def read(self, file: BinaryIO) -> str:
        soup = BeautifulSoup(file, "html.parser")
        text = soup.get_text()
        return text


class LaTeXParser(ParserStrategy):
    def read(self, file: BinaryIO) -> str:
        filename = getattr(file, 'name', 'file') # Get filename for error context
        try:
            # First, try to decode the byte stream to a string
            try:
                latex_content = file.read().decode() # Default is UTF-8
            except UnicodeDecodeError as e:
                raise CustomTextDecodingError(f"Error decoding LaTeX file '{filename}' as UTF-8: {e}") from e

            # Then, try to parse the LaTeX content
            text = LatexNodes2Text().latex_to_text(latex_content)
            return text
        
        except LatexWalkerParseError as e: # Catch pylatexenc's parsing error
            raise CustomLatexParsingError(f"Error parsing LaTeX structure in file '{filename}': {e}") from e


class FileContext:
    def __init__(self, parser: ParserStrategy, logger: logging.Logger):
        self.parser = parser
        self.logger = logger

    def set_parser(self, parser: ParserStrategy) -> None:
        self.logger.debug(f"Setting Context Parser to {parser}")
        self.parser = parser

    def decode_file(self, file: BinaryIO) -> str:
        self.logger.debug(
            f"Reading {getattr(file, 'name', 'file')} with parser {self.parser}"
        )
        return self.parser.read(file)


extension_to_parser = {
    ".txt": TXTParser(),
    ".md": TXTParser(),
    ".markdown": TXTParser(),
    ".csv": TXTParser(),
    ".pdf": PDFParser(),
    ".docx": DOCXParser(),
    ".json": JSONParser(),
    ".xml": XMLParser(),
    ".yaml": YAMLParser(),
    ".yml": YAMLParser(),
    ".html": HTMLParser(),
    ".htm": HTMLParser(),
    ".xhtml": HTMLParser(),
    ".tex": LaTeXParser(),
}


def is_file_binary_fn(file: BinaryIO) -> bool:
    """
    Checks if the beginning of a file stream appears to be binary by looking for null bytes.
    Reads only an initial chunk of the file for efficiency.

    Args:
        file (BinaryIO): The binary file stream to check.

    Returns:
        bool: True if a null byte is found in the initial chunk, False otherwise.
    """
    CHUNK_SIZE = 4096  # Read an initial chunk to check for binary content
    original_position = file.tell()
    try:
        # Read a chunk of the file. This is a heuristic, as checking the entire
        # file can be slow for large files.
        chunk = file.read(CHUNK_SIZE)
    finally:
        # Ensure the file pointer is reset to its original position,
        # so subsequent operations on the same file stream are not affected.
        file.seek(original_position)

    if b"\x00" in chunk:
        return True
    return False


def decode_textual_file(file: BinaryIO, ext: str, logger: logging.Logger) -> str:
    if not file.readable():
        raise ValueError(f"{repr(file)} is not readable")

    parser = extension_to_parser.get(ext.lower())
    if not parser:
        if is_file_binary_fn(file):
            raise ValueError(f"Unsupported binary file format: {ext}")
        # fallback to txt file parser (to support script and code files loading)
        parser = TXTParser()
    file_context = FileContext(parser, logger)
    return file_context.decode_file(file)
