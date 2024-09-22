import os
import sys
import argparse
import binascii
import zlib
import struct
from enum import Enum, auto
# from hexdump import hexdump

SIG_TYPES = {
    1: "SIGNATURE_TYPE_RESERVED",
    2: "SIGNATURE_TYPE_VOLATILE_THREAT_INFO",
    3: "SIGNATURE_TYPE_VOLATILE_THREAT_ID",
    17: "SIGNATURE_TYPE_CKOLDREC",
    32: "SIGNATURE_TYPE_KVIR32",
    33: "SIGNATURE_TYPE_POLYVIR32",
    39: "SIGNATURE_TYPE_NSCRIPT_NORMAL",
    40: "SIGNATURE_TYPE_NSCRIPT_SP",
    41: "SIGNATURE_TYPE_NSCRIPT_BRUTE",
    44: "SIGNATURE_TYPE_NSCRIPT_CURE",
    48: "SIGNATURE_TYPE_TITANFLT",
    61: "SIGNATURE_TYPE_PEFILE_CURE",
    62: "SIGNATURE_TYPE_MAC_CURE",
    64: "SIGNATURE_TYPE_SIGTREE",
    65: "SIGNATURE_TYPE_SIGTREE_EXT",
    66: "SIGNATURE_TYPE_MACRO_PCODE",
    67: "SIGNATURE_TYPE_MACRO_SOURCE",
    68: "SIGNATURE_TYPE_BOOT",
    73: "SIGNATURE_TYPE_CLEANSCRIPT",
    74: "SIGNATURE_TYPE_TARGET_SCRIPT",
    80: "SIGNATURE_TYPE_CKSIMPLEREC",
    81: "SIGNATURE_TYPE_PATTMATCH",
    83: "SIGNATURE_TYPE_RPFROUTINE",
    85: "SIGNATURE_TYPE_NID",
    86: "SIGNATURE_TYPE_GENSFX",
    87: "SIGNATURE_TYPE_UNPLIB",
    88: "SIGNATURE_TYPE_DEFAULTS",
    91: "SIGNATURE_TYPE_DBVAR",
    92: "SIGNATURE_TYPE_THREAT_BEGIN",
    93: "SIGNATURE_TYPE_THREAT_END",
    94: "SIGNATURE_TYPE_FILENAME",
    95: "SIGNATURE_TYPE_FILEPATH",
    96: "SIGNATURE_TYPE_FOLDERNAME",
    97: "SIGNATURE_TYPE_PEHSTR",
    98: "SIGNATURE_TYPE_LOCALHASH",
    99: "SIGNATURE_TYPE_REGKEY",
    100: "SIGNATURE_TYPE_HOSTSENTRY",
    103: "SIGNATURE_TYPE_STATIC",
    105: "SIGNATURE_TYPE_LATENT_THREAT",
    106: "SIGNATURE_TYPE_REMOVAL_POLICY",
    107: "SIGNATURE_TYPE_WVT_EXCEPTION",
    108: "SIGNATURE_TYPE_REVOKED_CERTIFICATE",
    112: "SIGNATURE_TYPE_TRUSTED_PUBLISHER",
    113: "SIGNATURE_TYPE_ASEP_FILEPATH",
    115: "SIGNATURE_TYPE_DELTA_BLOB",
    116: "SIGNATURE_TYPE_DELTA_BLOB_RECINFO",
    117: "SIGNATURE_TYPE_ASEP_FOLDERNAME",
    119: "SIGNATURE_TYPE_PATTMATCH_V2",
    120: "SIGNATURE_TYPE_PEHSTR_EXT",
    121: "SIGNATURE_TYPE_VDLL_X86",
    122: "SIGNATURE_TYPE_VERSIONCHECK",
    123: "SIGNATURE_TYPE_SAMPLE_REQUEST",
    124: "SIGNATURE_TYPE_VDLL_X64",
    126: "SIGNATURE_TYPE_SNID",
    127: "SIGNATURE_TYPE_FOP",
    128: "SIGNATURE_TYPE_KCRCE",
    131: "SIGNATURE_TYPE_VFILE",
    132: "SIGNATURE_TYPE_SIGFLAGS",
    133: "SIGNATURE_TYPE_PEHSTR_EXT2",
    134: "SIGNATURE_TYPE_PEMAIN_LOCATOR",
    135: "SIGNATURE_TYPE_PESTATIC",
    136: "SIGNATURE_TYPE_UFSP_DISABLE",
    137: "SIGNATURE_TYPE_FOPEX",
    138: "SIGNATURE_TYPE_PEPCODE",
    139: "SIGNATURE_TYPE_IL_PATTERN",
    140: "SIGNATURE_TYPE_ELFHSTR_EXT",
    141: "SIGNATURE_TYPE_MACHOHSTR_EXT",
    142: "SIGNATURE_TYPE_DOSHSTR_EXT",
    143: "SIGNATURE_TYPE_MACROHSTR_EXT",
    144: "SIGNATURE_TYPE_TARGET_SCRIPT_PCODE",
    145: "SIGNATURE_TYPE_VDLL_IA64",
    149: "SIGNATURE_TYPE_PEBMPAT",
    150: "SIGNATURE_TYPE_AAGGREGATOR",
    151: "SIGNATURE_TYPE_SAMPLE_REQUEST_BY_NAME",
    152: "SIGNATURE_TYPE_REMOVAL_POLICY_BY_NAME",
    153: "SIGNATURE_TYPE_TUNNEL_X86",
    154: "SIGNATURE_TYPE_TUNNEL_X64",
    155: "SIGNATURE_TYPE_TUNNEL_IA64",
    156: "SIGNATURE_TYPE_VDLL_ARM",
    157: "SIGNATURE_TYPE_THREAD_X86",
    158: "SIGNATURE_TYPE_THREAD_X64",
    159: "SIGNATURE_TYPE_THREAD_IA64",
    160: "SIGNATURE_TYPE_FRIENDLYFILE_SHA256",
    161: "SIGNATURE_TYPE_FRIENDLYFILE_SHA512",
    162: "SIGNATURE_TYPE_SHARED_THREAT",
    163: "SIGNATURE_TYPE_VDM_METADATA",
    164: "SIGNATURE_TYPE_VSTORE",
    165: "SIGNATURE_TYPE_VDLL_SYMINFO",
    166: "SIGNATURE_TYPE_IL2_PATTERN",
    167: "SIGNATURE_TYPE_BM_STATIC",
    168: "SIGNATURE_TYPE_BM_INFO",
    169: "SIGNATURE_TYPE_NDAT",
    170: "SIGNATURE_TYPE_FASTPATH_DATA",
    171: "SIGNATURE_TYPE_FASTPATH_SDN",
    172: "SIGNATURE_TYPE_DATABASE_CERT",
    173: "SIGNATURE_TYPE_SOURCE_INFO",
    174: "SIGNATURE_TYPE_HIDDEN_FILE",
    175: "SIGNATURE_TYPE_COMMON_CODE",
    176: "SIGNATURE_TYPE_VREG",
    177: "SIGNATURE_TYPE_NISBLOB",
    178: "SIGNATURE_TYPE_VFILEEX",
    179: "SIGNATURE_TYPE_SIGTREE_BM",
    180: "SIGNATURE_TYPE_VBFOP",
    181: "SIGNATURE_TYPE_VDLL_META",
    182: "SIGNATURE_TYPE_TUNNEL_ARM",
    183: "SIGNATURE_TYPE_THREAD_ARM",
    184: "SIGNATURE_TYPE_PCODEVALIDATOR",
    186: "SIGNATURE_TYPE_MSILFOP",
    187: "SIGNATURE_TYPE_KPAT",
    188: "SIGNATURE_TYPE_KPATEX",
    189: "SIGNATURE_TYPE_LUASTANDALONE",
    190: "SIGNATURE_TYPE_DEXHSTR_EXT",
    191: "SIGNATURE_TYPE_JAVAHSTR_EXT",
    192: "SIGNATURE_TYPE_MAGICCODE",
    193: "SIGNATURE_TYPE_CLEANSTORE_RULE",
    194: "SIGNATURE_TYPE_VDLL_CHECKSUM",
    195: "SIGNATURE_TYPE_THREAT_UPDATE_STATUS",
    196: "SIGNATURE_TYPE_VDLL_MSIL",
    197: "SIGNATURE_TYPE_ARHSTR_EXT",
    198: "SIGNATURE_TYPE_MSILFOPEX",
    199: "SIGNATURE_TYPE_VBFOPEX",
    200: "SIGNATURE_TYPE_FOP64",
    201: "SIGNATURE_TYPE_FOPEX64",
    202: "SIGNATURE_TYPE_JSINIT",
    203: "SIGNATURE_TYPE_PESTATICEX",
    204: "SIGNATURE_TYPE_KCRCEX",
    205: "SIGNATURE_TYPE_FTRIE_POS",
    206: "SIGNATURE_TYPE_NID64",
    207: "SIGNATURE_TYPE_MACRO_PCODE64",
    208: "SIGNATURE_TYPE_BRUTE",
    209: "SIGNATURE_TYPE_SWFHSTR_EXT",
    210: "SIGNATURE_TYPE_REWSIGS",
    211: "SIGNATURE_TYPE_AUTOITHSTR_EXT",
    212: "SIGNATURE_TYPE_INNOHSTR_EXT",
    213: "SIGNATURE_TYPE_ROOTCERTSTORE",
    214: "SIGNATURE_TYPE_EXPLICITRESOURCE",
    215: "SIGNATURE_TYPE_CMDHSTR_EXT",
    216: "SIGNATURE_TYPE_FASTPATH_TDN",
    217: "SIGNATURE_TYPE_EXPLICITRESOURCEHASH",
    218: "SIGNATURE_TYPE_FASTPATH_SDN_EX",
    219: "SIGNATURE_TYPE_BLOOM_FILTER",
    220: "SIGNATURE_TYPE_RESEARCH_TAG",
    222: "SIGNATURE_TYPE_ENVELOPE",
    223: "SIGNATURE_TYPE_REMOVAL_POLICY64",
    224: "SIGNATURE_TYPE_REMOVAL_POLICY64_BY_NAME",
    225: "SIGNATURE_TYPE_VDLL_META_X64",
    226: "SIGNATURE_TYPE_VDLL_META_ARM",
    227: "SIGNATURE_TYPE_VDLL_META_MSIL",
    228: "SIGNATURE_TYPE_MDBHSTR_EXT",
    229: "SIGNATURE_TYPE_SNIDEX",
    230: "SIGNATURE_TYPE_SNIDEX2",
    231: "SIGNATURE_TYPE_AAGGREGATOREX",
    232: "SIGNATURE_TYPE_PUA_APPMAP",
    233: "SIGNATURE_TYPE_PROPERTY_BAG",
    234: "SIGNATURE_TYPE_DMGHSTR_EXT",
    235: "SIGNATURE_TYPE_DATABASE_CATALOG",
}

SIG_TYPE_SIZE = 1
SIG_SIZE_LOW_SIZE = 1
SIG_SIZE_HIGH_SIZE = 2

global VERBOSE


class ScriptError(Enum):
    ERR_FILE_NOT_EXISTS = auto(),
    ERR_EXTRACT_VDM_FAILED = auto()


def print_if_printable(byte: bytes) -> str:
    c = chr(byte)
    return c if c.isprintable() else '.'


def hexdump(bstr: bytes) -> str:
    chunk_size = 16
    # 8 bytes = 16 digits, 7 spaces in between
    # chars_to_left_justify = chunk_size + (chunk_size // 2) - 1
    chars_to_left_justify = 16 + 7
    hexdumps = []

    for chunk in range(0, len(bstr), chunk_size):
        bin_data_left = bstr[chunk: chunk + chunk_size // 2]
        bin_data_right = bstr[chunk + chunk_size // 2: chunk + chunk_size]

        hex_string_left = binascii.hexlify(bin_data_left, sep=' ').decode(
            'utf-8').ljust(chars_to_left_justify, ' ').upper()
        hex_string_right = binascii.hexlify(bin_data_right, sep=' ').decode(
            'utf-8').ljust(chars_to_left_justify, ' ').upper()

        printable_string = ''.join(
            map(print_if_printable, bstr[chunk: chunk + chunk_size]))

        hexdumps.append(
            f"{chunk:08X}: {hex_string_left}  {hex_string_right}  {printable_string}")

    return '\n'.join(hexdumps)


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="parser.py",
        description="Short Python script used for parsing Defender VDM signature files."
    )

    # path to the VDM file containing signatures, positional
    parser.add_argument(
        "signature_filepath", help="Path to the VDM file (mpasbase.vdm or mpavbase.vdm) or decompressed/extracted VDM files (.extracted files)")

    # output format
    parser.add_argument("-f", "--format",
                        choices=["hexdump", "hex", "string"],
                        default="hexdump", required=False, help="Output format of the signatures")

    parser.add_argument("-e", "--extract-to-disk",
                        default=False, action="store_true", help="Write the extracted VDM file to disk")

    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print the status of the script during execution")

    # output file
    parser.add_argument("-o", "--output", required=True,
                        help="Path to which the signatures will be written")

    return parser.parse_args()


def perror(err: str) -> None:
    print(f"[!] {err}", file=sys.stderr)


def vprint(s: str) -> None:
    global VERBOSE
    if VERBOSE:
        print(f"[*] {s}")


def verify_filepath(filepath: str, create_if_not_exists: bool = False) -> None:
    if not os.path.exists(filepath):
        if create_if_not_exists:
            try:
                f = open(filepath, "w")
                f.close()
                print(f"[+] File '{filepath}' did not exist, created")
            except Exception as e:
                perror(f"File '{filepath}' could not be created.")
                perror(
                    f"Error: {type(e).__name__} at line {e.__traceback__.tb_lineno} of '{__file__}': {e}")
                sys.exit(ScriptError.ERR_FILE_NOT_EXISTS)
        else:
            perror(f"File '{filepath}' not found, exiting")
            sys.exit(ScriptError.ERR_FILE_NOT_EXISTS)


def ensure_file_is_pe(infile) -> bool:
    # verify we're at the start
    infile.seek(0)
    mz_header = infile.read(2)

    # reset the file pointer
    infile.seek(0)
    if mz_header != b"MZ":
        vprint("MZ header not found, defaulting to extracted VDM mode")
        return False
    return True


# original code: https://github.com/commial/experiments/tree/master/windows-defender/VDM#decompressing
def decompress_vdm(file_ptr, filename: str,  extract_to_disk: bool) -> bytes:
    data = file_ptr.read()
    # Look for the resource signature
    base = data.index(b"RMDX")
    # Extract relevant information
    offset, size = struct.unpack("II", data[base + 0x18: base + 0x20])
    # Decompress the data
    x = zlib.decompress(data[base + offset + 8:], -15)
    # Ensure correctness
    assert len(x) == size
    if extract_to_disk:
        # Dumps the output
        try:
            o = open(f"{filename}.extracted", "wb")
            o.write(x)
            o.close()
            vprint(f"VDM file extracted to '{filename}.extracted'")
        except Exception as e:
            perror("Extracted VDM file could not be written to disk")
            perror(
                f"Error: {type(e).__name__} at line {e.__traceback__.tb_lineno} of '{__file__}': {e}")
            sys.exit(ScriptError.ERR_EXTRACT_VDM_FAILED)
    return x

# https://gist.github.com/vladignatyev/06860ec2040cb497f0f3


def progress(count: int, total: int, status: str = '') -> None:
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '#' * filled_len + ' ' * (bar_len - filled_len)

    sys.stdout.write('Data analyzed: [%s] %s%s ...%s\r' % (
        bar, percents, '%', status))
    sys.stdout.flush()


def main():
    namespace = parse_arguments()

    output_format = namespace.format
    output_file = namespace.output
    extract_to_disk = namespace.extract_to_disk
    input_file = namespace.signature_filepath

    global VERBOSE
    VERBOSE = namespace.verbose

    vprint(f"Verifying that '{input_file}' exists")
    verify_filepath(input_file)
    vprint(f"Checking existence of '{output_file}'")
    verify_filepath(output_file, create_if_not_exists=True)

    with open(input_file, "rb") as infile, open(output_file, "w") as outfile:
        vprint(f"Checking if '{input_file}' is a PE file")
        is_file_pe = ensure_file_is_pe(infile)

        if is_file_pe:
            vprint("File is a PE file, decompressing")
            vdm_data = decompress_vdm(
                infile, input_file, extract_to_disk=extract_to_disk)
        else:
            if extract_to_disk:
                vprint("Extracted VDM file being used, ignoring '-e'")
            # assume we're reading a decompressed signature file
            vdm_data = infile.read()

        index = 0
        sig_count = 0
        while index < len(vdm_data):
            if sig_count >> 14 << 14 == sig_count:    # every 2**14 sigs, avoiding modulus
                progress(index, len(vdm_data))

            # https://github.com/commial/experiments/tree/master/windows-defender/VDM#signature-format
            sig_type = int.from_bytes(
                vdm_data[index: index + SIG_TYPE_SIZE],
                byteorder='little',
                signed=False
            )

            # move the index to simulate moving the file pointer
            index += SIG_TYPE_SIZE

            sig_size_low = int.from_bytes(
                vdm_data[index: index + SIG_SIZE_LOW_SIZE],
                byteorder='little',
                signed=False
            )

            index += SIG_SIZE_LOW_SIZE

            sig_size_high = int.from_bytes(
                vdm_data[index: index + SIG_SIZE_HIGH_SIZE],
                byteorder='little',
                signed=False
            )

            index += SIG_SIZE_HIGH_SIZE

            signature_size = sig_size_low | sig_size_high << 8
            signature = vdm_data[index: index + signature_size]

            # move on to the next signature
            index += signature_size

            try:
                outfile.write(f"{SIG_TYPES[sig_type]}({hex(sig_type)})\n")
            except KeyError:
                perror(
                    f"Signature type {sig_type} not found in known database, replacing with 'UNKNOWN_SIG_TYPE'")
                outfile.write(f"UNKNOWN_SIG_TYPE({hex(sig_type)})\n")

            if output_format == "hex":
                outfile.write(
                    f"{binascii.hexlify(signature).decode('utf-8')}\n\n")
            elif output_format == "string":
                # remove the b'' wrapper
                outfile.write(f"{str(signature)[2:-1]}\n\n")
            else:  # default
                outfile.write(f"{hexdump(signature)}\n\n")

            sig_count += 1


if __name__ == "__main__":
    main()
