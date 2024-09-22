# defender_signature_parser
Short Python script used for parsing Defender VDM signature files. Most of the research was performed by [commial](https://github.com/commial/experiments/tree/master/windows-defender/VDM) - all credits to the original authors.

The script was written in pure Python 3 and does not require additional modules, hence the lack of `requirements.txt`.

## Usage

```

python main.py -h

usage: parser.py [-h] [-f {hexdump,hex,string}] [-e] [-v] -o OUTPUT signature_filepath

Short Python script used for parsing Defender VDM signature files.

positional arguments:
  signature_filepath    Path to the VDM file (mpasbase.vdm or mpavbase.vdm) or decompressed/extracted VDM files (.extracted files)

options:
  -h, --help            show this help message and exit
  -f {hexdump,hex,string}, --format {hexdump,hex,string}
                        Output format of the signatures
  -e, --extract-to-disk
                        Write the extracted VDM file to disk
  -v, --verbose         Print the status of the script during execution
  -o OUTPUT, --output OUTPUT
                        Path to which the signatures will be written

```

### Example 1 - create a hexdump of mpasbase.vdm signatures (slow!)

This output is generally good enough for searching through the database, while maintaining readability.

```
python parser.py -o mpasbase_parsed.out /path/to/mpasbase.vdm

# or

python parser.py -f hexdump -o mpasbase_parsed.out /path/to/mpasbase.vdm
```

Sample output:

```
SIGNATURE_TYPE_FILEPATH(0x5f)
00000000: 1A 00 5C 6D 69 63 72 6F  73 6F 66 74 5C 69 6E 74  ..\microsoft\int
00000010: 65 72 6E 65 74 20 65 78  70 6C 6F 72 65 72 5C 71  ernet explorer\q
00000020: 75 69 63 6B 20 6C 61 75  6E 63 68 5C 61 63 74 69  uick launch\acti
00000030: 76 69 74 79 20 6D 6F 6E  69 74 6F 72 2E 6C 6E 6B  vity monitor.lnk
```

### Example 2 - print signatures from mpavbase.vdm as Python strings

This output can contain `\x`-prefixed characters, but it can be suitable for searching through the signatures using tools like `grep`.

```
python parser.py -f string -o mpavbase_parsed.out /path/to/mpavbase.vdm
```

Sample output:

```
SIGNATURE_TYPE_FILEPATH(0x5f)
\x1a\x00\\microsoft\\internet explorer\\quick launch\\activity monitor.lnk
```

### Example 3 - print signatures from mpasbase.vdm as hex strings

This output can be useful for automation scripts, e.g. when parsing Lua rules.

```
python parser.py -f hex -o mpasbase_parsed.out /path/to/mpasbase.vdm
```

Sample output:

```
SIGNATURE_TYPE_FILEPATH(0x5f)
1a005c6d6963726f736f66745c696e7465726e6574206578706c6f7265725c717569636b206c61756e63685c6163746976697479206d6f6e69746f722e6c6e6b
```

### Example 4 - store the extracted VDM file to the current directory for future use

```
python parser.py -v -e -o mpasbase_parsed.out /path/to/mpasbase.vdm

[*] Verifying that /path/to/mpasbase.vdm exists
[*] Checking existence of mpasbase_parsed.out
[*] Checking if /path/to/mpasbase is a PE file
[*] File is a PE file, decompressing
[*] VDM file extracted to mpasbase.vdm.extracted
```

### Example 5 - load the extracted VDM file instead of the original VDM

This feature is implemented somewhat naively - by checking the file header. A typical VDM file is a PE file (MZ) header, whereas extracted VDMs are just binary data extracted from the PE resources and decompressed (no file header).

```
python parser.py -o mpasbase_parsed.out /path/to/mpasbase.vdm.extracted

[*] Verifying that /path/to/mpasbase.vdm exists
[*] Checking existence of mpasbase_parsed.out
[*] Checking if /path/to/mpasbase is a PE file
[*] MZ header not found, defaulting to extracted VDM mode
```

## Notes

It's worth noting that the signature type enum used in this script has not been updated in quite a while. This is mostly due to the fact that Microsoft has removed the ability to download PDB files from their symbol servers a while back, rendering it impossible to know for certain what the enum name for certain values will be. Such instances have been marked as `"UNKNOWN_SIG_TYPE"` in the output.

