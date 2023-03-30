import pefile
import argparse

parser = argparse.ArgumentParser(description='Target DLL.')
parser.add_argument('--target', required=True, type=str,help='Target DLL')

args = parser.parse_args()

target = args.target

dll = pefile.PE(target)

print("EXPORTS")

for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
    if export.name:
        print(f"    {export.name.decode()}=original.{export.name.decode()} @{export.ordinal}")