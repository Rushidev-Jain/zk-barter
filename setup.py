from pathlib import Path

import shutil
from setuptools import setup

ROOT = Path(__file__).resolve().parent

BIN_DIR = ROOT/"bin"

# Only move the files you marked as bin wali files
BIN_FILES = {"IGroth16Verifier.abi","IGroth16Verifier.bin","IGroth16Verifier.json","ZKCredentialEscrow.abi","ZKCredentialEscrow.bin","ZKCredentialEscrow.json","solc-output-compile-all.json" }

def organize_repo():
    BIN_DIR.mkdir(exist_ok=True)
    for item in ROOT.iterdir():
        if not item.is_file():
            continue
        if item.name not in BIN_FILES:
            continue

        destination = BIN_DIR / item.name
        if destination.exists():
            # Keep the first copy already in bin and remove the duplicate file
            item.unlink()
            continue

        shutil.move(str(item), str(destination))


organize_repo()

setup(name="zk-barter",   version="0.1.0",description="Repository setup helper for zk-barter artifacts",py_modules=[],include_package_data=True)
