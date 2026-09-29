"""Copy the canonical fixtures in /conformance/fixtures into each SDK package, or --check for drift (CI)."""
import filecmp
import os
import shutil
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "conformance", "fixtures")
DESTS = [os.path.join(ROOT, "python", "abe", "conformance", "fixtures"),
         os.path.join(ROOT, "typescript", "fixtures")]


def files(base):
    out = []
    for d, _, fs in os.walk(base):
        out += [os.path.relpath(os.path.join(d, f), base) for f in fs]
    return sorted(out)


def main():
    check = "--check" in sys.argv
    bad = False
    for dest in DESTS:
        if check:
            if files(SRC) != files(dest) or any(not filecmp.cmp(os.path.join(SRC, f), os.path.join(dest, f), shallow=False)
                                                for f in files(SRC)):
                print(f"DRIFT: {os.path.relpath(dest, ROOT)} differs from conformance/fixtures")
                bad = True
        else:
            shutil.rmtree(dest, ignore_errors=True)
            shutil.copytree(SRC, dest)
            print(f"synced -> {os.path.relpath(dest, ROOT)}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
