r"""
Advanced Encryption Tool — Production Build Script

Programmatically invokes PyInstaller to compile the application into a
single standalone native executable. Handles pre-build cleanup, validates
the entry point exists, and surfaces PyInstaller errors with a non-zero
exit code so CI/CD pipelines can detect build failures.

Usage:
    .\.venv\Scripts\python build.py        # Windows
    .venv/bin/python build.py             # macOS / Linux

Requirements:
    pip install pyinstaller
"""

import os
import sys
import shutil
import subprocess


def run_production_build() -> None:
    """
    Compile the Advanced Encryption Tool into a single distributable binary.
    """
    print("[*] Initiating Advanced Encryption Tool compilation pipeline...")

    root_dir    = os.path.dirname(os.path.abspath(__file__))
    entry_point = os.path.join(root_dir, "src", "main.py")
    dist_dir    = os.path.join(root_dir, "dist")
    build_dir   = os.path.join(root_dir, "build")

    if not os.path.exists(entry_point):
        print(f"[!] Build fault: entry point not found at {entry_point}")
        sys.exit(1)

    for folder in (dist_dir, build_dir):
        if os.path.exists(folder):
            print(f"[*] Removing previous build artefact: {folder}")
            shutil.rmtree(folder)

    build_command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name=Advanced-Encryption-Tool",
        "--collect-submodules=cryptography",
        "--collect-submodules=PyQt6",
        "--hidden-import=src.core.encryption",
        "--hidden-import=src.ui.workers.encryption_thread",
        "--hidden-import=src.ui.components.drop_area",
        entry_point,
    ]

    print(f"[*] Dispatching build command:\n    {' '.join(build_command)}\n")

    try:
        subprocess.run(build_command, check=True)
        print(f"\n[+] Build complete. Standalone binary is inside: {dist_dir}")
    except subprocess.CalledProcessError as exc:
        print(f"\n[!] PyInstaller exited with code {exc.returncode}")
        sys.exit(exc.returncode)
    except FileNotFoundError:
        print("\n[!] PyInstaller is not installed in this environment.")
        print("    Run: pip install pyinstaller")
        sys.exit(1)


if __name__ == "__main__":
    run_production_build()
