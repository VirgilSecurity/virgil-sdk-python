import os
import shutil
import subprocess

from distutils import log
from setuptools import setup, find_packages, Extension
from distutils.command.build import build as _build

try:
    this_file = __file__
except NameError:
    this_file = sys.argv[0]
this_file = os.path.abspath(this_file)

if os.path.dirname(this_file):
    os.chdir(os.path.dirname(this_file))
script_dir = os.getcwd()

def run_process(args):
    process = subprocess.Popen(args, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            log.info(output.strip())
    return process.poll()

class virgil_build(_build):
    def __init__(self, *args, **kwargs):
        _build.__init__(self, *args, **kwargs)

    def run(self):
        crypto_dir = os.path.join(script_dir, "src", "virgil-crypto")
        os.chdir(crypto_dir)
        build_prefix = os.path.join(script_dir, "_build")
        install_prefix = os.path.join(script_dir, "VirgilSDK")
        install_dir = "virgil_crypto"
        shutil.rmtree(build_prefix, ignore_errors=True)

        cmake_build_command = [
            "cmake",
            "-H.",
            "-B%s" % build_prefix,
            "-DCMAKE_INSTALL_PREFIX=%s" % install_prefix,
            "-DINSTALL_API_DIR_NAME=%s" % install_dir,
            "-DINSTALL_LIB_DIR_NAME=%s" % install_dir,
            "-DLANG=python"
        ]
        run_process(cmake_build_command)
        cmake_install_command = [
            "cmake",
            "--build",
            build_prefix,
            "--target",
            "install"
        ]
        run_process(cmake_install_command)
        os.chdir(script_dir)

setup(
    name="virgilSDK",
    version="1.0",
    packages=find_packages(),
    long_description="Virgil keys service SDK",
    cmdclass = {
      'build': virgil_build,
    },
    ext_modules = [Extension('virgil-crypto', [])],
    ext_package = 'VirgilSDK.virgil_crypto'
)
