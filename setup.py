from setuptools import setup, find_packages, Extension
from setuptools.command.develop import develop
from setuptools.command.install import install
from Cython.Build import cythonize

import versioneer
import subprocess
import platform

system = platform.system()
arch = platform.machine()

# Default compile and link args
extra_compile_args = ["-O3"]
extra_link_args = ["-O3"]

if system == "Darwin":  
    if arch == "arm64": 
        extra_compile_args.append("-mcpu=apple-m1")
    else: 
        extra_compile_args.append("-march=native")

elif system == "Windows":
    if "amd64" in arch or "x86" in arch: 
        extra_compile_args.append("-march=x86-64")

extensions = [
    Extension(
        "xq.algorithms.xor",
        sources=[
            "xq/algorithms/c_functions/xor.pyx",
            "xq/algorithms/c_functions/neon_wrapper.c",
        ],
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    )
]

class PostDevelopCommand(develop):
    """Post-installation for development mode."""

    def run(self):
        develop.run(self)
        subprocess.check_call("pre-commit install".split(" "))


class PostInstallCommand(install):
    """Post-installation for installation mode."""

    def run(self):
        install.run(self)
        # prod install, keep vanilla


setup(
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    packages=find_packages(exclude=["tests"]),
    tests_require=["coverage", "mock", "pytest", "python-docx", "pypdf"],
    ext_modules=cythonize(extensions),
)
