from setuptools import setup, find_packages, Extension
from setuptools.command.develop import develop
from setuptools.command.install import install
from subprocess import check_call
from Cython.Build import cythonize

import versioneer


class PostDevelopCommand(develop):
    """Post-installation for development mode."""

    def run(self):
        develop.run(self)
        check_call("pre-commit install".split(" "))


class PostInstallCommand(install):
    """Post-installation for installation mode."""

    def run(self):
        install.run(self)
        # prod install, keep vanilla


extensions = [
    Extension(
        "xor",
        sources=[
            "xq/algorithms/c_functions/xor.pyx",
            "xq/algorithms/c_functions/neon_wrapper.c",
        ],
        extra_compile_args=["-O3", "-march=native"],
        extra_link_args=["-O3"],
    )
]

setup(
    name="xq-sdk",
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(
        {"develop": PostDevelopCommand, "install": PostInstallCommand}
    ),
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        "black",
        "python-dotenv",
        "pre-commit",
        "pycryptodome",
        "sphinx_rtd_theme",
        "requests",
        "Cython",
    ],
    tests_require=["coverage", "mock", "pytest", "python-docx", "PyPDF2"],
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    ext_modules=cythonize(extensions),
)
