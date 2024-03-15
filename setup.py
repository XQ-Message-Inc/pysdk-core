from setuptools import setup, find_packages, Extension
from setuptools.command.develop import develop
from setuptools.command.install import install
from subprocess import check_call

import versioneer


def check_and_install_cython():
    """Check if Cython is installed, if not, install it."""
    try:
        from Cython.Build import cythonize
    except ImportError:
        print("Cython is not installed. Installing Cython...")
        check_call([sys.executable, "-m", "pip", "install", "Cython"])
        # Check if Cython installation was successful
        try:
            from Cython.Build import cythonize
        except ImportError:
            raise ImportError(
                "Failed to install Cython. Please install Cython manually before proceeding."
            )

    return cythonize


# Custom Cython import that ensures it's installed before importing Cython related modules
cythonize = check_and_install_cython()


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
    tests_require=["coverage", "mock", "pytest", "python-docx", "pypdf", "python-docx"],
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    ext_modules=cythonize(extensions),
)
