from setuptools import setup, find_packages
from setuptools.command.develop import develop
from setuptools.command.install import install
import versioneer
from subprocess import check_call


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
        "python-dotenv",
        "sphinx_rtd_theme",
        "requests",
    ],
    tests_requires=["coverage", "mock", "pytest"],
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
