import os
from setuptools import find_packages, setup

requirements = [
    'Click',
    'paramiko',
    'pyvmomi',
    'requests',
    'ansicolors',
    'progressbar2',
    'termcolor',
    'colorama',
    'mcommons'
]

if os.name == 'posix':
    requirements.append('sh')

setup(name = "esx-cli",
    install_requires = requirements,
    version = "1.1",
    description = "A command line tool for managing vCenter and ESXi servers",
    author = "Moshe Immerman",
    author_email = 'name.surname@gmail.com',
    platforms = ["any"],
    license = "BSD",
    url = "http://github.com/Moshe-Immerman/esx-cli",
    packages = find_packages(),
    entry_points = {
        "console_scripts": [
            "esx = esx_cli.cli:main",
        ]
    }
)
