import re
import setuptools


def read_version():
    with open('code/api/threatresponse/version.py', 'r') as fin:
        return re.search(
            r"^__version__ = '(?P<version>.+)'$",
            fin.read().strip(),
        ).group('version')


def read_readme():
    with open('README.md', 'r') as fin:
        return fin.read().strip()


def read_requirements():
    with open('code/requirements.txt', 'r') as fin:
        requirements = []
        for line in fin:
            # Discard any comments (i.e. everything after the very first '#').
            line = line.split('#', 1)[0].strip()
            if line:
                requirements.append(line)
        return requirements


NAME = 'threatresponse'

VERSION = read_version()

DESCRIPTION = 'Threat Response API Module'

LONG_DESCRIPTION = read_readme()

LONG_DESCRIPTION_CONTENT_TYPE = 'text/markdown'

URL = 'https://github.com/CiscoSecurity/tr-05-api-module'

AUTHOR = 'Cisco Security'

LICENSE = 'MIT'

PACKAGE_DIR = {"": "code/api/threatresponse"}

PACKAGES = setuptools.find_packages(where='code/api/threatresponse', exclude=['tests', 'tests.*'])

PYTHON_REQUIRES = '>=2.6'

INSTALL_REQUIRES = read_requirements()

KEYWORDS = [
    'cisco', 'security',
    'threat', 'response',
    'api', 'module',
    'python',
]

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Topic :: Software Development :: Libraries :: Python Modules',
]


setuptools.setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type=LONG_DESCRIPTION_CONTENT_TYPE,
    url=URL,
    author=AUTHOR,
    license=LICENSE,
    package_dir=PACKAGE_DIR,
    packages=PACKAGES,
    python_requires=PYTHON_REQUIRES,
    install_requires=INSTALL_REQUIRES,
    keywords=KEYWORDS,
    classifiers=CLASSIFIERS,
)
