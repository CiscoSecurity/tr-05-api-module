import setuptools

import threatresponse


def read_requirements():
    with open('requirements.txt', 'r') as fin:
        requirements = []
        for line in fin:
            # Discard any comments (i.e. everything after the very first '#')
            line = line.split('#', 1)[0].strip()
            if line:
                requirements.append(line)
        return requirements


NAME = 'tr-api-client'

DESCRIPTION = 'Python module for working with the Threat Response APIs'

AUTHOR = 'Cisco'

URL = 'https://github.com/CiscoSecurity/tr-05-api-module'

VERSION = threatresponse.__version__

INSTALL_REQUIRES = read_requirements()

PACKAGES = setuptools.find_packages()

KEYWORDS = ['python', 'threat', 'response', 'api', 'client']

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 3',
]


setuptools.setup(
    name=NAME,
    description=DESCRIPTION,
    author=AUTHOR,
    url=URL,
    version=VERSION,
    install_requires=INSTALL_REQUIRES,
    packages=PACKAGES,
    keywords=KEYWORDS,
    classifiers=CLASSIFIERS,
)
