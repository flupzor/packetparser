from setuptools import find_packages, setup

setup(
    name='packetparser',
    version='0.1',
    url='https://github.com/flupzor/packetparser/',
    author='Alexander Schrijver',
    author_email='alex@flupzor.nl',
    description=('A PCAP parser with support for Radiotap and IEEE 802.11 frames'),
    license='ISC',
    packages=find_packages(exclude=['run_tests.sh', ]),

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: Other/Proprietary License',  # The ISC License I've used isn't OSI approved.
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
)
