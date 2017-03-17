from setuptools import setup, find_packages

setup(
    name="virgil-sdk",
    version="4.2.0",
    packages=find_packages(),
    install_requires=[
        'virgil-crypto',
    ],
    author="Virgil Security",
    author_email="support@virgilsecurity.com",
    url="https://virgilsecurity.com/",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Topic :: Security :: Cryptography",
        ],
    license="BSD",
    description="Virgil keys service SDK",
    long_description="Virgil keys service SDK",
)
