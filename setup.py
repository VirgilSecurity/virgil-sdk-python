from setuptools import setup, find_packages

setup(
    name="virgil-sdk",
    version="4.0.1b",
    packages=find_packages(),
    install_requires=[
        'virgil-crypto',
    ],
    author="Virgil Security",
    author_email="support@virgilsecurity.com",
    url="https://virgilsecurity.com/",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Programming Language :: Python :: 2.7",
        "Topic :: Security :: Cryptography",
        ],
    license="BSD",
    long_description="Virgil keys service SDK",
)
