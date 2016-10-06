from setuptools import setup, find_packages

setup(
    name="virgil-sdk",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        'virgil-crypto',
    ],
    long_description="Virgil keys service SDK",
)
