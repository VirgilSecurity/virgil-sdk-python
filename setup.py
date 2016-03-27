from setuptools import setup, find_packages

setup(
    name='virgilSDK',
    version='1.0',
    packages=find_packages(),
    long_description='Virgil keys service SDK',
    package_data={
        "VirgilSDK.virgil_crypto": [
            "_virgil_crypto_python.pyd",
            "_virgil_crypto_python_64.pyd",
            "_virgil_crypto_python.so",
        ],
    },
)
