from setuptools import setup, find_packages

setup(
    name='virgilSDK',
    version='1.0',
    packages=find_packages(),
    long_description='Virgil keys service SDK',
    package_data={
        "VirgilSDK.virgil_crypto": [
            "virgil-crypto-1.5.0-python-2.7-darwin-14.5-universal/_virgil_crypto_python.so",
            "virgil-crypto-1.5.0-python-2.7-linux-x86_64/_virgil_crypto_python.so",
            "virgil-crypto-1.5.0-python-2.7-windows-6.3-x64/_virgil_crypto_python.pyd",
            "virgil-crypto-1.5.0-python-2.7-windows-6.3-x86/_virgil_crypto_python.pyd",
            "virgil-crypto-1.5.0-python-3.4-darwin-14.5-universal/_virgil_crypto_python.so",
            "virgil-crypto-1.5.0-python-3.4-linux-x86_64/_virgil_crypto_python.so",
            "virgil-crypto-1.5.0-python-3.4-windows-6.3-x64/_virgil_crypto_python.pyd",
            "virgil-crypto-1.5.0-python-3.4-windows-6.3-x86/_virgil_crypto_python.pyd",
            "virgil-crypto-1.5.0-python-3.5-darwin-14.5-universal/_virgil_crypto_python.so",
            "virgil-crypto-1.5.0-python-3.5-windows-6.3-x64/_virgil_crypto_python.pyd",
            "virgil-crypto-1.5.0-python-3.5-windows-6.3-x86/_virgil_crypto_python.pyd", 
        ],
    },
)
