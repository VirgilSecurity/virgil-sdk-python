from setuptools import setup, find_packages

setup(
    name='virgilSDK',
    version='1.0',
    packages=find_packages(),
    long_description='Virgil keys service SDK',
    data_files=[('VirgilSDK/virgil_crypto', ['VirgilSDK/virgil_crypto/_virgil_crypto_python.pyd',
    'VirgilSDK/virgil_crypto/_virgil_crypto_python_64.pyd'])],
)
