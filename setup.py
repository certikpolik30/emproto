# setup.py

from setuptools import setup, find_packages

setup(
    name="cryptogamax",
    version="0.1.0",
    description="A Super Strong Cipher for secure encryption and decryption.",
    author="Alfisene Keita",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'cryptography',  # Ensure this dependency is installed
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
