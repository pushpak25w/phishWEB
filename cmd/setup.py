from setuptools import setup

setup(
    name='phishweb',
    version='0.1.2',
    py_modules=['phishweb'],
    install_requires=[
        'Click',
    ],
    entry_points={
        'console_scripts': [
            'phishweb = phishweb:cli',
        ],
    },
)
