from setuptools import setup

setup(
    name='acmepy',
    packages = ['acmepy'],
    version='0.1',
    license='Apache 2.0',
    description = 'Acme client to generate SSL Certificates for the websites',
    author = 'Krishna Khadka',
    author_email = 'krishnakhadka2802@gmail.com',
    url="https://github.com/khadkakrishna/acmepy/",
    download_url = 'https://github.com/khadkakrishna/acmepy/archive/v_01.tar.gz',
    keywords = ['acme', 'letsencrypt', 'sslwebsite','acmeclient'],
    install_requires=[
        'acme'
    ],
    classifiers = [
    'Development Status :: 1 - Production/Stable',
    'Intended Audience :: System Administrators and Developers',
    'License :: OSI Approved :: Apache 2.0 License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    ]
)