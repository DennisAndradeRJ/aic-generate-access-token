from setuptools import setup, find_packages

setup(
    name='aic-service-account',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'requests',
        'jwcrypto'
    ],
    description='A service account client for Ping/ForgeRock Advanced Identity Cloud(AIC) APIs.',
    author='Anthony Harrison',
    author_email='anthony.harrison@pingidentity.com',
    url='https://stash.forgerock.org/users/anthony.harrison/repos/aic-service-account',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)