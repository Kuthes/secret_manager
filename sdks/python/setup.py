from setuptools import setup, find_packages

setup(
    name="aegisvault",
    version="1.0.0-rc1",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=["httpx>=0.27.0"],
)
