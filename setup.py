# -*- coding: utf-8 -*-
import os
import re

from setuptools import Extension, setup, find_packages
from Cython.Build import cythonize

ext_modules = [
    Extension("pytea.tea",
              sources=["pytea/tea.pyx", "pytea/src/tea.c"], library_dirs=["pytea/src"])
]


def get_version() -> str:
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "pytea", "__init__.py")
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
    result = re.findall(r"(?<=__version__ = \")\S+(?=\")", data)
    return result[0]


def get_dis():
    with open("README.md", "r", encoding="utf-8") as f:
        return f.read()


packages = find_packages(exclude=('test', 'tests.*', "test*"))


def main():
    version: str = get_version()

    dis = get_dis()
    setup(
        name="pytea",
        version=version,
        url="https://github.com/synodriver/pytea",
        packages=packages,
        keywords=["tea", "encrypt", "decrypt"],
        description="tea encrypt and decrypt",
        long_description_content_type="text/markdown",
        long_description=dis,
        author="synodriver",
        author_email="diguohuangjiajinweijun@gmail.com",
        python_requires=">=3.6",
        install_requires=["cython"],
        license='GPLv3',
        ext_modules=cythonize(ext_modules),
        classifiers=[
            "Development Status :: 3 - Alpha",
            "Framework :: AsyncIO",
            "Operating System :: OS Independent",
            "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
            "Programming Language :: Python",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: Implementation :: CPython"
        ],
        include_package_data=True
    )


if __name__ == "__main__":
    main()
