import sys,setuptools
with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="flask_plus",
    version="1.1.4",
    author="AlaBouali",
    author_email="trap.leader.123@gmail.com",
    description="Flask module to auto setup the project's configurations (app and database)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AlaBouali/flask_plus",
    python_requires=">=2.7",
    install_requires=["pymysql","cryptography","sanitizy","psycopg2"],
    packages=["flask_plus"],
    entry_points={ 'console_scripts': ['flask_plus = flask_plus.__main__:main' ] },
    license="MIT License",
    classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: MIT License ",
    ],
)