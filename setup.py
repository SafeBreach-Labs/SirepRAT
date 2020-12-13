import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sireprat-dorazouri", # Replace with your own username
    version="2.0.0",
    author="Dor Azouri",
    author_email="dorazouri@gmail.com",
    description="Remote Command Execution as SYSTEM on Windows IoT Core - \
      Features full RAT capabilities without the need of writing a real RAT malware on target",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SafeBreach-Labs/SirepRAT",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Intended Audience :: Manufacturing",
        "Topic :: Education",
        "Topic :: Education :: Testing",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: System :: System Shells",
        "Topic :: Utilities",
    ],
    python_requires='>=3.4',
)
