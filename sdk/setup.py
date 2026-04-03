from setuptools import find_packages, setup

setup(
    name="zerofalse",
    version="2.0.0",
    description="Runtime security firewall for AI agents",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Zerofalse, Inc.",
    url="https://zerofalse.com",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=["httpx>=0.27.0"],
    extras_require={
        "langchain": ["langchain>=0.1.0"],
        "redis": ["redis[asyncio]>=5.0.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
