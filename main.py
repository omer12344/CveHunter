#!/usr/bin/env python3
import sys
from dependency_factory import DependencyFileFactory


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: cve-hunter -r <path to example_requirements.txt> or cve-hunter -p <path to example_package.json>")
    user_option, path = sys.argv[1], sys.argv[2]
    DependencyFileFactory.create_dependency_file(user_option, path).parse()


if __name__ == "__main__":
    main()
