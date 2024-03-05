import json
import sys
import threading
from threading import Lock
from vulnerability_checker import VulnerabilityChecker


class DependencyFileFactory:
    @staticmethod
    def create_dependency_file(file_type: str, path: str):
        """
        :param file_type: type of file to check (requirements or package)
        :param path: path to the file we will check
        :return: based on the file type, returns the optimal object that will use the file data accordingly
        """
        if file_type == '-r':
            return RequirementsFile(path)
        elif file_type == '-p':
            return PackageJsonFile(path)
        else:
            print("Unsupported file type")
            sys.exit(4)


class DependencyFile:
    def __init__(self, path):
        self.path = path
        self.vulnerability_checker = VulnerabilityChecker()

    def parse(self):
        print("Each subclass must implement the parse method")
        sys.exit(1)


class RequirementsFile(DependencyFile):
    def parse(self):
        """
         parses the data from the requirements.txt file.
         after the data is parsed, each package and its version are checked inside
         our vulnerability checker.
        """
        try:
            try:
                # try UTF-8 encoding
                with open(self.path, 'r', encoding='utf-8') as req:
                    lines = req.readlines()
            except UnicodeDecodeError:
                # if UTF-8 fails, try UTF-16
                with open(self.path, 'r', encoding='utf-16') as req:
                    lines = req.readlines()
            for line in lines:
                if '==' in line and '#' not in line:
                    package, version = line.strip().split('==')
                    self.vulnerability_checker.rcheck_package(package, version)
        except FileNotFoundError:
            print(f"File not found at  {self.path}")
            sys.exit(4)
        except PermissionError:
            print(f"Permission to open the file at {self.path} was denied by the system.")
            sys.exit(4)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            sys.exit(1)
        print(self.vulnerability_checker.print_report())


class PackageJsonFile(DependencyFile):
    def parse(self):
        """
         parses the data from the package.json file.
         after the data is parsed, each package and its version are checked inside
         our vulnerability checker.
        """
        try:
            #  since the vast majority of json files are encoded with UTF-8, we'll keep that as the only possible option
            with open(self.path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            dependencies = data.get('dependencies', {})
            dependencies.update(data.get('devDependencies', {}))
            threads = []
            for dependency in dependencies:
                thread = threading.Thread(target=self.vulnerability_checker.pcheck_package,
                                          args=(dependency, dependencies[dependency]))
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join()
        except FileNotFoundError:
            print(f"File not found at  {self.path}")
            sys.exit(4)
        except PermissionError:
            print(f"Permission to open the file at {self.path} was denied by the system.")
            sys.exit(4)
        except Exception as e:
            print(f"Unexpected error occurred: {e}")
            sys.exit(1)
        print(self.vulnerability_checker.print_report())

