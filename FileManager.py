import os
import glob
from typing import List, Any


class FileManager:
    """
    FileManager class that provides methods for deleting files and writing objects to files.
    """

    version = '1.0'

    @staticmethod
    def delete_files(files_or_wildcards: List[str]) -> None:
        """
        Deletes files based on a list of filenames or wildcards. If a file does not exist,
        or the wildcard does not yield any results, it prints a message with the filename or wildcard.

        Parameters:
            files_or_wildcards (List[str]): A list of filenames or wildcard strings to match files for deletion.

        Returns:
            None
        """
        for pattern in files_or_wildcards:
            # Expand wildcard to actual file list
            files = glob.glob(pattern)
            if not files:
                print(f"No files found for wildcard/pattern: '{pattern}'")
                continue

            for file in files:
                try:
                    os.remove(file)
                    print(f"File deleted: {file}")
                except FileNotFoundError:
                    print(f"File does not exist and cannot be deleted: {file}")
                except OSError as e:
                    print(f"Error deleting file {file}: {e}")

    @staticmethod
    def write_to_file(obj: Any, filename: str) -> None:
        """
        Writes an object to a file with the specified filename. If the object is a string or bytes,
        it writes directly to the file. If it's another type that can be converted to a string (e.g., dict, list),
        it converts to a string using str() before writing.

        Parameters:
            obj (Any): The object to be written to the file. Can be a string, bytes, or any object
                       that has a string representation.
            filename (str): The name of the file to which the object will be written.

        Returns:
            None
        """
        try:
            # Check if the object is binary or text and open the file in the appropriate mode
            mode = 'wb' if isinstance(obj, bytes) else 'w'
            with open(filename, mode) as file:
                # If the object is not bytes, convert it to string
                if not isinstance(obj, bytes):
                    obj = str(obj)
                file.write(obj)
                print(f"Object successfully written to {filename}")
        except IOError as e:
            print(f"Failed to write to file {filename}: {e}")
        except TypeError as e:
            print(f"TypeError: The object could not be written to the file {filename}: {e}")
