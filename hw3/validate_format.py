#!/usr/bin/env python

import zipfile,json, argparse
from typing import Dict, Final, List, Optional, Union
from pathlib import Path
import re
import tempfile

FILENAME_REGEX: Final[re.Pattern] = re.compile(r"^results_\d{6}\.json$")
EXPECTED_KEYS: Dict[str, List[str]] = {"task_one": ["description", "m1"], "task_two": ["description", "m5"], "task_three": ["description", "plaintext", "modified_encrypted_command"]}

def extract_and_validate_zip(filepath: Path, unzip_path: Path) -> None:
    try:
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            zip_ref.extractall(unzip_path)
    except zipfile.BadZipFile:
        raise ValueError(f"The file {filepath} is not a valid zip file that could be extracted.")

def get_json_file(dir: Path) -> Path:
    jsons = [x for x in dir.iterdir() if x.is_file() and re.search(FILENAME_REGEX, x.name)]

    if not jsons:
        raise ValueError("Json file with proper name not found.")
    if len(jsons) > 1:
        raise ValueError("Multiple json files found.")

    return jsons[0]

def load_json(filepath: Path) -> Union[List, Dict]:
    try:
        with filepath.open("r") as handle:
            data = json.load(handle)
    except Exception:
        raise ValueError(f"The file {filepath} is not a valid JSON file.")

    if not isinstance(data, dict):
        raise ValueError(f"The {filepath} contents is not a dictionary.")

    return data

def validate_hex(val: Optional[str]) -> None:
    if not val:
        return
    try:
        bytes.fromhex(val)
    except Exception:
        raise ValueError(f"Value {val} is not a valid hexadecimal string.")

def validate_string(string: Optional[str]) -> None:
    if string and not isinstance(string, str):
        raise ValueError(f"The following value should be string but is not: `{string}`.")

def validate_description(string: Optional[str]) -> None:
    validate_string(string)
    if string and len(string) > 500:
        raise ValueError(f"The following description is too long (>500 characters): {string}.")

def validate_task_one(data: dict) -> None:
    validate = {"description": validate_description, "m1": validate_string}
    for key in data:
        validate[key](data[key])

def validate_task_two(data: dict) -> None:
    validate = {"description": validate_description, "m5": validate_hex}
    for key in data:
        validate[key](data[key])

def validate_task_three(data: dict) -> None:
    validate = {"description": validate_description, "plaintext": validate_string, "modified_encrypted_command": validate_hex}
    for key in data:
        validate[key](data[key])

def validate_json(data: dict) -> None:
    validate = {"task_one": validate_task_one, "task_two": validate_task_two, "task_three": validate_task_three}

    for task in EXPECTED_KEYS:
        if task not in data:
            raise ValueError(f"The json file is missing {task} solution.")
        if not data[task]:
            continue
        for key in EXPECTED_KEYS[task]:
            if key not in data[task]:
                raise ValueError(f"The json file is missing the {key} key of {task}.")
        if len(data[task]) != len(EXPECTED_KEYS[task]):
            raise ValueError(f"The dictionary {task} contains some extra keys, delete them.")

        validate[task](data[task])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "path",
        help="The filepath to ZIP file.",
        type=Path,
    )
    args = parser.parse_args()

    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            extract_and_validate_zip(args.path, Path(tmp_dir))
            json_path = get_json_file(Path(tmp_dir))
            data = load_json(json_path)
            validate_json(data)
    except Exception as e:
        print(f"Validation failed with: {e}")
    else:
        print("Your solution format is valid. Good job!")


if __name__ == "__main__":
    main()
