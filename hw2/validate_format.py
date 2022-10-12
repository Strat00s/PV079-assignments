#!/usr/bin/env python

import os, zipfile,json, argparse
from pathlib import Path
from shutil import copyfile

JSON_NOT_FOUND = "JSON not found"
INVALID_FILENAME = "Filename of JSON is not valid"
JSON_NOT_JSON = "Your JSON is not valid JSON file"
DICT_NOT_DICT = "Your JSON file does not contain a dictionary"
ZIP_FILE = "The file is not correct zip file"

INTEGERS = ["c0","c12","c34","max","min"]
HEXES = ["m0","m1","m2","m3","m4","hash12","hash0","hash34"]
DESCS = ["D1", "D2", "D3"]
FLOAT = "avg"


def validate_descriptions(data):
    for s in DESCS:
        try:
            if data[s] is None:
                continue
            assert isinstance(data[s],str)
        except:
            raise ValueError(f"Something wrong with {s}")

def validate_hexes(data):
    for h in HEXES:
        try:
            if data[h] is None:
                continue
            assert isinstance(data[h],str)
            int(data[h],16)
        except:
            raise ValueError(f"Something wrong with {h}")

def validate_int(data):
    for i in INTEGERS:
        try:
            if data[i] is None:
                continue
            assert isinstance(data[i],int)
        except:
            raise ValueError(f"Something wrong with {i}")

def validate_float(data):
    try:
        if data[FLOAT] is None:
            return
        assert isinstance(data[FLOAT],float)
        s = "%.2f" % (data[FLOAT])
        assert float(s)==data[FLOAT]
    except:
        raise ValueError(f"Something wrong with {FLOAT}")


def validate_format(data: dict) -> bool:
    if not isinstance(data, dict):
        raise ValueError(DICT_NOT_DICT)

    validate_descriptions(data)
    validate_hexes(data)
    validate_int(data)
    validate_float(data)

def load_solution(filepath: Path) -> str:
    with open(filepath, "r") as handle:
        data = json.load(handle)

    return data

def validate_solution(filepath: Path, unzip_path = '.', json_copy = None):
    try:
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            zip_ref.extractall(unzip_path)
    except zipfile.BadZipFile:
        raise ValueError(ZIP_FILE)

    found_json = False
    for file in os.listdir(unzip_path):
        if file.startswith("results_") and file.endswith(".json"):
            found_json = True
            break
    if not found_json:
        raise ValueError(JSON_NOT_FOUND)
    try:
        uco = int(file[len("results_"):-len(".json")])
    except ValueError:
        raise ValueError(INVALID_FILENAME)

    try:
        data = load_solution(os.path.join(unzip_path,file))
    except:
        raise ValueError(JSON_NOT_JSON)
    validate_format(data)
    if json_copy is not None:
        new_name = f"{uco}.json"
        copyfile(os.path.join(unzip_path,file), os.path.join(json_copy,new_name))
    return uco


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "path",
        help="The filepath to ZIP file.",
        type=Path,
    )

    args = parser.parse_args()
    validate_solution(args.path)

    # control-flow is interrupted if there are any validation errors
    print("Your solution format is valid. Good job!")


if __name__ == "__main__":
    main()
