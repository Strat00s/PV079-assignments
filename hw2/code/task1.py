import math
import os
import re

HASH = "94bd25c4cf6ca889126df37ddd9c36e6a9b28a4fe15cc3da6debcdd7"

paths = ["test_vectors/bit", "test_vectors/byte"]

for path in paths:
    files = os.listdir(path)
    for file in files:
        with open(f"{path}/{file}", "r") as f:
            match = re.findall(HASH, f.read(), re.MULTILINE)
        if len(match) > 0:
            print(f"Match in {path}/{file}")
