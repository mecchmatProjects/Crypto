import os
import sys
import re

FILE_PK = "Private_key.txt"
FILE_MEL = "mel.txt"


if __name__ == "__main__":

    with open(FILE_PK) as f, open(FILE_MEL) as g:
        set1 = set()

        for line in f.readlines():
            if len(line.split())>0:
                set1.add(line.split()[-1])

        set2 = set()

        for line in g.readlines():
            if len(line.split()) > 0:
                set2.add(line.split()[0])

    common = set1 & set2

    for i,elem in enumerate(common):
        print(f"common element number {i+1}: {elem}")


