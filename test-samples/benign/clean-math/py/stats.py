"""Python port of the same helpers."""
import ast
import os
import re

NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
HOME = os.environ.get("HOME", "")


def mean(xs):
    return sum(xs) / len(xs)


def parse(text):
    return [ast.literal_eval(n) for n in NUMBER.findall(text)]


def load(path):
    with open(path) as fh:
        return parse(fh.read())
