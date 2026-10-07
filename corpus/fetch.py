"""Download the SpamAssassin public corpus.

    python -m corpus.fetch

About 4,600 real messages - legitimate mail and spam, collected by the
SpamAssassin project and published for exactly this purpose. Roughly 25 MB,
extracted into corpus/data/, which is gitignored: you do not commit other
people's mail into your repo.
"""

from __future__ import annotations

import tarfile
import urllib.request
from pathlib import Path

BASE = "https://spamassassin.apache.org/old/publiccorpus/"
ARCHIVES = {
    "20030228_easy_ham.tar.bz2": "ham",
    "20030228_hard_ham.tar.bz2": "ham",
    "20030228_spam.tar.bz2": "spam",
    "20050311_spam_2.tar.bz2": "spam",
}

DATA = Path("corpus/data")


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    for archive, label in ARCHIVES.items():
        target = DATA / archive
        if not target.exists():
            print(f"downloading {archive} ...", flush=True)
            urllib.request.urlretrieve(BASE + archive, target)
        destination = DATA / label
        destination.mkdir(exist_ok=True)
        print(f"extracting {archive} -> {destination}", flush=True)
        with tarfile.open(target, "r:bz2") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                name = Path(member.name).name
                if name in ("cmds", ".DS_Store"):
                    continue
                out = destination / f"{Path(member.name).parent.name}_{name}"
                if out.exists():
                    continue
                source = tar.extractfile(member)
                if source is not None:
                    out.write_bytes(source.read())

    for label in ("ham", "spam"):
        print(f"{label}: {len(list((DATA / label).glob('*')))} messages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
