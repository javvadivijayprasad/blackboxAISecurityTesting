#!/usr/bin/env bash
# Reproduce the Paper K PHP corpus at its pinned commits. Clones into ./_tmp, exports clean trees to ./targets.
set -euo pipefail
TMP="./_tmp"; T="./targets"; mkdir -p "$TMP" "$T"
pin() { # name url sha
  cd "$TMP"; rm -rf "$1"; git clone --quiet "$2" "$1"; cd "$1"; git checkout --quiet "$3"
  mkdir -p "../../$T/$1"; git archive HEAD | tar -x -C "../../$T/$1"; cd ../..
  echo "$3  $2" > "$T/$1/PINNED_COMMIT.txt"; echo "pinned $1 @ $3"
}
pin DVVWA       https://github.com/digininja/DVWA.git        a1978a2fed195acd093010af6395f86a281537ca
pin mutillidae  https://github.com/webpwnized/mutillidae.git 126a1fdb4ff977f87e980d018f0def477afc3d5d
pin WackoPicko  https://github.com/adamdoupe/WackoPicko.git  cabc1b3a06beda7df98e839fa2d84db9a4bdfee7
# vulhub subset: clone full repo at 9b90d4276f84feed6333286afeb7e1250379a1da and copy the environments listed in targets/vulhub-selected/PINNED_COMMIT.txt
echo "done"
