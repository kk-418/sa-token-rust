#!/usr/bin/env bash
# Offline compile: Java Sa-Token 1.46.0 sources + FixtureGen/Verify.
# No mvn, no writes to ~/.m2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${ROOT}/out"
SA_TOKEN_SRC="${SA_TOKEN_SRC:-/Users/cikenerd/program/source-code/Sa-Token}"
M2="${M2_REPO:-${HOME}/.m2/repository}"

if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/javac" ]]; then
  JAVAC="${JAVA_HOME}/bin/javac"
else
  JAVAC="$(command -v javac)"
fi
if [[ -z "${JAVAC}" ]]; then
  echo "error: javac not found (need JDK 21)" >&2
  exit 1
fi

need_jar() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "error: missing jar (offline, will not download): ${path}" >&2
    exit 1
  fi
  echo "${path}"
}

JACKSON_DATABIND="$(need_jar "${M2}/tools/jackson/core/jackson-databind/3.1.0/jackson-databind-3.1.0.jar")"
JACKSON_CORE="$(need_jar "${M2}/tools/jackson/core/jackson-core/3.1.0/jackson-core-3.1.0.jar")"
# Jackson 3.1.0 databind still depends on com.fasterxml.jackson.annotation 2.x ([2.21,))
JACKSON_ANNOTATIONS="$(need_jar "${M2}/com/fasterxml/jackson/core/jackson-annotations/2.21/jackson-annotations-2.21.jar")"
HUTOOL_CORE="$(need_jar "${M2}/cn/hutool/hutool-core/5.8.36/hutool-core-5.8.36.jar")"
HUTOOL_JSON="$(need_jar "${M2}/cn/hutool/hutool-json/5.8.36/hutool-json-5.8.36.jar")"
HUTOOL_CRYPTO="$(need_jar "${M2}/cn/hutool/hutool-crypto/5.8.36/hutool-crypto-5.8.36.jar")"
HUTOOL_JWT="$(need_jar "${M2}/cn/hutool/hutool-jwt/5.8.36/hutool-jwt-5.8.36.jar")"

CP="${JACKSON_DATABIND}:${JACKSON_CORE}:${JACKSON_ANNOTATIONS}:${HUTOOL_CORE}:${HUTOOL_JSON}:${HUTOOL_CRYPTO}:${HUTOOL_JWT}"

MODULES=(
  "${SA_TOKEN_SRC}/sa-token-core/src/main/java"
  "${SA_TOKEN_SRC}/sa-token-plugin/sa-token-jackson3/src/main/java"
  "${SA_TOKEN_SRC}/sa-token-plugin/sa-token-jwt/src/main/java"
  "${SA_TOKEN_SRC}/sa-token-plugin/sa-token-apikey/src/main/java"
  "${SA_TOKEN_SRC}/sa-token-plugin/sa-token-sign/src/main/java"
)

for dir in "${MODULES[@]}"; do
  if [[ ! -d "${dir}" ]]; then
    echo "error: missing Sa-Token sources: ${dir}" >&2
    echo "       set SA_TOKEN_SRC to the Sa-Token 1.46.0 checkout" >&2
    exit 1
  fi
done

rm -rf "${OUT}"
mkdir -p "${OUT}"

SRC_LIST="$(mktemp)"
trap 'rm -f "${SRC_LIST}"' EXIT

for dir in "${MODULES[@]}"; do
  find "${dir}" -name '*.java' >> "${SRC_LIST}"
done

echo "javac Sa-Token $(wc -l < "${SRC_LIST}" | tr -d ' ') files -> ${OUT}"
"${JAVAC}" --release 21 -encoding UTF-8 -cp "${CP}" -d "${OUT}" @"${SRC_LIST}"

# Plugin SPI descriptors (optional; harness installs jackson3 explicitly)
copy_resources() {
  local src_res="$1"
  if [[ -d "${src_res}" ]]; then
    (
      cd "${src_res}"
      find . -type f | while IFS= read -r rel; do
        mkdir -p "${OUT}/$(dirname "${rel}")"
        cp "${rel}" "${OUT}/${rel}"
      done
    )
  fi
}
copy_resources "${SA_TOKEN_SRC}/sa-token-plugin/sa-token-jackson3/src/main/resources"
copy_resources "${SA_TOKEN_SRC}/sa-token-plugin/sa-token-apikey/src/main/resources"
copy_resources "${SA_TOKEN_SRC}/sa-token-plugin/sa-token-sign/src/main/resources"

HARNESS_LIST="$(mktemp)"
trap 'rm -f "${SRC_LIST}" "${HARNESS_LIST}"' EXIT
find "${ROOT}/src" -name '*.java' > "${HARNESS_LIST}"
echo "javac harness $(wc -l < "${HARNESS_LIST}" | tr -d ' ') files"
"${JAVAC}" --release 21 -encoding UTF-8 -cp "${CP}:${OUT}" -d "${OUT}" @"${HARNESS_LIST}"

# Persist classpath for java-interop.sh
cat > "${OUT}/classpath" <<EOF
${CP}:${OUT}
EOF

echo "build ok: ${OUT}"
