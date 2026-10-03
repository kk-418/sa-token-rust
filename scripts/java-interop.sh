#!/usr/bin/env bash
# Compile Java harness, optionally generate gold samples, Verify fixtures
# and (if set) SA_INTEROP_DUMP_DIR Rust dumps.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAVA_DIR="${ROOT}/interop/java"
FIXTURE_DIR="${ROOT}/sa-token-integration-tests/fixtures/java-1.46.0"

if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
  JAVA="${JAVA_HOME}/bin/java"
else
  JAVA="$(command -v java)"
fi
if [[ -z "${JAVA}" ]]; then
  echo "error: java not found (need JDK 21)" >&2
  exit 1
fi

bash "${JAVA_DIR}/build.sh"

CP="$(cat "${JAVA_DIR}/out/classpath")"

if [[ "${1:-}" == "gen" ]]; then
  mkdir -p "${FIXTURE_DIR}"
  "${JAVA}" -cp "${CP}" FixtureGen "${FIXTURE_DIR}"
fi

shopt -s nullglob
gold=( "${FIXTURE_DIR}"/*.json )
if [[ ${#gold[@]} -eq 0 ]]; then
  echo "error: no gold samples in ${FIXTURE_DIR} (run: bash scripts/java-interop.sh gen)" >&2
  exit 1
fi

echo "Verify gold samples (${#gold[@]}) ..."
for f in "${gold[@]}"; do
  "${JAVA}" -cp "${CP}" Verify "${f}"
done

if [[ -n "${SA_INTEROP_DUMP_DIR:-}" && -d "${SA_INTEROP_DUMP_DIR}" ]]; then
  dumps=( "${SA_INTEROP_DUMP_DIR}"/*.json )
  if [[ ${#dumps[@]} -gt 0 ]]; then
    echo "Verify SA_INTEROP_DUMP_DIR dumps (${#dumps[@]}) ..."
    for f in "${dumps[@]}"; do
      "${JAVA}" -cp "${CP}" Verify "${f}"
    done
  else
    echo "SA_INTEROP_DUMP_DIR=${SA_INTEROP_DUMP_DIR} has no json (skip)"
  fi
fi

echo "java-interop ok"
