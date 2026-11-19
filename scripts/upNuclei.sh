#!/bin/sh
set -e

NUCLEI_VERSION="${NUCLEI_VERSION:-latest}"

if command -v nuclei >/dev/null 2>&1; then
	nuclei -update
	nuclei -update-templates
	nuclei -version
else
	echo "nuclei is not installed" >&2
	echo "Install it with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@$NUCLEI_VERSION" >&2
	exit 1
fi
