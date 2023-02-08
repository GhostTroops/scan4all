/usr/bin/git -c protocol.version=2 submodule update --remote --force --recursive
go install github.com/securego/gosec/cmd/gosec@latest
gosec -no-fail -fmt=sonarqube -out report.json ./...

