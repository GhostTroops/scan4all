MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := test
.DELETE_ON_ERROR:
.SUFFIXES:

# ---------------------
# Environment variables
# ---------------------

GOPATH := $(shell go env GOPATH)

# ------------------
# Internal variables
# ------------------

package_name   := zbase32
test_args      := -v
virtualenv_cmd := $(shell command -v virtualenv)

# -------------
# Files & paths
# -------------

makfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
makefile_dir := $(patsubst %/,%,$(dir $(makfile_path)))

venv_base_path       := ${makefile_dir}/virtualenv
venv_check_path      := ${venv_base_path}/ok
venv_bin_path        := ${venv_base_path}/bin
venv_activation_path := ${venv_bin_path}/activate
venv_pip_path        := ${venv_bin_path}/pip

fuzz_pkg_path := ${makefile_dir}/${package_name}-fuzz.zip
fuzz_work_dir := ${makefile_dir}/fuzz


# -------
# Targets
# -------

.PHONY: test
test:
	@[[ -f ${venv_check_path} ]] && source ${venv_activation_path}; go test ${test_args} .

.PHONY: test-python
test-python: prepare_python
	@[[ -f ${venv_check_path} ]] && source ${venv_activation_path}; go test ${test_args} -test.run=Python .

.PHONY: test-fuzz
test-fuzz: ${fuzz_pkg_path}
	go-fuzz -bin=$< -workdir=${fuzz_work_dir}

install: ${GOPATH}/bin/${package_name}

${GOPATH}/bin/${package_name}: **/*.go
	go build -i -o "${@}" ./cmd

ifdef virtualenv_cmd
test: prepare_python
endif

.PHONY: prepare_python
prepare_python: ${venv_check_path}

${venv_check_path}: 
	${virtualenv_cmd} virtualenv
	${venv_pip_path} install zbase32
	touch $@

${fuzz_pkg_path}: **/*.go
	go-fuzz-build gopkg.in/corvus-ch/zbase32.v1

.PHONY: clean
clean:
	rm -rf ${venv_base_path}
	rm -rf ${fuzz_pkg_path} ${fuzz_work_dir}

# This Makefile tries to follow the principles describe at
# http://clarkgrubb.com/makefile-style-guide
