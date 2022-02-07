#------------------------------------------------------------------------------
# Micro Service: IPTables
#
# Copyright (c) 2022 Robert I. Gike
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#------------------------------------------------------------------------------

SHELL := /bin/bash

#---------------------------------------------
# development
#---------------------------------------------
VERBOSE=1

#---------------------------------------------
# directories
#---------------------------------------------
BASE_DIR=$(CURDIR)
TEMP_DIR=~/temp

#---------------------------------------------
# scripts
#---------------------------------------------

#---------------------------------------------
# shell commands
#---------------------------------------------
CDBACK=cd - 2>&1 >/dev/null
GCC=gcc -Wall -Werror -std=gnu14
LD=ld
LL=ls -al --color
NASM=nasm -f elf64
NASMDEBUG=nasm -f elf64 -F dwarf -g
SQLITE=sqlite3
TAGS=ctags

#---------------------------------------------
# variables
#---------------------------------------------
HOSTNAME=`hostname`
PYTHON=python3

#---------------------------------------------
# default target: help
#---------------------------------------------
.PHONY: help
help:
	@echo ""
	@echo "Micro Service IPTables Targets:"
	@echo ""
	@echo "clean          - cleanup output files"
	@echo "edit           - edit source files"
	@echo "rootservice    - run microservice as root"
	@echo ""

#---------------------------------------------
# target: clean
#---------------------------------------------
.PHONY: clean
clean:
	@rm -rf __pycache__

#---------------------------------------------
# target: check_if_root_user
#---------------------------------------------
.PHONY: check_if_root_user
check_if_root_user:
	@if [ `id -u` -ne 0 ] ; \
		then echo "User must be root!" ; \
		exit 1 ; \
	fi

#---------------------------------------------
# target: edit
#---------------------------------------------
.PHONY: edit
edit:
	@$(TAGS) *.py
	@vi *.py makefile

#---------------------------------------------
# target: rootservice
#---------------------------------------------
.PHONY: rootservice
rootservice:
	@su -c "./ms_iptables.py"

