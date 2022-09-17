// Copyright 2020 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package redact

import "regexp"

const startRedactable = '‹'
const startRedactableS = string(startRedactable)

var startRedactableBytes = []byte(startRedactableS)

const endRedactable = '›'
const endRedactableS = string(endRedactable)

var endRedactableBytes = []byte(endRedactableS)

const escapeMark = '?'
const escapeMarkS = string(escapeMark)

var escapeBytes = []byte(escapeMarkS)

const redactedS = startRedactableS + "×" + endRedactableS

var redactedBytes = []byte(redactedS)

var reStripSensitive = regexp.MustCompile(startRedactableS + "[^" + startRedactableS + endRedactableS + "]*" + endRedactableS)

var reStripMarkers = regexp.MustCompile("[" + startRedactableS + endRedactableS + "]")
