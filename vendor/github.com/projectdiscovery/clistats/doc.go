// Package clistats implements a progress bar like functionality which
// displays periodic progress based on various rules.
//
// Rather than rendering and maintaining a dynamic progress bar, statistics
// are displayed in individual lines either based on user keystrokes or
// using a display alogrithm that observes changes in statistics over time.
//
// It is heavily inspired from nmap which is a very popular security scanning tool.
package clistats
