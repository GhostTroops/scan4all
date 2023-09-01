// Copyright (c) 2023 dhn. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package go_utils

import (
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"os"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// Print results as JSON
func WriteJSON(results <-chan interface{}) {
	encoder := jsoniter.NewEncoder(os.Stdout)

	for result := range results {
		err := encoder.Encode(&result)
		if err != nil {
			gologger.Fatal().Msgf(err.Error())
		}
	}
}

// Print results as JSON or plain
func PrintResults(json bool, results <-chan interface{}) {
	if json {
		WriteJSON(results)
	} else {
		for result := range results {
			gologger.Silent().Msg(fmt.Sprintf("%v", result))
		}
	}
}

// Remove duplicate strings
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}

	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// Remove duplicates from a channel and return a channel from type Result
func RemoveDuplicates(input <-chan interface{}) <-chan interface{} {
	output := make(chan interface{})

	go func() {
		set := make(map[interface{}]struct{})
		for index := range input {
			if _, ok := set[index]; !ok {
				set[index] = struct{}{}
				output <- index
			}
		}
		close(output)
	}()

	return output
}

// Merge multiple channels from type Result
func MergeChannels(channels ...<-chan interface{}) <-chan interface{} {
	out := make(chan interface{})
	wg := sync.WaitGroup{}
	wg.Add(len(channels))

	for _, channel := range channels {
		go func(channel <-chan interface{}) {
			for value := range channel {
				out <- value
			}
			wg.Done()
		}(channel)
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
