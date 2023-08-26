// Copyright (c) 2020, Theodor-Iulian Ciobanu
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:

// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//go:build profdump

package main

import (
	"flag"
	"fmt"
	"log/slog"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"
)

func init() {
	var (
		cpuprofile   = flag.Bool("cpuprofile", false, "write cpu profile")
		goprofile    = flag.Int("goprofile", -1, "write goroutine profile")
		heapprofile  = flag.Int("heapprofile", -1, "write heap profile")
		allocprofile = flag.Int("allocprofile", -1, "write allocs profile")
		tcprofile    = flag.Int("tcprofile", -1, "write threadcreate profile")
		blockprofile = flag.Int("blockprofile", -1, "write block profile")
		mutexprofile = flag.Int("mutexprofile", -1, "write mutex profile")
		allprofile   = flag.Int("allprofile", -1, "write all profiles")
	)

	// flag.Parse()

	if *allprofile >= 0 {
		*cpuprofile = true
		*goprofile = *allprofile
		*heapprofile = *allprofile
		*allocprofile = *allprofile
		*tcprofile = *allprofile
		*blockprofile = *allprofile
		*mutexprofile = *allprofile
	}

	getProfileFile, err := profileFileGetter("pprof")
	if err != nil {
		slog.Error(err.Error())
		return
	}

	var cpufile *os.File
	startProfiling = func() {
		var err error
		if *cpuprofile {
			cpufile, err = getProfileFile("cpu", 0)
			if err != nil {
				slog.Error(err.Error())
				return
			}
			if err = pprof.StartCPUProfile(cpufile); err != nil {
				slog.Error("could not start CPU profile", "error", err)
			}
		}
	}

	stopProfiling = func() {
		var err error
		if *cpuprofile {
			pprof.StopCPUProfile()
			if err = cpufile.Close(); err != nil {
				slog.Error("could not close CPU profil", "error", err)
				return
			}
		}

		runtime.GC()
		switch {
		case *goprofile >= 0:
			writeProfile("goroutine", *goprofile, getProfileFile)
			fallthrough
		case *heapprofile >= 0:
			writeProfile("heap", *heapprofile, getProfileFile)
			fallthrough
		case *allprofile >= 0:
			writeProfile("allocs", *allocprofile, getProfileFile)
			fallthrough
		case *tcprofile >= 0:
			writeProfile("threadcreate", *tcprofile, getProfileFile)
			fallthrough
		case *blockprofile >= 0:
			writeProfile("block", *blockprofile, getProfileFile)
			fallthrough
		case *mutexprofile >= 0:
			writeProfile("mutex", *mutexprofile, getProfileFile)
		}
	}
}

func writeProfile(name string, debug int,
	getProfileFile func(string, int) (*os.File, error),
) {
	f, err := getProfileFile(name, debug)
	if err != nil {
		slog.Error(err.Error())
		return
	}
	defer f.Close()

	if profile := pprof.Lookup(name); profile != nil {
		if err := profile.WriteTo(f, debug); err != nil {
			slog.Error("could not write profile", "name", name, "error", err)
			return
		}
	} else {
		slog.Error("profile not found", "name", name)
		return
	}
}

func profileFileGetter(prefix string) (func(string, int) (*os.File, error), error) {
	if prefix != "" {
		if err := os.MkdirAll(prefix, 0o755); err != nil {
			return nil, fmt.Errorf("could not create profiling folder %q: %v", prefix, err)
		}
	}

	startTime := time.Now().UTC().Unix()
	baseName := filepath.Base(os.Args[0])

	return func(profile string, debug int) (*os.File, error) {
		ext := "gz"
		if debug > 0 {
			ext = "txt"
		}

		f, err := os.Create(fmt.Sprintf("%s/%s_%s_%d.prof.%s", prefix, baseName, profile, startTime, ext))
		if err != nil {
			return nil, fmt.Errorf("could not create %s profile: %v", profile, err)
		}

		return f, nil
	}, nil
}
