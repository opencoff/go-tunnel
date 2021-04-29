// pathutils.go -- reusable path utils
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"os"
)

// read directory 'dn' and return entries
func readdir(dn string) (files, dirs, oth []os.FileInfo, err error) {
	var fd *os.File

	fd, err = os.Open(dn)
	if err != nil {
		return
	}

	ent, err := fd.Readdir(-1)
	fd.Close()

	if err != nil {
		return
	}

	for _, e := range ent {
		m := e.Mode()
		if m.IsRegular() {
			files = append(files, e)
		} else if m.IsDir() {
			dirs = append(dirs, e)
		} else {
			oth = append(oth, e)
		}
	}

	return
}

// return true if fn exists and is a file
func isfile(fn string) bool {
	st, err := os.Stat(fn)
	if err == nil {
		m := st.Mode()
		return m.IsRegular()
	}

	return false
}

func isdir(dn string) bool {
	st, err := os.Stat(dn)
	if err == nil {
		return st.IsDir()
	}
	return false
}
