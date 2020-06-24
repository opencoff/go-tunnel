// safety.go -- safety checks on files and dirs
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"os"
	"path"
)

// Safely open a file named in the config-file
func (c *Conf) SafeOpenFile(fn string) (*os.File, error) {

	fn = c.Path(fn)
	fd, err := os.Open(fn)
	if err != nil {
		return nil, err
	}

	fi, err := fd.Stat()
	if err != nil {
		fd.Close()
		return nil, err
	}

	m := fi.Mode()
	if !m.IsRegular() {
		fd.Close()
		return nil, fmt.Errorf("%s: not a regular file", fn)
	}

	if err = checkStat(fi, fn); err != nil {
		fd.Close()
		return nil, err
	}
	return fd, nil
}

func (c *Conf) IsFileSafe(nm string) error {
	fn := c.Path(nm)
	fi, err := os.Stat(fn)
	if err != nil {
		return err
	}

	m := fi.Mode()
	if !m.IsRegular() {
		return fmt.Errorf("%s: Not a file", fn)
	}

	if err = checkStat(fi, fn); err != nil {
		return err
	}

	return nil
}

// Safely open a directory or file
func (c *Conf) SafeOpen(dn string) ([]*os.File, error) {
	fn := c.Path(dn)
	fd, err := os.Open(fn)
	if err != nil {
		return nil, err
	}

	fi, err := fd.Stat()
	if err != nil {
		fd.Close()
		return nil, err
	}

	// make sure every parent is safe
	if err = checkStat(fi, fn); err != nil {
		fd.Close()
		return nil, err
	}

	m := fi.Mode()
	if m.IsRegular() {
		return []*os.File{fd}, nil
	}

	// we know it's a dir or a non-regular file. So, we ought to close this from this point
	// on..
	defer fd.Close()

	if !m.IsDir() {
		return nil, fmt.Errorf("%s: not a file or directory", dn)
	}

	// now we can safely read the dir
	var files []*os.File

	fail := func(err error) ([]*os.File, error) {
		for i := range files {
			fd := files[i]
			fd.Close()
		}
		return nil, err
	}

	fiv, err := fd.Readdir(-1)
	if err != nil {
		return nil, err
	}

	for i := range fiv {
		fi := fiv[i]
		m := fi.Mode()
		if !m.IsRegular() {
			continue
		}

		// XXX we've checked every parent path to be safe. No need to check again?

		nm := fmt.Sprintf("%s/%s", fn, fi.Name())
		fx, err := os.Open(nm)
		if err != nil {
			return fail(err)
		}
		files = append(files, fx)

		fi, err = fx.Stat()
		if err != nil {
			return fail(err)
		}
		m = fi.Mode()
		if (m & 0066) != 0 {
			return fail(fmt.Errorf("%s: insecure perms (group/world writable)", nm))
		}
	}
	return files, nil
}

// check this stat result, validate it and its parent.
// We walk all the way up to the root
func checkStat(fi os.FileInfo, nm string) error {
	m := fi.Mode()
	if (m & 0066) != 0 {
		return fmt.Errorf("insecure perms on %s (group/world read/write)", nm)
	}

	// walk every parent of the given name 'nm' and make sure perms are good all the way
	// through
	for {
		dir := path.Dir(nm)
		if dir == nm {
			break
		}
		fi, err := os.Stat(dir)
		if err != nil {
			return err
		}
		m = fi.Mode()
		if (m & 0066) != 0 {
			return fmt.Errorf("insecure perms on %s (group/world read/write)", dir)
		}

		nm = dir
	}
	return nil
}
