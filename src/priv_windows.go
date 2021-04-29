// privdummy.go -- Dummy Privilege dropping on Non-unix platforms
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

// +build windows

package main

func DropPrivilege(uids, guids string) {
	warn("can't change uid/gid on this platform")
}
