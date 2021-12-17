// priv.go -- Privilege dropping on unix platforms
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

//go:build !windows
// +build !windows

package main

import (
	u "os/user"
	"strconv"
	"syscall"
)

// DropPrivilege changes the uid/gid. It dies if it cannot.
func DropPrivilege(uids, gids string) {

	if me := syscall.Getuid(); me != 0 {
		warn("Not running as 'root'; can't change uid/gid")
		return
	}

	if len(gids) > 0 {
		gi, err := u.LookupGroup(gids)
		if err != nil {
			gi, err = u.LookupGroupId(gids)
			if err != nil {
				die("can't find group '%s' to drop privilege: %s", gids, err)
			}
		}

		gid, err := strconv.Atoi(gi.Gid)
		if err != nil {
			die("can't parse integer gid %s: %s", gi.Gid, err)
		}

		if err = syscall.Setgid(gid); err != nil {
			die("can't change Gid to %d: %s", gid, err)
		}
	}

	if len(uids) > 0 {
		ui, err := u.Lookup(uids)
		if err != nil {
			ui, err = u.LookupId(uids)
			if err != nil {
				die("can't find user '%s' to drop privilege: %s", uids, err)
			}
		}
		uid, err := strconv.Atoi(ui.Uid)
		if err != nil {
			die("can't parse integer uid %s: %s", ui.Uid, err)
		}

		if err = syscall.Setuid(uid); err != nil {
			die("can't change Uid to %d: %s", uid, err)
		}
	}
}
