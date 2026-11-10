package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/overspend1/wgh/internal/acl"
	"github.com/overspend1/wgh/internal/coord"
)

// cmdAdminACL is 'wgh admin acl' (show the policy in use) and
// 'wgh admin acl check FILE' (validate a file without installing it).
func cmdAdminACL(fs *flag.FlagSet, args []string, adm func() *coord.Admin, stdout io.Writer) error {
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	switch {
	case len(pos) == 0:
		st, err := adm().ACL()
		if err != nil {
			return err
		}
		printACL(stdout, st)
		return nil
	case pos[0] == "check" && len(pos) == 2:
		return checkACL(stdout, pos[1], adm)
	}
	return fmt.Errorf("usage: wgh admin acl [check FILE], got %q", pos)
}

func printACL(w io.Writer, st coord.ACLStatus) {
	if st.InUse {
		fmt.Fprintf(w, "Access policy: %s, in use (%d rule(s), %d group(s))\n", st.Path, st.Rules, st.Groups)
		if !st.RelayFilter {
			fmt.Fprintln(w, "The relay does not filter relayed traffic; devices still filter what reaches them.")
		}
	} else {
		fmt.Fprintf(w, "Access policy: none (no %s): every device can reach every other one\n", st.Path)
	}
	if st.Error != "" {
		fmt.Fprintf(w, "\nThe file on disk was NOT loaded; the previous policy stays in use:\n  %s\n", st.Error)
	}
	printWarnings(w, st.Warnings)
	printReach(w, st.Reach)
}

func printWarnings(w io.Writer, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	fmt.Fprintln(w, "\nWarnings:")
	for _, s := range warnings {
		fmt.Fprintf(w, "  %s\n", s)
	}
}

func printReach(w io.Writer, reach []acl.Reach) {
	if len(reach) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nDEVICE\tCAN REACH")
	for _, r := range reach {
		to := strings.Join(r.To, ", ")
		switch {
		case len(r.To) == 0:
			to = "nobody"
		case len(reach) > 2 && len(r.To) == len(reach)-1:
			to = "everyone"
		}
		fmt.Fprintf(tw, "%s\t%s\n", r.From, to)
	}
	tw.Flush()
}

// checkACL validates a policy file. When the coordinator answers, it also
// shows what the file would mean for the devices in the mesh now.
func checkACL(w io.Writer, path string, adm func() *coord.Admin) error {
	p, err := acl.ParseFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s does not exist", path)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s is valid: %d rule(s), %d group(s)\n", path, p.Rules(), p.Groups())
	st, err := adm().Status()
	if err != nil {
		fmt.Fprintln(w, "(no coordinator answered here, so device names were not checked)")
		printWarnings(w, p.Warnings(nil))
		return nil
	}
	names := make([]string, 0, len(st.Devices))
	for _, d := range st.Devices {
		names = append(names, d.Name)
	}
	printWarnings(w, p.Warnings(names))
	printReach(w, p.Reach(names))
	fmt.Fprintf(w, "\nTo use it, copy it to %s in the coordinator directory; it is picked up within a few seconds.\n", acl.FileName)
	return nil
}
