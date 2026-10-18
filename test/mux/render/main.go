// Command render prints the wireguardd swift-mux ruleset for PUBLIC:AWG maps
// (used by test/mux/run.sh, so the e2e test runs the exact production rules).
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/reloadlife/wireguardd/internal/wgbackend"
)

func main() {
	var maps []wgbackend.MuxMap
	for _, a := range os.Args[1:] {
		pub, awg, ok := strings.Cut(a, ":")
		p, err1 := strconv.Atoi(pub)
		w, err2 := strconv.Atoi(awg)
		if !ok || err1 != nil || err2 != nil {
			fmt.Fprintln(os.Stderr, "usage: render PUBLIC:AWG_PORT ...")
			os.Exit(2)
		}
		maps = append(maps, wgbackend.MuxMap{PublicPort: p, AWGPort: w, Iface: "awgs"})
	}
	if err := wgbackend.ValidateMuxMaps(maps); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(wgbackend.RenderMux(maps))
}
