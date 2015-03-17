package main

import (
	"fmt"
	"github.com/docopt/docopt-go"
)

func main() {
	usage := `Trustedb.

Usage:
  trustedb [--version] [--keyfile=<path>] [--trustfile=<path>]
           <command> [<args>...]

  options:
    -h, --help

  The most commonly used trustedb commands are:
    init      Create a Trustfile
    key       Show or Create your trustedb key
    add       Add a key to the Trustfile
    remove    Remove a key from the Trustfile
    confirm   Confirm a Trustfile addition or removal`

	arguments, _ := docopt.Parse(usage, nil, true, "Trustedb 0.0.1", true)
	fmt.Println(arguments)
}
