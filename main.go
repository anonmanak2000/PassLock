package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/anonmanak/PassLock/implementation"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-help" {
		implementation.PrintUsage()
		return
	}

	operation := os.Args[1]

	pm, err := implementation.NewPasswordManager()

	if err != nil {
		fmt.Println("An error occured: ", err)
		return
	}

	switch operation {
	case "-add-password":
		var tag, password string
		var generate bool

		flagSet := flag.NewFlagSet("add-password", flag.ExitOnError)
		flagSet.StringVar(&tag, "tag", "", "Specify the tag.")
		flagSet.StringVar(&password, "password", "", "Specify the password.")
		flagSet.BoolVar(&generate, "generate", false, "Generate a strong password.")
		flagSet.Parse(os.Args[2:])

		err := pm.AddPasswordWithTag(tag, password, generate)
		if err != nil {
			fmt.Println("An error occured: ", err)
		}

	case "-update-password":
		var tag, password string
		var generate bool

		flagSet := flag.NewFlagSet("update-password", flag.ExitOnError)
		flagSet.StringVar(&tag, "tag", "", "Specify the tag.")
		flagSet.StringVar(&password, "password", "", "Specify the new password.")
		flagSet.BoolVar(&generate, "generate", false, "Generate a new strong password.")
		flagSet.Parse(os.Args[2:])

		err := pm.UpdatePasswordWithTag(tag, password, generate)
		if err != nil {
			fmt.Println("An error occured: ", err)
		}
	case "-delete-password":
		var tag string
		flagSet := flag.NewFlagSet("delete-password", flag.ExitOnError)
		flagSet.StringVar(&tag, "tag", "", "Specify the tag.")
		flagSet.Parse(os.Args[2:])

		err := pm.DeletePasswordWithTag(tag)
		if err != nil {
			fmt.Println("An error occured: ", err)
		}
	case "-get-password":
		var tag string

		flagSet := flag.NewFlagSet("get-password", flag.ExitOnError)
		flagSet.StringVar(&tag, "tag", "", "Specify the tag.")
		flagSet.Parse(os.Args[2:])

		pm.GetPasswordWithTag(tag)
	case "-get-tags":

		pm.GetAllTags()
	default:
		fmt.Println("Invalid operation. Please use -help command to see all options.")
	}
}
