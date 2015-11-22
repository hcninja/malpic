package main

import (
	"flag"
	"fmt"
	"image"
	"image/png"
	"io/ioutil"
	"os"

	bin "github.com/hcninja/malpic/binanal"
	img "github.com/hcninja/malpic/image"
)

const VERSION = "0.1β"

var infoFlag, execInfoFlag, colorizeFlag, symbolsDumpFlag, noPictFlag bool
var inputFlag, outputFlag string

func init() {
	flag.BoolVar(&infoFlag, "info", false, "Shows version and extended info")
	flag.BoolVar(&execInfoFlag, "execinfo", false, "Gets information from the PE format")
	flag.BoolVar(&symbolsDumpFlag, "symbols", false, "Dump symbols")
	flag.BoolVar(&colorizeFlag, "colorize", false, "Colorizes the binary sections on the picture")
	flag.BoolVar(&noPictFlag, "nopict", false, "Do not create the binary picture")
	flag.StringVar(&inputFlag, "in", "", "Select file to take photo")
	flag.StringVar(&outputFlag, "out", "", "Select the output name")
}

func main() {
	flag.Parse()

	if infoFlag {
		fmt.Println("")
		fmt.Println("malPic " + VERSION)
		fmt.Println("\t Malware visual analysis tool")
		fmt.Println("\t Licensed under GPLv2 – 2015")
		fmt.Println("\t https://github.com/hcninja/malpic/LICENSE")
		fmt.Println("\t By @bitsniper")
		fmt.Println("")
		os.Exit(0)
	}

	// Flag sanity checks
	if inputFlag == "" || outputFlag == "" && !noPictFlag {
		fmt.Println("[!] Please give me an input and output, try with -h")
		os.Exit(1)
	}

	if colorizeFlag && !execInfoFlag {
		fmt.Println("[!] Colorized output needs -execinfo")
		os.Exit(1)
	}

	if noPictFlag && !execInfoFlag {
		fmt.Println("[!] Setting -execinfo flag")
		execInfoFlag = true
	}

	if noPictFlag && inputFlag != "" {
		fmt.Println("[!] Ignoring -out flag")
	}

	if symbolsDumpFlag && !execInfoFlag {
		fmt.Println("[!] For symbols dump the -execinfo is needed")
		fmt.Println("[!] Symbols will not be dumped")
	}

	// Open file
	file, err := ioutil.ReadFile(inputFlag)
	if err != nil {
		fmt.Printf("[!] %s\n", err)
		os.Exit(1)
	}

	var sectionData [][]int
	// Extract executable info
	if execInfoFlag {
		if err := bin.IsPE(inputFlag); err == nil {
			fmt.Println("[+] File is PE")
			sectionData, err = bin.PEAnal(inputFlag, symbolsDumpFlag)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		} else if err := bin.IsELF(inputFlag); err == nil {
			fmt.Println("[+] File is ELF")
			sectionData, err = bin.ELFAnal(inputFlag, symbolsDumpFlag)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		} else if err := bin.IsMACHO(inputFlag); err == nil {
			fmt.Println("[+] File is MACH-O")
			sectionData, err = bin.MACHOAnal(inputFlag, symbolsDumpFlag)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		} else {
			fmt.Println("[+] File is not an executable")
		}
	}

	var encoder png.Encoder
	var binImage *image.RGBA

	// Encode binary to colorized image or B/W
	if !noPictFlag {
		if colorizeFlag {
			encoder, binImage = img.EncodeColor(file, sectionData)
		} else {
			encoder, binImage = img.EncodeBW(file)
		}

		// Write image to file
		malPict, _ := os.Create(outputFlag)
		encoder.Encode(malPict, binImage)
		fmt.Println("[+] Picture saved as: " + outputFlag)
	}
}
