package main

import (
	"debug/pe"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"math"
	"os"
)

const VERSION = "0.1β"

var inputFlag, outputFlag string
var decodeFlag, infoFlag, peInfoFlag bool

func init() {
	flag.BoolVar(&infoFlag, "info", false, "Shows version and extended info")
	flag.BoolVar(&decodeFlag, "decode", false, "Decodes input to output")
	flag.BoolVar(&peInfoFlag, "peinfo", false, "Gets information of the PE format")
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

	if inputFlag == "" || outputFlag == "" {
		fmt.Println("[!] Please give me an input and output, try with -h")
		os.Exit(1)
	}

	if peInfoFlag {
		fmt.Printf("[+] Analyzing binary: %s\n", inputFlag)

		// Check for executable type
		peFmt, err := pe.Open(inputFlag)
		if err != nil {
			fmt.Printf("[!] %s is not a valid PE file\n", inputFlag)
			os.Exit(1)
		}
		defer peFmt.Close()

		fmt.Printf("[+] %s is a valid PE file\n", inputFlag)
		fmt.Printf("[+] Number of sections: %d\n", peFmt.NumberOfSections)
		sections := peFmt.Sections
		for k := range sections {
			fmt.Printf("\t Name: %s\n", sections[k].Name)
			fmt.Printf("\t Size: %d\n", sections[k].Size)
			fmt.Printf("\t Offset: %d\n", sections[k].Offset)
			fmt.Println("")
		}
	}

	if decodeFlag {
		decode(inputFlag)
	} else {
		// Open file
		file, err := ioutil.ReadFile(inputFlag)
		if err != nil {
			fmt.Printf("[!] %s\n", err)
			os.Exit(1)
		}
		encode(file)
	}
}

// Decodes a PGN grayscale file
func decode(file string) {
	// r, err := os.Open(file)
	// if err != nil {
	// 	fmt.Printf("[!] %s\n", err)
	// 	os.Exit(1)
	// }

	// img, err := png.Decode(r)
	// if err != nil {
	// 	fmt.Printf("[!] %s\n", err)
	// 	os.Exit(1)
	// }

	// var data color.Color{}
	// max := 757

	// for x := 0; x < max; x++ {
	// 	for y := 0; y < max; y++ {
	// 		data = append(data, []byte(img.At(x, y))[0])
	// 	}
	// }

	// fmt.Println(len(data))

	fmt.Println("[!] NYI")
}

// Encodes data to grayscale PNG file
func encode(file []byte) {
	fSize := len(file)
	min := 0
	max := int(math.Sqrt(float64(fSize)))
	binIndex := 0

	fmt.Printf("[+] File size: %d\n", fSize)
	fmt.Printf("[+] Max vector size: %d\n", max)
	fmt.Printf("[+] Total vectors: %d\n", fSize/max)

	binImage := image.NewRGBA(
		image.Rect(min, min, max, max),
	)

	// Fill the image with the file bytes
	for y := min; y < max; y++ {
		for x := min; x < max; x++ {
			c := color.Gray{
				uint8(file[binIndex]),
			}
			binIndex++
			binImage.Set(x, y, c)
		}
	}

	malPict, _ := os.Create(outputFlag)
	png.Encode(malPict, binImage)
	fmt.Println("[+] Picture saved as: " + outputFlag)
}
