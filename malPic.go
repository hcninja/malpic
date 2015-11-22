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

var infoFlag, execInfoFlag, colorizeFlag, symbolsDumpFlag bool
var inputFlag, outputFlag string

func init() {
	flag.BoolVar(&infoFlag, "info", false, "Shows version and extended info")
	flag.BoolVar(&execInfoFlag, "execinfo", false, "Gets information from the PE format")
	flag.BoolVar(&symbolsDumpFlag, "symbols", false, "Dump symbols")
	flag.BoolVar(&colorizeFlag, "colorize", false, "Colorizes the binary sections on the picture")
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

	// Open file
	file, err := ioutil.ReadFile(inputFlag)
	if err != nil {
		fmt.Printf("[!] %s\n", err)
		os.Exit(1)
	}

	// An array of arrays for storing the section offsets
	var sectionData [][]int

	// Extract executable info
	if execInfoFlag {
		fmt.Printf("[+] Analyzing binary: %s\n", inputFlag)

		// Check for executable type
		peFmt, err := pe.Open(inputFlag)
		if err != nil {
			fmt.Println("[!] This is not a valid PE file")
			os.Exit(1)
		}
		defer peFmt.Close()

		fmt.Println("[+] This is a valid PE file")
		fmt.Printf("[+] Number of sections: %d\n", peFmt.NumberOfSections)
		sections := peFmt.Sections

		for k := range sections {
			sec := sections[k]
			secName := sec.Name
			secSize := sec.Size
			secOffset := sec.Offset + 1
			secEnd := secOffset + secSize - 1
			secVSize := sec.VirtualSize
			secVAddr := sec.VirtualAddress

			fmt.Printf("\t Name: %s\n", secName)
			fmt.Printf("\t Size: %d\n", secSize)
			fmt.Printf("\t Offset: %d\n", secOffset)
			fmt.Printf("\t Section end: %d\n", secEnd)
			fmt.Printf("\t Virtual size: %d\n", secVSize)
			fmt.Printf("\t Virtual address: %d\n", secVAddr)
			fmt.Println("")

			sectionData = append(sectionData, []int{int(secOffset), int(secEnd)})
		}

		numberOfSymbols := peFmt.NumberOfSymbols
		fmt.Printf("[+] Found %d symbols\n", numberOfSymbols)
		if numberOfSymbols > 0 && symbolsDumpFlag {
			symbols := peFmt.Symbols

			for k := range symbols {
				sym := symbols[k]
				symName := sym.Name
				// symType := sym.Type
				// symValue := sym.Value

				fmt.Printf("\t Name: %s", symName)
				// fmt.Printf("\t\t Type: %d", symType)
				// fmt.Printf("\t\t Value: %d", symValue)
				fmt.Println("")
			}
		}
	}

	encode(file, sectionData)
}

// Encodes data to monochromatic-scale PNG file
func encode(file []byte, secDat [][]int) {
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

	var c color.Color
	sectionNumber := 0

	// Fill the image with the file bytes
	for y := min; y < max; y++ {
		for x := min; x < max; x++ {
			// Set section color delimiters
			idxA := binIndex > secDat[sectionNumber][0]
			idxB := binIndex < secDat[sectionNumber][1]
			lim := sectionNumber < len(secDat)-1

			// Increase section number
			if binIndex > secDat[sectionNumber][1] && lim {
				sectionNumber++
			}

			// If the same section and colorize flags is set
			if idxA && idxB && lim && colorizeFlag {
				// Get a color for every different section
				c = getColor(sectionNumber, file[binIndex])

			} else {
				c = color.RGBA{
					uint8(file[binIndex]),
					uint8(file[binIndex]),
					uint8(file[binIndex]),
					uint8(255),
				}
			}

			binIndex++
			binImage.Set(x, y, c)
		}
	}

	var enc png.Encoder
	enc.CompressionLevel = 0

	malPict, _ := os.Create(outputFlag)
	enc.Encode(malPict, binImage)
	fmt.Println("[+] Picture saved as: " + outputFlag)
}

// Generate color with the chromatic scale value setted
func getColor(selector int, value byte) color.Color {
	palette := []color.Color{
		// Red
		color.RGBA{
			uint8(value),
			uint8(16),
			uint8(16),
			uint8(255),
		},
		// Green
		color.RGBA{
			uint8(16),
			uint8(value),
			uint8(16),
			uint8(255),
		},
		// Blue
		color.RGBA{
			uint8(16),
			uint8(16),
			uint8(value),
			uint8(255),
		},
		// Yellow
		color.RGBA{
			uint8(value),
			uint8(value),
			uint8(16),
			uint8(255),
		},
		// Turquoise
		color.RGBA{
			uint8(16),
			uint8(value),
			uint8(value),
			uint8(255),
		},
		// Pink
		color.RGBA{
			uint8(value),
			uint8(16),
			uint8(value),
			uint8(255),
		},
		// …
		color.RGBA{
			uint8(16),
			uint8(value),
			uint8(16),
			uint8(128),
		},
		// …
		color.RGBA{
			uint8(16),
			uint8(16),
			uint8(value),
			uint8(128),
		},
		// …
		color.RGBA{
			uint8(value),
			uint8(value),
			uint8(16),
			uint8(128),
		},
		// …
		color.RGBA{
			uint8(16),
			uint8(value),
			uint8(value),
			uint8(128),
		},
		// …
		color.RGBA{
			uint8(value),
			uint8(16),
			uint8(value),
			uint8(128),
		},
	}

	return palette[selector]
}
