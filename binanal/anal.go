package binanal

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
)

func IsPE(fPath string) error {
	if _, err := pe.Open(fPath); err != nil {
		return err
	}

	return nil
}

func IsELF(fPath string) error {
	if _, err := elf.Open(fPath); err != nil {
		return err
	}

	return nil
}

func IsMACHO(fPath string) error {
	if _, err := macho.Open(fPath); err != nil {
		return err
	}

	return nil
}

func PEAnal(input string, symbolsDump bool) ([][]int, error) {
	// An array of arrays for storing the section offsets
	var sectionData [][]int

	fmt.Printf("[+] Analyzing binary: %s\n", input)

	// Check for executable type
	peFmt, err := pe.Open(input)
	if err != nil {
		fmt.Println("[!] This is not a valid PE file")
		return sectionData, nil
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
	if numberOfSymbols > 0 && symbolsDump {
		symbols := peFmt.Symbols

		for k := range symbols {
			sym := symbols[k]
			symName := sym.Name
			// symType := sym.Type
			// symValue := sym.Value

			fmt.Printf("\t Name: %s\n", symName)
			// fmt.Printf("\t\t Type: %d", symType)
			// fmt.Printf("\t\t Value: %d", symValue)
		}
		fmt.Println("")
	}

	return sectionData, nil
}

func MACHOAnal(input string, symbolsDump bool) ([][]int, error) {
	// An array of arrays for storing the section offsets
	var sectionData [][]int

	fmt.Printf("[+] Analyzing binary: %s\n", input)

	// Check for executable type
	machoFmt, err := macho.Open(input)
	if err != nil {
		return sectionData, err
	}
	defer machoFmt.Close()

	sections := machoFmt.Sections
	sectionCount := len(sections)

	fmt.Printf("[+] Number of sections: %d\n", sectionCount)

	for k := range sections {
		sec := sections[k]
		secName := sec.Name
		secSize := sec.Size
		secOffset := sec.Offset + 1
		secEnd := int(secOffset) + int(secSize) - 1

		fmt.Printf("\t Name: %s\n", secName)
		fmt.Printf("\t Size: %d\n", secSize)
		fmt.Printf("\t Offset: %d\n", secOffset)
		fmt.Printf("\t Section end: %d\n", secEnd)
		fmt.Println("")

		sectionData = append(sectionData, []int{int(secOffset), int(secEnd)})
	}

	symbols, err := machoFmt.ImportedSymbols()
	if err != nil {
		return sectionData, err
	}

	numberOfSymbols := len(symbols)

	fmt.Printf("[+] Found %d symbols\n", numberOfSymbols)
	if numberOfSymbols > 0 && symbolsDump {
		for k := range symbols {
			symName := symbols[k]

			fmt.Printf("\t Name: %s\n", symName)
		}
		fmt.Println("")
	}

	return sectionData, nil
}

func ELFAnal(input string, symbolsDump bool) ([][]int, error) {
	// An array of arrays for storing the section offsets
	var sectionData [][]int

	fmt.Printf("[+] Analyzing binary: %s\n", input)

	// Check for executable type
	elfFmt, err := elf.Open(input)
	if err != nil {
		return sectionData, err
	}
	defer elfFmt.Close()

	sections := elfFmt.Sections
	sectionCount := len(sections)

	fmt.Printf("[+] Number of sections: %d\n", sectionCount)

	for k := range sections {
		sec := sections[k]
		secName := sec.Name
		secSize := sec.Size
		secOffset := sec.Offset + 1
		secEnd := int(secOffset) + int(secSize) - 1

		fmt.Printf("\t Name: %s\n", secName)
		fmt.Printf("\t Size: %d\n", secSize)
		fmt.Printf("\t Offset: %d\n", secOffset)
		fmt.Printf("\t Section end: %d\n", secEnd)
		fmt.Println("")

		sectionData = append(sectionData, []int{int(secOffset), int(secEnd)})
	}

	symbols, err := elfFmt.ImportedSymbols()
	if err != nil {
		return sectionData, err
	}

	numberOfSymbols := len(symbols)

	fmt.Printf("[+] Found %d symbols\n", numberOfSymbols)
	if numberOfSymbols > 0 && symbolsDump {
		for k := range symbols {
			symName := symbols[k]

			fmt.Printf("\t Name: %s\n", symName)
		}
		fmt.Println("")
	}

	return sectionData, nil
}
