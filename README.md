# malpic
Malware visual analysis

## Usage

After a proper build with `go build -o malpic`, you can execute `./malpic -h`, this will show you all the available flags, there are self-explanatory.

```
Usage of malPic:
  -colorize
        Colorizes the binary sections on the picture
  -execinfo
        Gets information from the PE format
  -in string
        Select file to take photo
  -info
        Shows version and extended info
  -out string
        Select the output name
  -symbols
        Dump symbols
```

### Encode:

`malpic -in /bin/zsh -out test.png`


### Analysis:

**NYI**
