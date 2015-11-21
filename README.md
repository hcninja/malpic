# malpic
Malware visual analysis

## Usage

After a proper build with `go build -o malpic`, you can execute `./malpic -h`, this will show you all the available flags, there are self-explanatory.

```
Usage of malPic:
  -decode
        Decodes input to output
  -in string
        Select file to take photo
  -info
        Shows version and extended info
  -out string
        Select the output name
```

### Encode:

`malpic -in zsh -out test.png`

### Decode:

`malpic -in zsh -out test.png -decode`

### Analysis:

**NYI**
