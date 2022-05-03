# cnkl
chunklist util for file Integrity checking or generate chunklist file such as `.chunklist` `.integrityDataV1` for file

## build
```swift build -c release```
or
```clang -O -o cnkl Sources/cnkl/main.c```

## usage
```
Usage: cnkl [-vcg] [-l <chunklist>] <file>
  -v              verbose
  -c              check file integrity
  -g              gen chunklist file
  -l <chunklist>  specify the <chunklist> file to use，if omitted try to match
                  <file>.chunklist or <file>.integrityDataV1
```
