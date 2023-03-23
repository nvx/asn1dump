package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

// WidthFieldNameColumn is the width of the left column used to display
// data field name. You can change it to any value you like
var WidthFieldNameColumn = 48

// GetOIName retrieves the name of an object identifier from the oid-info.com Web site.
// Only the last two parts of the full name are kept to avoid names to be too long and
// difficult to read.
func GetOIName(oi string) string {
	// Check if we already know this object identifier from our MapOfObjects
	on, ok := MapOfObjects[oi]
	if ok {
		return on
	}

	return ""
}

// Min returns the smallest of x or y.
func Min(x, y int) int {
	if x > y {
		return y
	}
	return x
}

// PrintHex dumps a byte slice as hexadecimal values, with width and left margin
// of the dump given as parameters
func PrintHex(data []byte, prefix string, width int, margin int) {
	if len(data) == 0 {
		fmt.Printf("NUL")
		return
	}

	for i := 0; i < len(data); i += width {
		limit := Min(len(data), i+width)
		if i == 0 {
			fmt.Printf("% X", data[i:limit])
		} else {
			fmt.Printf("\n%s%s: % X", prefix, strings.Repeat(" ", margin-1-len(prefix)), data[i:limit])
		}
	}
}

// GetStringFromTag returns the full name of an ASN.1 type
func GetStringFromTag(class, tag int) string {
	if class != asn1.ClassUniversal {
		p := "UNKNOWN "
		switch class {
		case asn1.ClassApplication:
			p = "APPLICATION "
		case asn1.ClassContextSpecific:
			p = ""
		case asn1.ClassPrivate:
			p = "PRIVATE "
		}
		return "[" + p + strconv.Itoa(tag) + "]"
	}

	switch tag {
	case asn1.TagBoolean:
		return "BOOLEAN"
	case asn1.TagInteger:
		return "INTEGER"
	case asn1.TagBitString:
		return "BIT STRING"
	case asn1.TagOctetString:
		return "OCTET STRING"
	case asn1.TagNull:
		return "NULL"
	case asn1.TagOID:
		return "OBJECT IDENTIFIER"
	case asn1.TagEnum:
		return "ENUM"
	case asn1.TagUTF8String:
		return "UTF8 STRING"
	case asn1.TagSequence:
		return "SEQUENCE"
	case asn1.TagSet:
		return "SET"
	case asn1.TagNumericString:
		return "NUMERIC STRING"
	case asn1.TagPrintableString:
		return "PRINTABLE STRING"
	case asn1.TagT61String:
		return "T61String"
	case asn1.TagIA5String:
		return "IA5String"
	case asn1.TagUTCTime:
		return "UTCTime"
	case asn1.TagGeneralizedTime:
		return "GeneralizedTime"
	case asn1.TagGeneralString:
		return "GENERAL STRING"
	default:
		return "[UNIVERSAL " + strconv.Itoa(tag) + "]"
	}
}

// GetAsnValueAsString converts the raw value of parsed ASN1 data as
// something more readable depending on the ASN1 type value of the
// data read. Returns an empty string "" when no conversion of the value as
// a string was made.
func GetAsnValueAsString(asn *asn1.RawValue) string {
	if asn == nil || asn.Class != asn1.ClassUniversal {
		return ""
	}

	switch asn.Tag {
	case asn1.TagOID:
		var oi asn1.ObjectIdentifier
		_, err := asn1.Unmarshal(asn.FullBytes, &oi)
		if err != nil {
			// log.Println("Error unmarshalling -", err)
			return ""
		}
		s := oi.String()
		return fmt.Sprintf("%s %s", s, GetOIName(s))

	case asn1.TagPrintableString, asn1.TagIA5String, asn1.TagNumericString, asn1.TagUTF8String:
		var asnString string
		_, err := asn1.Unmarshal(asn.FullBytes, &asnString)
		if err != nil {
			log.Fatalln("Error unmarshalling -", err)
		}
		return asnString

	case asn1.TagUTCTime, asn1.TagGeneralizedTime:
		var t time.Time
		_, err := asn1.Unmarshal(asn.FullBytes, &t)
		if err != nil {
			log.Fatalln("Error unmarshalling -", err)
		}
		return t.String()

	case asn1.TagBoolean:
		var b bool
		_, err := asn1.Unmarshal(asn.FullBytes, &b)
		if err != nil {
			// log.Println("Error unmarshalling -", err)
			return ""
		}
		if b {
			return "true"
		} else {
			return "false"
		}

	case asn1.TagInteger:
		if len(asn.Bytes) <= 24 {
			// We only convert INTEGER when are not too large. INT larger
			// than 24 bytes are displayed has hex charts, which are easier to read
			var t *big.Int
			_, err := asn1.Unmarshal(asn.FullBytes, &t)
			if err != nil {
				log.Fatalln("Error unmarshalling -", err)
			}
			return t.String()
		}
	}

	return ""
}

// PrintFieldName prints on stdio the name of an ASN1 data field, making sure to
// stay in the WidthFieldNameColumn defined
func PrintFieldName(s string) {
	fmt.Printf("\n%-*.*s: ", WidthFieldNameColumn, WidthFieldNameColumn, s)
}

// IsValidAsn1 iff data consists entirely of valid ASN.1 data
func IsValidAsn1(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	var asn asn1.RawValue
	for {
		if len(data) == 0 {
			return true
		}

		var err error
		data, err = asn1.Unmarshal(data, &asn)
		if err != nil {
			return false
		}
	}
}

// Parse parses a slice of bytes as ASN1 data. It runs recursively to manage
// nested data entry
func Parse(data []byte, index int) {
	if len(data) == 0 {
		return
	}

	var asn asn1.RawValue
	for {
		var err error
		data, err = asn1.Unmarshal(data, &asn)
		if err != nil {
			log.Printf("Error unmarshalling - %v\n", err)
			log.Printf("\n% X\n", data)
			break
		}

		prefix := strings.Repeat("| ", index)

		// log.Printf("[%02d] %s (%d bytes) IsCompound:%v Rest:%d", index, GetStringFromTag(asn.Tag), len(asn.Bytes), asn.IsCompound, len(rest))
		PrintFieldName(fmt.Sprintf("%s%s (%d bytes)", prefix, GetStringFromTag(asn.Class, asn.Tag), len(asn.Bytes)))

		if asn.IsCompound {
			Parse(asn.Bytes, index+1)
		} else if asn.Class == asn1.ClassUniversal && asn.Tag == asn1.TagBitString && len(asn.Bytes) > 2 && asn.Bytes[0] == 0 && IsValidAsn1(asn.Bytes[1:]) {
			// A sequence inside a bit string
			PrintHex(asn.Bytes, prefix, 32, WidthFieldNameColumn+1)
			Parse(asn.Bytes[1:], index+1)
		} else if (asn.Class != asn1.ClassUniversal || asn.Tag == asn1.TagOctetString) && len(asn.Bytes) > 1 && IsValidAsn1(asn.Bytes) {
			// A sequence inside a octet string
			PrintHex(asn.Bytes, prefix, 32, WidthFieldNameColumn+1)
			Parse(asn.Bytes, index+1)
		} else {
			s := GetAsnValueAsString(&asn)
			if s == "" {
				PrintHex(asn.Bytes, prefix, 32, WidthFieldNameColumn+1)
			} else {
				fmt.Printf("%s", s)
			}
		}

		// log.Printf("[%02d] %s (%d bytes) IsCompound:%v Rest:%d", index, GetStringFromTag(asn.Tag), len(asn.Bytes), asn.IsCompound, len(rest))

		// Stop when no rest left, or rest is a line feed character
		if len(data) == 0 || (len(data) == 1 && data[0] == '\x0a') {
			break
		}
	}
}

// dumpDER is a Go program to read a DER file from stdin and display its structure and content
// in a readable way on stdio. Based on the Golang encoding/asn1 package to parse the DER file
func main() {
	var (
		decodeHex = flag.Bool("hex", false, "Decode hex")
	)
	flag.IntVar(&WidthFieldNameColumn, "width", WidthFieldNameColumn, "Width of field name column")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Read DER file from Stdin
	der, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalln("Error reading stdin -", err)
	}

	if *decodeHex {
		// strip whitespace
		der = bytes.Join(bytes.Fields(der), nil)

		n, err := hex.Decode(der, der)
		if err != nil {
			log.Fatalln("Error decoding hex bytes -", err)
		}
		der = der[:n]
	}

	Parse(der, 0)

	fmt.Println()

	// log.Printf("%#v", MapOfObjects)
}
