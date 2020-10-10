//Package ldapstrprep implements string preparation algorithms described in RFC 4518 (Lightweight Directory Access Protocol Internationalized String Preparation), including errata (as of 2020-09)
/*

Relations between RFC 4518 six-step process and functions are following:

1)  Transcode:

  func Transcode(s string) []rune

Note: To transcode non-Unicode string value to string, such as ut8string to string, is out of this function's scope. Use asn.1 or another package.

2)  Map:

  func MapCharacters(src []rune, caseFolding bool) []rune

3)  Normalize

  func Normalize(r []rune) []rune

4)  Prohibit

  func IsProhibited(src []rune) bool

5)  Check bidi

  No function is implemented. Because expected behaviour is the output string is same as the input string. So you do not need to do anything at this step.

6)  Insignificant Character Handling

6-1)  Insignificant Space Handling

6-1-1)  For attribute values or non-substring assertion values:

  func ApplyInsignificantSpaceHandling(src []rune) []rune

6-1-2)  For substring assertion values:

6-1-2-1)  For Initial

  func ApplyInsignificantSpaceHandlingInitial(substr []rune) []rune

6-1-2-2)  For Final

  func ApplyInsignificantSpaceHandlingFinal(substr []rune) []rune

6-1-2-3)  For Any

  func ApplyInsignificantSpaceHandlingAny(substr []rune) []rune

6-2)  numericString Insignificant Character Handling:

  func ApplyNumericStringInsignificantCharacterHandling(src []rune) []rune

6-3)  telephoneNumber Insignificant Character Handling:

  func ApplyTelephoneNumberInsignificantCharacterHandling(src []rune) []rune
*/
package ldapstrprep

import (
	"fmt"
	"golang.org/x/text/unicode/norm"
)

var (
	//https://tools.ietf.org/html/rfc4518#section-2.2
	//https://tools.ietf.org/html/rfc3454#appendix-B.2
	b2Table = make(map[rune][]rune)

	//https://tools.ietf.org/html/rfc4518#section-2.2
	nothingTable = make(map[rune]struct{})

	//https://tools.ietf.org/html/rfc4518#section-2.2
	spaceTable = make(map[rune]struct{})
)

//Transcode transcodes string s to slices of runes.
//https://tools.ietf.org/html/rfc4518#section-2.1
func Transcode(s string) []rune {
	return []rune(s)
}

//Normalize normalizes src to Unicode Form KC.
//https://tools.ietf.org/html/rfc4518#section-2.3
func Normalize(r []rune) []rune {
	src := string(r)
	if norm.NFKC.IsNormalString(src) {
		return []rune(src)
	}
	dst := norm.NFKC.String(string(r))
	return []rune(dst)
}

//MapCharacters maps src based on RFC 4518 section-2.2. if caseFolding is true, then Table B.2 is mapped.
//https://tools.ietf.org/html/rfc4518#section-2.2
func MapCharacters(src []rune, caseFolding bool) []rune {
	var dst = make([]rune, 0, 0)
	for _, uc := range src {

		//https://tools.ietf.org/html/rfc4518#section-2.2
		//CHARACTER TABULATION (U+0009), LINE FEED (LF) (U+000A), LINE
		//TABULATION (U+000B), FORM FEED (FF) (U+000C), CARRIAGE RETURN (CR)
		//(U+000D), and NEXT LINE (NEL) (U+0085) are mapped to SPACE (U+0020).
		//
		//All other code points with Separator (space, line, or paragraph) property (e.g., Zs,
		//Zl, or Zp) are mapped to SPACE (U+0020).  The following is a complete
		//list of these code points: U+0020, 00A0, 1680, 2000-200A, 2028-2029,
		//202F, 205F, 3000.
		if _, ok := spaceTable[uc]; ok {
			dst = append(dst, '\U00000020')
			continue
		}

		//https://tools.ietf.org/html/rfc4518#section-2.2
		//SOFT HYPHEN (U+00AD) and MONGOLIAN TODO SOFT HYPHEN (U+1806) code
		//points are mapped to nothing.  COMBINING GRAPHEME JOINER (U+034F) and
		//VARIATION SELECTORs (U+180B-180D, FF00-FE0F) code points are also
		//mapped to nothing.  The OBJECT REPLACEMENT CHARACTER (U+FFFC) is
		//mapped to nothing.
		//
		//All other control code (e.g., Cc) points or code points with a
		//control function (e.g., Cf) are mapped to nothing.  The following is
		//a complete list of these code points: U+0000-0008, 000E-001F, 007F-
		//0084, 0086-009F, 06DD, 070F, 180E, 200C-200F, 202A-202E, 2060-2063,
		//206A-206F, FEFF, FFF9-FFFB, 1D173-1D17A, E0001, E0020-E007F.
		//
		//ZERO WIDTH SPACE (U+200B) is mapped to nothing.
		if _, ok := nothingTable[uc]; ok {
			continue
		}

		//https://tools.ietf.org/html/rfc4518#section-2.2
		//For case ignore, numeric, and stored prefix string matching rules,
		//characters are case folded per B.2 of [RFC3454].
		if m, ok := b2Table[uc]; caseFolding && ok {
			//https://tools.ietf.org/html/rfc4518#section-2.2 RFC3454 Table B.2
			if len(m) != 0 {
				for _, mc := range m {
					dst = append(dst, mc)
				}
			}
			continue
		}
		dst = append(dst, uc)
	}
	return dst
}

//IsProhibited reports whether src contains prohibited code points.
//https://tools.ietf.org/html/rfc4518#section-2.4
func IsProhibited(src []rune) bool {
	for _, c := range src {
		if isProhibitedCharacter(c) {
			return true
		}
	}
	return false
}

//newProhibitError generate prohibited character Error.
func newProhibitError(c rune) error {
	return fmt.Errorf("ldapstrprep: %#U is prohibit character", c)
}

//isProhibitedCharacter reports whether c is prohibited code points.
//https://tools.ietf.org/html/rfc4518#section-2.4
func isProhibitedCharacter(c rune) bool {
	switch {
	//https://tools.ietf.org/html/rfc4518#section-2.4 RFC3454 Table A.1
	case c == 0X0221:
		return true
	case (c >= 0X0234) && (c <= 0X024F):
		return true
	case (c >= 0X02AE) && (c <= 0X02AF):
		return true
	case (c >= 0X02EF) && (c <= 0X02FF):
		return true
	case (c >= 0X0350) && (c <= 0X035F):
		return true
	case (c >= 0X0370) && (c <= 0X0373):
		return true
	case (c >= 0X0376) && (c <= 0X0379):
		return true
	case (c >= 0X037B) && (c <= 0X037D):
		return true
	case (c >= 0X037F) && (c <= 0X0383):
		return true
	case c == 0X038B:
		return true
	case c == 0X038D:
		return true
	case c == 0X03A2:
		return true
	case c == 0X03CF:
		return true
	case (c >= 0X03F7) && (c <= 0X03FF):
		return true
	case c == 0X0487:
		return true
	case c == 0X04CF:
		return true
	case (c >= 0X04F6) && (c <= 0X04F7):
		return true
	case (c >= 0X04FA) && (c <= 0X04FF):
		return true
	case (c >= 0X0510) && (c <= 0X0530):
		return true
	case (c >= 0X0557) && (c <= 0X0558):
		return true
	case c == 0X0560:
		return true
	case c == 0X0588:
		return true
	case (c >= 0X058B) && (c <= 0X0590):
		return true
	case c == 0X05A2:
		return true
	case c == 0X05BA:
		return true
	case (c >= 0X05C5) && (c <= 0X05CF):
		return true
	case (c >= 0X05EB) && (c <= 0X05EF):
		return true
	case (c >= 0X05F5) && (c <= 0X060B):
		return true
	case (c >= 0X060D) && (c <= 0X061A):
		return true
	case (c >= 0X061C) && (c <= 0X061E):
		return true
	case c == 0X0620:
		return true
	case (c >= 0X063B) && (c <= 0X063F):
		return true
	case (c >= 0X0656) && (c <= 0X065F):
		return true
	case (c >= 0X06EE) && (c <= 0X06EF):
		return true
	case c == 0X06FF:
		return true
	case c == 0X070E:
		return true
	case (c >= 0X072D) && (c <= 0X072F):
		return true
	case (c >= 0X074B) && (c <= 0X077F):
		return true
	case (c >= 0X07B2) && (c <= 0X0900):
		return true
	case c == 0X0904:
		return true
	case (c >= 0X093A) && (c <= 0X093B):
		return true
	case (c >= 0X094E) && (c <= 0X094F):
		return true
	case (c >= 0X0955) && (c <= 0X0957):
		return true
	case (c >= 0X0971) && (c <= 0X0980):
		return true
	case c == 0X0984:
		return true
	case (c >= 0X098D) && (c <= 0X098E):
		return true
	case (c >= 0X0991) && (c <= 0X0992):
		return true
	case c == 0X09A9:
		return true
	case c == 0X09B1:
		return true
	case (c >= 0X09B3) && (c <= 0X09B5):
		return true
	case (c >= 0X09BA) && (c <= 0X09BB):
		return true
	case c == 0X09BD:
		return true
	case (c >= 0X09C5) && (c <= 0X09C6):
		return true
	case (c >= 0X09C9) && (c <= 0X09CA):
		return true
	case (c >= 0X09CE) && (c <= 0X09D6):
		return true
	case (c >= 0X09D8) && (c <= 0X09DB):
		return true
	case c == 0X09DE:
		return true
	case (c >= 0X09E4) && (c <= 0X09E5):
		return true
	case (c >= 0X09FB) && (c <= 0X0A01):
		return true
	case (c >= 0X0A03) && (c <= 0X0A04):
		return true
	case (c >= 0X0A0B) && (c <= 0X0A0E):
		return true
	case (c >= 0X0A11) && (c <= 0X0A12):
		return true
	case c == 0X0A29:
		return true
	case c == 0X0A31:
		return true
	case c == 0X0A34:
		return true
	case c == 0X0A37:
		return true
	case (c >= 0X0A3A) && (c <= 0X0A3B):
		return true
	case c == 0X0A3D:
		return true
	case (c >= 0X0A43) && (c <= 0X0A46):
		return true
	case (c >= 0X0A49) && (c <= 0X0A4A):
		return true
	case (c >= 0X0A4E) && (c <= 0X0A58):
		return true
	case c == 0X0A5D:
		return true
	case (c >= 0X0A5F) && (c <= 0X0A65):
		return true
	case (c >= 0X0A75) && (c <= 0X0A80):
		return true
	case c == 0X0A84:
		return true
	case c == 0X0A8C:
		return true
	case c == 0X0A8E:
		return true
	case c == 0X0A92:
		return true
	case c == 0X0AA9:
		return true
	case c == 0X0AB1:
		return true
	case c == 0X0AB4:
		return true
	case (c >= 0X0ABA) && (c <= 0X0ABB):
		return true
	case c == 0X0AC6:
		return true
	case c == 0X0ACA:
		return true
	case (c >= 0X0ACE) && (c <= 0X0ACF):
		return true
	case (c >= 0X0AD1) && (c <= 0X0ADF):
		return true
	case (c >= 0X0AE1) && (c <= 0X0AE5):
		return true
	case (c >= 0X0AF0) && (c <= 0X0B00):
		return true
	case c == 0X0B04:
		return true
	case (c >= 0X0B0D) && (c <= 0X0B0E):
		return true
	case (c >= 0X0B11) && (c <= 0X0B12):
		return true
	case c == 0X0B29:
		return true
	case c == 0X0B31:
		return true
	case (c >= 0X0B34) && (c <= 0X0B35):
		return true
	case (c >= 0X0B3A) && (c <= 0X0B3B):
		return true
	case (c >= 0X0B44) && (c <= 0X0B46):
		return true
	case (c >= 0X0B49) && (c <= 0X0B4A):
		return true
	case (c >= 0X0B4E) && (c <= 0X0B55):
		return true
	case (c >= 0X0B58) && (c <= 0X0B5B):
		return true
	case c == 0X0B5E:
		return true
	case (c >= 0X0B62) && (c <= 0X0B65):
		return true
	case (c >= 0X0B71) && (c <= 0X0B81):
		return true
	case c == 0X0B84:
		return true
	case (c >= 0X0B8B) && (c <= 0X0B8D):
		return true
	case c == 0X0B91:
		return true
	case (c >= 0X0B96) && (c <= 0X0B98):
		return true
	case c == 0X0B9B:
		return true
	case c == 0X0B9D:
		return true
	case (c >= 0X0BA0) && (c <= 0X0BA2):
		return true
	case (c >= 0X0BA5) && (c <= 0X0BA7):
		return true
	case (c >= 0X0BAB) && (c <= 0X0BAD):
		return true
	case c == 0X0BB6:
		return true
	case (c >= 0X0BBA) && (c <= 0X0BBD):
		return true
	case (c >= 0X0BC3) && (c <= 0X0BC5):
		return true
	case c == 0X0BC9:
		return true
	case (c >= 0X0BCE) && (c <= 0X0BD6):
		return true
	case (c >= 0X0BD8) && (c <= 0X0BE6):
		return true
	case (c >= 0X0BF3) && (c <= 0X0C00):
		return true
	case c == 0X0C04:
		return true
	case c == 0X0C0D:
		return true
	case c == 0X0C11:
		return true
	case c == 0X0C29:
		return true
	case c == 0X0C34:
		return true
	case (c >= 0X0C3A) && (c <= 0X0C3D):
		return true
	case c == 0X0C45:
		return true
	case c == 0X0C49:
		return true
	case (c >= 0X0C4E) && (c <= 0X0C54):
		return true
	case (c >= 0X0C57) && (c <= 0X0C5F):
		return true
	case (c >= 0X0C62) && (c <= 0X0C65):
		return true
	case (c >= 0X0C70) && (c <= 0X0C81):
		return true
	case c == 0X0C84:
		return true
	case c == 0X0C8D:
		return true
	case c == 0X0C91:
		return true
	case c == 0X0CA9:
		return true
	case c == 0X0CB4:
		return true
	case (c >= 0X0CBA) && (c <= 0X0CBD):
		return true
	case c == 0X0CC5:
		return true
	case c == 0X0CC9:
		return true
	case (c >= 0X0CCE) && (c <= 0X0CD4):
		return true
	case (c >= 0X0CD7) && (c <= 0X0CDD):
		return true
	case c == 0X0CDF:
		return true
	case (c >= 0X0CE2) && (c <= 0X0CE5):
		return true
	case (c >= 0X0CF0) && (c <= 0X0D01):
		return true
	case c == 0X0D04:
		return true
	case c == 0X0D0D:
		return true
	case c == 0X0D11:
		return true
	case c == 0X0D29:
		return true
	case (c >= 0X0D3A) && (c <= 0X0D3D):
		return true
	case (c >= 0X0D44) && (c <= 0X0D45):
		return true
	case c == 0X0D49:
		return true
	case (c >= 0X0D4E) && (c <= 0X0D56):
		return true
	case (c >= 0X0D58) && (c <= 0X0D5F):
		return true
	case (c >= 0X0D62) && (c <= 0X0D65):
		return true
	case (c >= 0X0D70) && (c <= 0X0D81):
		return true
	case c == 0X0D84:
		return true
	case (c >= 0X0D97) && (c <= 0X0D99):
		return true
	case c == 0X0DB2:
		return true
	case c == 0X0DBC:
		return true
	case (c >= 0X0DBE) && (c <= 0X0DBF):
		return true
	case (c >= 0X0DC7) && (c <= 0X0DC9):
		return true
	case (c >= 0X0DCB) && (c <= 0X0DCE):
		return true
	case c == 0X0DD5:
		return true
	case c == 0X0DD7:
		return true
	case (c >= 0X0DE0) && (c <= 0X0DF1):
		return true
	case (c >= 0X0DF5) && (c <= 0X0E00):
		return true
	case (c >= 0X0E3B) && (c <= 0X0E3E):
		return true
	case (c >= 0X0E5C) && (c <= 0X0E80):
		return true
	case c == 0X0E83:
		return true
	case (c >= 0X0E85) && (c <= 0X0E86):
		return true
	case c == 0X0E89:
		return true
	case (c >= 0X0E8B) && (c <= 0X0E8C):
		return true
	case (c >= 0X0E8E) && (c <= 0X0E93):
		return true
	case c == 0X0E98:
		return true
	case c == 0X0EA0:
		return true
	case c == 0X0EA4:
		return true
	case c == 0X0EA6:
		return true
	case (c >= 0X0EA8) && (c <= 0X0EA9):
		return true
	case c == 0X0EAC:
		return true
	case c == 0X0EBA:
		return true
	case (c >= 0X0EBE) && (c <= 0X0EBF):
		return true
	case c == 0X0EC5:
		return true
	case c == 0X0EC7:
		return true
	case (c >= 0X0ECE) && (c <= 0X0ECF):
		return true
	case (c >= 0X0EDA) && (c <= 0X0EDB):
		return true
	case (c >= 0X0EDE) && (c <= 0X0EFF):
		return true
	case c == 0X0F48:
		return true
	case (c >= 0X0F6B) && (c <= 0X0F70):
		return true
	case (c >= 0X0F8C) && (c <= 0X0F8F):
		return true
	case c == 0X0F98:
		return true
	case c == 0X0FBD:
		return true
	case (c >= 0X0FCD) && (c <= 0X0FCE):
		return true
	case (c >= 0X0FD0) && (c <= 0XFFF):
		return true
	case c == 0X1022:
		return true
	case c == 0X1028:
		return true
	case c == 0X102B:
		return true
	case (c >= 0X1033) && (c <= 0X1035):
		return true
	case (c >= 0X103A) && (c <= 0X103F):
		return true
	case (c >= 0X105A) && (c <= 0X109F):
		return true
	case (c >= 0X10C6) && (c <= 0X10CF):
		return true
	case (c >= 0X10F9) && (c <= 0X10FA):
		return true
	case (c >= 0X10FC) && (c <= 0X10FF):
		return true
	case (c >= 0X115A) && (c <= 0X115E):
		return true
	case (c >= 0X11A3) && (c <= 0X11A7):
		return true
	case (c >= 0X11FA) && (c <= 0X11FF):
		return true
	case c == 0X1207:
		return true
	case c == 0X1247:
		return true
	case c == 0X1249:
		return true
	case (c >= 0X124E) && (c <= 0X124F):
		return true
	case c == 0X1257:
		return true
	case c == 0X1259:
		return true
	case (c >= 0X125E) && (c <= 0X125F):
		return true
	case c == 0X1287:
		return true
	case c == 0X1289:
		return true
	case (c >= 0X128E) && (c <= 0X128F):
		return true
	case c == 0X12AF:
		return true
	case c == 0X12B1:
		return true
	case (c >= 0X12B6) && (c <= 0X12B7):
		return true
	case c == 0X12BF:
		return true
	case c == 0X12C1:
		return true
	case (c >= 0X12C6) && (c <= 0X12C7):
		return true
	case c == 0X12CF:
		return true
	case c == 0X12D7:
		return true
	case c == 0X12EF:
		return true
	case c == 0X130F:
		return true
	case c == 0X1311:
		return true
	case (c >= 0X1316) && (c <= 0X1317):
		return true
	case c == 0X131F:
		return true
	case c == 0X1347:
		return true
	case (c >= 0X135B) && (c <= 0X1360):
		return true
	case (c >= 0X137D) && (c <= 0X139F):
		return true
	case (c >= 0X13F5) && (c <= 0X1400):
		return true
	case (c >= 0X1677) && (c <= 0X167F):
		return true
	case (c >= 0X169D) && (c <= 0X169F):
		return true
	case (c >= 0X16F1) && (c <= 0X16FF):
		return true
	case c == 0X170D:
		return true
	case (c >= 0X1715) && (c <= 0X171F):
		return true
	case (c >= 0X1737) && (c <= 0X173F):
		return true
	case (c >= 0X1754) && (c <= 0X175F):
		return true
	case c == 0X176D:
		return true
	case c == 0X1771:
		return true
	case (c >= 0X1774) && (c <= 0X177F):
		return true
	case (c >= 0X17DD) && (c <= 0X17DF):
		return true
	case (c >= 0X17EA) && (c <= 0X17FF):
		return true
	case c == 0X180F:
		return true
	case (c >= 0X181A) && (c <= 0X181F):
		return true
	case (c >= 0X1878) && (c <= 0X187F):
		return true
	case (c >= 0X18AA) && (c <= 0X1DFF):
		return true
	case (c >= 0X1E9C) && (c <= 0X1E9F):
		return true
	case (c >= 0X1EFA) && (c <= 0X1EFF):
		return true
	case (c >= 0X1F16) && (c <= 0X1F17):
		return true
	case (c >= 0X1F1E) && (c <= 0X1F1F):
		return true
	case (c >= 0X1F46) && (c <= 0X1F47):
		return true
	case (c >= 0X1F4E) && (c <= 0X1F4F):
		return true
	case c == 0X1F58:
		return true
	case c == 0X1F5A:
		return true
	case c == 0X1F5C:
		return true
	case c == 0X1F5E:
		return true
	case (c >= 0X1F7E) && (c <= 0X1F7F):
		return true
	case c == 0X1FB5:
		return true
	case c == 0X1FC5:
		return true
	case (c >= 0X1FD4) && (c <= 0X1FD5):
		return true
	case c == 0X1FDC:
		return true
	case (c >= 0X1FF0) && (c <= 0X1FF1):
		return true
	case c == 0X1FF5:
		return true
	case c == 0X1FFF:
		return true
	case (c >= 0X2053) && (c <= 0X2056):
		return true
	case (c >= 0X2058) && (c <= 0X205E):
		return true
	case (c >= 0X2064) && (c <= 0X2069):
		return true
	case (c >= 0X2072) && (c <= 0X2073):
		return true
	case (c >= 0X208F) && (c <= 0X209F):
		return true
	case (c >= 0X20B2) && (c <= 0X20CF):
		return true
	case (c >= 0X20EB) && (c <= 0X20FF):
		return true
	case (c >= 0X213B) && (c <= 0X213C):
		return true
	case (c >= 0X214C) && (c <= 0X2152):
		return true
	case (c >= 0X2184) && (c <= 0X218F):
		return true
	case (c >= 0X23CF) && (c <= 0X23FF):
		return true
	case (c >= 0X2427) && (c <= 0X243F):
		return true
	case (c >= 0X244B) && (c <= 0X245F):
		return true
	case c == 0X24FF:
		return true
	case (c >= 0X2614) && (c <= 0X2615):
		return true
	case c == 0X2618:
		return true
	case (c >= 0X267E) && (c <= 0X267F):
		return true
	case (c >= 0X268A) && (c <= 0X2700):
		return true
	case c == 0X2705:
		return true
	case (c >= 0X270A) && (c <= 0X270B):
		return true
	case c == 0X2728:
		return true
	case c == 0X274C:
		return true
	case c == 0X274E:
		return true
	case (c >= 0X2753) && (c <= 0X2755):
		return true
	case c == 0X2757:
		return true
	case (c >= 0X275F) && (c <= 0X2760):
		return true
	case (c >= 0X2795) && (c <= 0X2797):
		return true
	case c == 0X27B0:
		return true
	case (c >= 0X27BF) && (c <= 0X27CF):
		return true
	case (c >= 0X27EC) && (c <= 0X27EF):
		return true
	case (c >= 0X2B00) && (c <= 0X2E7F):
		return true
	case c == 0X2E9A:
		return true
	case (c >= 0X2EF4) && (c <= 0X2EFF):
		return true
	case (c >= 0X2FD6) && (c <= 0X2FEF):
		return true
	case (c >= 0X2FFC) && (c <= 0X2FFF):
		return true
	case c == 0X3040:
		return true
	case (c >= 0X3097) && (c <= 0X3098):
		return true
	case (c >= 0X3100) && (c <= 0X3104):
		return true
	case (c >= 0X312D) && (c <= 0X3130):
		return true
	case c == 0X318F:
		return true
	case (c >= 0X31B8) && (c <= 0X31EF):
		return true
	case (c >= 0X321D) && (c <= 0X321F):
		return true
	case (c >= 0X3244) && (c <= 0X3250):
		return true
	case (c >= 0X327C) && (c <= 0X327E):
		return true
	case (c >= 0X32CC) && (c <= 0X32CF):
		return true
	case c == 0X32FF:
		return true
	case (c >= 0X3377) && (c <= 0X337A):
		return true
	case (c >= 0X33DE) && (c <= 0X33DF):
		return true
	case c == 0X33FF:
		return true
	case (c >= 0X4DB6) && (c <= 0X4DFF):
		return true
	case (c >= 0X9FA6) && (c <= 0X9FFF):
		return true
	case (c >= 0XA48D) && (c <= 0XA48F):
		return true
	case (c >= 0XA4C7) && (c <= 0XABFF):
		return true
	case (c >= 0XD7A4) && (c <= 0XD7FF):
		return true
	case (c >= 0XFA2E) && (c <= 0XFA2F):
		return true
	case (c >= 0XFA6B) && (c <= 0XFAFF):
		return true
	case (c >= 0XFB07) && (c <= 0XFB12):
		return true
	case (c >= 0XFB18) && (c <= 0XFB1C):
		return true
	case c == 0XFB37:
		return true
	case c == 0XFB3D:
		return true
	case c == 0XFB3F:
		return true
	case c == 0XFB42:
		return true
	case c == 0XFB45:
		return true
	case (c >= 0XFBB2) && (c <= 0XFBD2):
		return true
	case (c >= 0XFD40) && (c <= 0XFD4F):
		return true
	case (c >= 0XFD90) && (c <= 0XFD91):
		return true
	case (c >= 0XFDC8) && (c <= 0XFDCF):
		return true
	case (c >= 0XFDFD) && (c <= 0XFDFF):
		return true
	case (c >= 0XFE10) && (c <= 0XFE1F):
		return true
	case (c >= 0XFE24) && (c <= 0XFE2F):
		return true
	case (c >= 0XFE47) && (c <= 0XFE48):
		return true
	case c == 0XFE53:
		return true
	case c == 0XFE67:
		return true
	case (c >= 0XFE6C) && (c <= 0XFE6F):
		return true
	case c == 0XFE75:
		return true
	case (c >= 0XFEFD) && (c <= 0XFEFE):
		return true
	case c == 0XFF00:
		return true
	case (c >= 0XFFBF) && (c <= 0XFFC1):
		return true
	case (c >= 0XFFC8) && (c <= 0XFFC9):
		return true
	case (c >= 0XFFD0) && (c <= 0XFFD1):
		return true
	case (c >= 0XFFD8) && (c <= 0XFFD9):
		return true
	case (c >= 0XFFDD) && (c <= 0XFFDF):
		return true
	case c == 0XFFE7:
		return true
	case (c >= 0XFFEF) && (c <= 0XFFF8):
		return true
	case (c >= 0X10000) && (c <= 0X102FF):
		return true
	case c == 0X1031F:
		return true
	case (c >= 0X10324) && (c <= 0X1032F):
		return true
	case (c >= 0X1034B) && (c <= 0X103FF):
		return true
	case (c >= 0X10426) && (c <= 0X10427):
		return true
	case (c >= 0X1044E) && (c <= 0X1CFFF):
		return true
	case (c >= 0X1D0F6) && (c <= 0X1D0FF):
		return true
	case (c >= 0X1D127) && (c <= 0X1D129):
		return true
	case (c >= 0X1D1DE) && (c <= 0X1D3FF):
		return true
	case c == 0X1D455:
		return true
	case c == 0X1D49D:
		return true
	case (c >= 0X1D4A0) && (c <= 0X1D4A1):
		return true
	case (c >= 0X1D4A3) && (c <= 0X1D4A4):
		return true
	case (c >= 0X1D4A7) && (c <= 0X1D4A8):
		return true
	case c == 0X1D4AD:
		return true
	case c == 0X1D4BA:
		return true
	case c == 0X1D4BC:
		return true
	case c == 0X1D4C1:
		return true
	case c == 0X1D4C4:
		return true
	case c == 0X1D506:
		return true
	case (c >= 0X1D50B) && (c <= 0X1D50C):
		return true
	case c == 0X1D515:
		return true
	case c == 0X1D51D:
		return true
	case c == 0X1D53A:
		return true
	case c == 0X1D53F:
		return true
	case c == 0X1D545:
		return true
	case (c >= 0X1D547) && (c <= 0X1D549):
		return true
	case c == 0X1D551:
		return true
	case (c >= 0X1D6A4) && (c <= 0X1D6A7):
		return true
	case (c >= 0X1D7CA) && (c <= 0X1D7CD):
		return true
	case (c >= 0X1D800) && (c <= 0X1FFFD):
		return true
	case (c >= 0X2A6D7) && (c <= 0X2F7FF):
		return true
	case (c >= 0X2FA1E) && (c <= 0X2FFFD):
		return true
	case (c >= 0X30000) && (c <= 0X3FFFD):
		return true
	case (c >= 0X40000) && (c <= 0X4FFFD):
		return true
	case (c >= 0X50000) && (c <= 0X5FFFD):
		return true
	case (c >= 0X60000) && (c <= 0X6FFFD):
		return true
	case (c >= 0X70000) && (c <= 0X7FFFD):
		return true
	case (c >= 0X80000) && (c <= 0X8FFFD):
		return true
	case (c >= 0X90000) && (c <= 0X9FFFD):
		return true
	case (c >= 0XA0000) && (c <= 0XAFFFD):
		return true
	case (c >= 0XB0000) && (c <= 0XBFFFD):
		return true
	case (c >= 0XC0000) && (c <= 0XCFFFD):
		return true
	case (c >= 0XD0000) && (c <= 0XDFFFD):
		return true
	case c == 0XE0000:
		return true
	case (c >= 0XE0002) && (c <= 0XE001F):
		return true
	case (c >= 0XE0080) && (c <= 0XEFFFD):
		return true

	//https://tools.ietf.org/html/rfc4518#section-2.4 RFC3454 Table C.3
	case (c >= 0XE000) && (c <= 0XF8FF):
		return true
	case (c >= 0XF0000) && (c <= 0XFFFFD):
		return true
	case (c >= 0X100000) && (c <= 0X10FFFD):
		return true

	//https://tools.ietf.org/html/rfc4518#section-2.4 RFC3454 Table C.4
	case (c >= 0XFDD0) && (c <= 0XFDEF):
		return true
	case (c >= 0XFFFE) && (c <= 0XFFFF):
		return true
	case (c >= 0X1FFFE) && (c <= 0X1FFFF):
		return true
	case (c >= 0X2FFFE) && (c <= 0X2FFFF):
		return true
	case (c >= 0X3FFFE) && (c <= 0X3FFFF):
		return true
	case (c >= 0X4FFFE) && (c <= 0X4FFFF):
		return true
	case (c >= 0X5FFFE) && (c <= 0X5FFFF):
		return true
	case (c >= 0X6FFFE) && (c <= 0X6FFFF):
		return true
	case (c >= 0X7FFFE) && (c <= 0X7FFFF):
		return true
	case (c >= 0X8FFFE) && (c <= 0X8FFFF):
		return true
	case (c >= 0X9FFFE) && (c <= 0X9FFFF):
		return true
	case (c >= 0XAFFFE) && (c <= 0XAFFFF):
		return true
	case (c >= 0XBFFFE) && (c <= 0XBFFFF):
		return true
	case (c >= 0XCFFFE) && (c <= 0XCFFFF):
		return true
	case (c >= 0XDFFFE) && (c <= 0XDFFFF):
		return true
	case (c >= 0XEFFFE) && (c <= 0XEFFFF):
		return true
	case (c >= 0XFFFFE) && (c <= 0XFFFFF):
		return true
	case (c >= 0X10FFFE) && (c <= 0X10FFFF):
		return true

	//https://tools.ietf.org/html/rfc4518#section-2.4 RFC3454 Table C.5
	case (c >= 0XD800) && (c <= 0XDFFF):
		return true

	//https://tools.ietf.org/html/rfc4518#section-2.4 RFC3454 Table C.8
	case c == 0X0340:
		return true
	case c == 0X0341:
		return true
	case c == 0X200E:
		return true
	case c == 0X200F:
		return true
	case c == 0X202A:
		return true
	case c == 0X202B:
		return true
	case c == 0X202C:
		return true
	case c == 0X202D:
		return true
	case c == 0X202E:
		return true
	case c == 0X206A:
		return true
	case c == 0X206B:
		return true
	case c == 0X206C:
		return true
	case c == 0X206D:
		return true
	case c == 0X206E:
		return true
	case c == 0X206F:
		return true

	//https://tools.ietf.org/html/rfc4518#section-2.4 The REPLACEMENT CHARACTER (U+FFFD)
	case c == 0XFFFD:
		return true

	default:
		return false
	}
}

//ApplyInsignificantSpaceHandling applies Insignificant Space Handling to src.
//src is attribute values or non-substring character.
//https://tools.ietf.org/html/rfc4518#section-2.6.1
func ApplyInsignificantSpaceHandling(src []rune) []rune {
	dst := make([]rune, 0, 0)
	words := splitToWords(src)
	l := len(words)
	if l == 0 {
		return []rune("\U00000020\U00000020")
	}

	for i := 0; i < l; i++ {
		if i == 0 {
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, words[0]...)
			continue
		}
		if i == l-1 {
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, words[l-1]...)
			continue
		}
		dst = append(dst, rune('\U00000020'))
		dst = append(dst, rune('\U00000020'))
		dst = append(dst, words[i]...)
	}
	dst = append(dst, rune('\U00000020'))
	return dst
}

//ApplyInsignificantSpaceHandlingInitial applies Insignificant Space Handling to substr.
//substr is substring assertion values and an initial substring.
//https://tools.ietf.org/html/rfc4518#section-2.6.1
func ApplyInsignificantSpaceHandlingInitial(substr []rune) []rune {
	dst := make([]rune, 0, 0)
	words := splitToWords(substr)
	l := len(words)
	if l == 0 {
		return []rune("\U00000020")
	}

	for i := 0; i < l; i++ {
		if i == 0 {
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, words[0]...)
			continue
		}
		if i == l-1 {
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, words[l-1]...)
			continue
		}
		dst = append(dst, rune('\U00000020'))
		dst = append(dst, rune('\U00000020'))
		dst = append(dst, words[i]...)
	}
	if isEndWithSpace(substr) {
		dst = append(dst, rune('\U00000020'))
	}
	return dst
}

//ApplyInsignificantSpaceHandlingFinal applies Insignificant Space Handling to substr.
//substr is substring assertion values and a final substring.
//https://tools.ietf.org/html/rfc4518#section-2.6.1
func ApplyInsignificantSpaceHandlingFinal(substr []rune) []rune {
	dst := make([]rune, 0, 0)
	words := splitToWords(substr)
	l := len(words)
	if l == 0 {
		return []rune("\U00000020")
	}

	for i := 0; i < l; i++ {
		if i == 0 {
			if isStartWithSpace(substr) {
				dst = append(dst, rune('\U00000020'))
			}
			dst = append(dst, words[0]...)
			continue
		}
		if i == l-1 {
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, words[l-1]...)
			continue
		}
		dst = append(dst, rune('\U00000020'))
		dst = append(dst, rune('\U00000020'))
		dst = append(dst, words[i]...)
	}
	dst = append(dst, rune('\U00000020'))
	return dst
}

//ApplyInsignificantSpaceHandlingAny applies Insignificant Space Handling to substr.
//substr is substring assertion values and an any substring.
//https://tools.ietf.org/html/rfc4518#section-2.6.1
func ApplyInsignificantSpaceHandlingAny(substr []rune) []rune {
	dst := make([]rune, 0, 0)
	words := splitToWords(substr)
	l := len(words)
	if l == 0 {
		return []rune("\U00000020")
	}

	for i := 0; i < l; i++ {
		if i == 0 {
			if isStartWithSpace(substr) {
				dst = append(dst, rune('\U00000020'))
			}
			dst = append(dst, words[0]...)
			continue
		}
		if i == l-1 {
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, rune('\U00000020'))
			dst = append(dst, words[l-1]...)
			continue
		}
		dst = append(dst, rune('\U00000020'))
		dst = append(dst, rune('\U00000020'))
		dst = append(dst, words[i]...)
	}
	if isEndWithSpace(substr) {
		dst = append(dst, rune('\U00000020'))
	}
	return dst
}

//ApplyNumericStringInsignificantCharacterHandling applies Insignificant Space Handling to src.
//https://tools.ietf.org/html/rfc4518#section-2.6.2
func ApplyNumericStringInsignificantCharacterHandling(src []rune) []rune {
	dst := make([]rune, 0, 0)
	words := splitToWords(src)
	l := len(words)
	if l == 0 {
		return []rune{}
	}
	for i := 0; i < l; i++ {
		dst = append(dst, words[i]...)
	}
	return dst
}

//ApplyTelephoneNumberInsignificantCharacterHandling applies Insignificant Space Handling to src.
//https://tools.ietf.org/html/rfc4518#section-2.6.3
func ApplyTelephoneNumberInsignificantCharacterHandling(src []rune) []rune {
	dst := make([]rune, 0, 0)
	words := splitToWords(src)
	l := len(words)
	if l == 0 {
		return []rune{}
	}
	for i := 0; i < l; i++ {
		dst = append(dst, removeHyphen(words[i])...)
	}
	return dst
}

//removeHyphen removes hyphen followed by no combination marks from src. hephen is defined at RFC 4518 section-2.6.3.
func removeHyphen(src []rune) []rune {
	dst := make([]rune, 0, 0)
	l := len(src)
	if l == 0 {
		return dst
	}
	if l == 1 {
		if !isHyphen(src[0]) {
			dst = append(dst, src[0])
		}
		return dst
	}
	for i := range src {
		if isHyphen(src[i]) && !isHyphenFollowedByCombinationMarks(src, i) {
			continue
		}
		dst = append(dst, src[i])
	}
	return dst
}

//isStartWithSpace reports whether src starts with space followed by no combining marks.
func isStartWithSpace(src []rune) bool {
	l := len(src)
	if l == 0 {
		return false
	}
	if l == 1 && isSpace(src[0]) {
		return true
	}
	if l >= 2 && isSpace(src[0]) && !isSpaceFollowedByCombinationMarks(src, 0) {
		return true
	}
	return false
}

//isEndWithSpace reports whether src ends with space.
func isEndWithSpace(src []rune) bool {
	l := len(src)
	if l == 0 {
		return false
	}
	if l == 1 && isSpace(src[0]) {
		return true
	}
	if l >= 2 && isSpace(src[l-1]) {
		return true
	}
	return false
}

//isHyphenFollowedByCombinationMarks reports whether character which specified by the index at src is kind of hyphen
//and is followed by combining marks.
func isHyphenFollowedByCombinationMarks(src []rune, index int) bool {
	//https://tools.ietf.org/html/rfc4518#section-2.6.3
	//a hyphen is defined to be a HYPHEN-MINUS (U+002D), ARMENIAN HYPHEN (U+058A), HYPHEN (U+2010),
	//	NON-BREAKING HYPHEN (U+2011), MINUS SIGN (U+2212), SMALL HYPHEN-MINUS
	//(U+FE63), or FULLWIDTH HYPHEN-MINUS (U+FF0D) code point followed by
	//no combining marks
	l := len(src)
	if index < 0 || (index > l-2) {
		return false
	}
	uc := src[index]
	//Check <HYPHEN><CHARACTER> sequence
	if isHyphen(uc) && isCombiningMark(src[index+1]) {
		return true
	}
	return false
}

//isHyphen reports whether c is hyphen. hephen is defined at RFC 4518 section-2.6.3.
func isHyphen(c rune) bool {
	//a hyphen is defined to be a HYPHEN-MINUS (U+002D), ARMENIAN HYPHEN (U+058A), HYPHEN (U+2010),
	//	NON-BREAKING HYPHEN (U+2011), MINUS SIGN (U+2212), SMALL HYPHEN-MINUS
	//(U+FE63), or FULLWIDTH HYPHEN-MINUS (U+FF0D) code point
	if c == 0X002D || c == 0X058A || c == 0X2010 || c == 0X2011 || c == 0X2212 || c == 0XFE63 || c == 0XFF0D {
		return true
	}
	return false
}

//splitToWords splits src into all words separated by the SPACE (U+0020) code point followed by no combining marks.
//and returns a slice of word.
//https://tools.ietf.org/html/rfc4518#section-2.6.1
func splitToWords(src []rune) [][]rune {
	dst := make([][]rune, 0, 0)
	word, rest := extractFirstWord(src)
	for {
		if len(word) == 0 && len(rest) == 0 {
			return dst
		}
		dst = append(dst, word)
		if len(rest) == 0 {
			break
		}
		word, rest = extractFirstWord(rest)
	}
	return dst
}

//extractFirstWord extracts first word from src and return the word and rest of src.
func extractFirstWord(src []rune) (word []rune, rest []rune) {
	l := len(src)
	word = make([]rune, 0, 0)
	rest = make([]rune, 0, 0)
	type extractedWord struct {
		startIndex int
		endIndex   int
	}

	w := extractedWord{-1, -1}
	//src is zero length
	if l == 0 {
		return word, rest
	}

	w.startIndex = findBeginningWordBoundaryIndex(src)
	w.endIndex = findEndWordBoundaryIndex(src)
	if w.startIndex != -1 {
		word = src[w.startIndex : w.endIndex+1]
		rest = src[w.endIndex+1:]
	}
	return word, rest
}

//isSpaceFollowedByCombinationMarks reports whether character which specified by the index at src is space(U+0020)
//and is followed by combining marks.
func isSpaceFollowedByCombinationMarks(src []rune, index int) bool {
	l := len(src)
	if index < 0 || (index > l-2) {
		return false
	}
	uc := src[index]
	//Check <SPACE><CHARACTER> sequence
	if isSpace(uc) && isCombiningMark(src[index+1]) {
		//https://tools.ietf.org/html/rfc4518#section-2.6.1
		//   For the purposes of this section, a space is defined to be the SPACE
		//   (U+0020) code point followed by no combining marks.
		return true
	}
	return false
}

//findBeginningWordBoundaryIndex returns the index of first letter of the word which is found first at src.
func findBeginningWordBoundaryIndex(src []rune) int {
	l := len(src)
	if l == 1 {
		if !isSpace(src[0]) {
			return 0
		}
		return -1
	}
	for i := range src {
		if i > l-1 {
			return -1
		}
		uc := src[i]
		if i == 0 {
			if !isSpace(uc) {
				return i
			}
			continue
		}
		//Check <SPACE><CHARACTER> sequence
		if isSpace(src[i-1]) && !isSpace(uc) {
			//the space is base character of combining character sequence therefore the space is word boundary.
			if isSpaceFollowedByCombinationMarks(src, i-1) {
				return i - 1
			}
			return i
		}
	}
	return -1
}

//findEndWordBoundaryIndex returns the index of last letter of the word which is found first at src.
func findEndWordBoundaryIndex(src []rune) int {
	l := len(src)
	if l == 1 {
		if !isSpace(src[0]) {
			return 0
		}
		return -1
	}

	for i := range src {
		if i == 0 {
			continue
		}
		uc := src[i]

		//Check <CHARACTER><SPACE> sequence
		if !isSpace(src[i-1]) && isSpace(uc) {
			//the space is base character of combining character sequence therefore this is not word boundary.
			if isSpaceFollowedByCombinationMarks(src, i) {
				continue
			}
			//Word boundary found.
			return i - 1
		}
	}
	//Word boundary is end of src.
	if !isSpace(src[l-1]) {
		return l - 1
	}
	return -1
}

//isSpace reports whether c is space(U+0020).
func isSpace(r rune) bool {
	if r == '\U00000020' {
		return true
	}
	return false
}

//isCombiningMark reports whether c is combining marks. combining marks is defined at at RFC 4518 appendix-A.
//https://tools.ietf.org/html/rfc4518#appendix-A
func isCombiningMark(c rune) bool {
	//https://tools.ietf.org/html/rfc4518 Appendix A.  Combining Marks
	switch {
	case (c >= 0X0300) && (c <= 0X034F):
		return true
	case (c >= 0X0360) && (c <= 0X036F):
		return true
	case (c >= 0X0483) && (c <= 0X0486):
		return true
	case (c >= 0X0488) && (c <= 0X0489):
		return true
	case (c >= 0X0591) && (c <= 0X05A1):
		return true
	case (c >= 0X05A3) && (c <= 0X05B9):
		return true
	case (c >= 0X05BB) && (c <= 0X05BC):
		return true
	case c == 0X05BF:
		return true
	case (c >= 0X05C1) && (c <= 0X05C2):
		return true
	case c == 0X05C4:
		return true
	case (c >= 0X064B) && (c <= 0X0655):
		return true
	case c == 0X0670:
		return true
	case (c >= 0X06D6) && (c <= 0X06DC):
		return true
	case (c >= 0X06DE) && (c <= 0X06E4):
		return true
	case (c >= 0X06E7) && (c <= 0X06E8):
		return true
	case (c >= 0X06EA) && (c <= 0X06ED):
		return true
	case c == 0X0711:
		return true
	case (c >= 0X0730) && (c <= 0X074A):
		return true
	case (c >= 0X07A6) && (c <= 0X07B0):
		return true
	case (c >= 0X0901) && (c <= 0X0903):
		return true
	case c == 0X093C:
		return true
	case (c >= 0X093E) && (c <= 0X094F):
		return true
	case (c >= 0X0951) && (c <= 0X0954):
		return true
	case (c >= 0X0962) && (c <= 0X0963):
		return true
	case (c >= 0X0981) && (c <= 0X0983):
		return true
	case c == 0X09BC:
		return true
	case (c >= 0X09BE) && (c <= 0X09C4):
		return true
	case (c >= 0X09C7) && (c <= 0X09C8):
		return true
	case (c >= 0X09CB) && (c <= 0X09CD):
		return true
	case c == 0X09D7:
		return true
	case (c >= 0X09E2) && (c <= 0X09E3):
		return true
	case c == 0X0A02:
		return true
	case c == 0X0A3C:
		return true
	case (c >= 0X0A3E) && (c <= 0X0A42):
		return true
	case (c >= 0X0A47) && (c <= 0X0A48):
		return true
	case (c >= 0X0A4B) && (c <= 0X0A4D):
		return true
	case (c >= 0X0A70) && (c <= 0X0A71):
		return true
	case (c >= 0X0A81) && (c <= 0X0A83):
		return true
	case c == 0X0ABC:
		return true
	case (c >= 0X0ABE) && (c <= 0X0AC5):
		return true
	case (c >= 0X0AC7) && (c <= 0X0AC9):
		return true
	case (c >= 0X0ACB) && (c <= 0X0ACD):
		return true
	case (c >= 0X0B01) && (c <= 0X0B03):
		return true
	case c == 0X0B3C:
		return true
	case (c >= 0X0B3E) && (c <= 0X0B43):
		return true
	case (c >= 0X0B47) && (c <= 0X0B48):
		return true
	case (c >= 0X0B4B) && (c <= 0X0B4D):
		return true
	case (c >= 0X0B56) && (c <= 0X0B57):
		return true
	case c == 0X0B82:
		return true
	case (c >= 0X0BBE) && (c <= 0X0BC2):
		return true
	case (c >= 0X0BC6) && (c <= 0X0BC8):
		return true
	case (c >= 0X0BCA) && (c <= 0X0BCD):
		return true
	case c == 0X0BD7:
		return true
	case (c >= 0X0C01) && (c <= 0X0C03):
		return true
	case (c >= 0X0C3E) && (c <= 0X0C44):
		return true
	case (c >= 0X0C46) && (c <= 0X0C48):
		return true
	case (c >= 0X0C4A) && (c <= 0X0C4D):
		return true
	case (c >= 0X0C55) && (c <= 0X0C56):
		return true
	case (c >= 0X0C82) && (c <= 0X0C83):
		return true
	case (c >= 0X0CBE) && (c <= 0X0CC4):
		return true
	case (c >= 0X0CC6) && (c <= 0X0CC8):
		return true
	case (c >= 0X0CCA) && (c <= 0X0CCD):
		return true
	case (c >= 0X0CD5) && (c <= 0X0CD6):
		return true
	case (c >= 0X0D02) && (c <= 0X0D03):
		return true
	case (c >= 0X0D3E) && (c <= 0X0D43):
		return true
	case (c >= 0X0D46) && (c <= 0X0D48):
		return true
	case (c >= 0X0D4A) && (c <= 0X0D4D):
		return true
	case c == 0X0D57:
		return true
	case (c >= 0X0D82) && (c <= 0X0D83):
		return true
	case c == 0X0DCA:
		return true
	case (c >= 0X0DCF) && (c <= 0X0DD4):
		return true
	case c == 0X0DD6:
		return true
	case (c >= 0X0DD8) && (c <= 0X0DDF):
		return true
	case (c >= 0X0DF2) && (c <= 0X0DF3):
		return true
	case c == 0X0E31:
		return true
	case (c >= 0X0E34) && (c <= 0X0E3A):
		return true
	case (c >= 0X0E47) && (c <= 0X0E4E):
		return true
	case c == 0X0EB1:
		return true
	case (c >= 0X0EB4) && (c <= 0X0EB9):
		return true
	case (c >= 0X0EBB) && (c <= 0X0EBC):
		return true
	case (c >= 0X0EC8) && (c <= 0X0ECD):
		return true
	case (c >= 0X0F18) && (c <= 0X0F19):
		return true
	case c == 0X0F35:
		return true
	case c == 0X0F37:
		return true
	case c == 0X0F39:
		return true
	case (c >= 0X0F3E) && (c <= 0X0F3F):
		return true
	case (c >= 0X0F71) && (c <= 0X0F84):
		return true
	case (c >= 0X0F86) && (c <= 0X0F87):
		return true
	case (c >= 0X0F90) && (c <= 0X0F97):
		return true
	case (c >= 0X0F99) && (c <= 0X0FBC):
		return true
	case c == 0X0FC6:
		return true
	case (c >= 0X102C) && (c <= 0X1032):
		return true
	case (c >= 0X1036) && (c <= 0X1039):
		return true
	case (c >= 0X1056) && (c <= 0X1059):
		return true
	case (c >= 0X1712) && (c <= 0X1714):
		return true
	case (c >= 0X1732) && (c <= 0X1734):
		return true
	case (c >= 0X1752) && (c <= 0X1753):
		return true
	case (c >= 0X1772) && (c <= 0X1773):
		return true
	case (c >= 0X17B4) && (c <= 0X17D3):
		return true
	case (c >= 0X180B) && (c <= 0X180D):
		return true
	case c == 0X18A9:
		return true
	case (c >= 0X20D0) && (c <= 0X20EA):
		return true
	case (c >= 0X302A) && (c <= 0X302F):
		return true
	case (c >= 0X3099) && (c <= 0X309A):
		return true
	case c == 0XFB1E:
		return true
	case (c >= 0XFE00) && (c <= 0XFE0F):
		return true
	case (c >= 0XFE20) && (c <= 0XFE23):
		return true
	case (c >= 0X1D165) && (c <= 0X1D169):
		return true
	case (c >= 0X1D16D) && (c <= 0X1D172):
		return true
	case (c >= 0X1D17B) && (c <= 0X1D182):
		return true
	case (c >= 0X1D185) && (c <= 0X1D18B):
		return true
	case (c >= 0X1D1AA) && (c <= 0X1D1AD):
		return true
	default:
		return false
	}
}

func init() {
	b2Table[0X0041] = []rune{0X0061}
	b2Table[0X0042] = []rune{0X0062}
	b2Table[0X0043] = []rune{0X0063}
	b2Table[0X0044] = []rune{0X0064}
	b2Table[0X0045] = []rune{0X0065}
	b2Table[0X0046] = []rune{0X0066}
	b2Table[0X0047] = []rune{0X0067}
	b2Table[0X0048] = []rune{0X0068}
	b2Table[0X0049] = []rune{0X0069}
	b2Table[0X004A] = []rune{0X006A}
	b2Table[0X004B] = []rune{0X006B}
	b2Table[0X004C] = []rune{0X006C}
	b2Table[0X004D] = []rune{0X006D}
	b2Table[0X004E] = []rune{0X006E}
	b2Table[0X004F] = []rune{0X006F}
	b2Table[0X0050] = []rune{0X0070}
	b2Table[0X0051] = []rune{0X0071}
	b2Table[0X0052] = []rune{0X0072}
	b2Table[0X0053] = []rune{0X0073}
	b2Table[0X0054] = []rune{0X0074}
	b2Table[0X0055] = []rune{0X0075}
	b2Table[0X0056] = []rune{0X0076}
	b2Table[0X0057] = []rune{0X0077}
	b2Table[0X0058] = []rune{0X0078}
	b2Table[0X0059] = []rune{0X0079}
	b2Table[0X005A] = []rune{0X007A}
	b2Table[0X00B5] = []rune{0X03BC}
	b2Table[0X00C0] = []rune{0X00E0}
	b2Table[0X00C1] = []rune{0X00E1}
	b2Table[0X00C2] = []rune{0X00E2}
	b2Table[0X00C3] = []rune{0X00E3}
	b2Table[0X00C4] = []rune{0X00E4}
	b2Table[0X00C5] = []rune{0X00E5}
	b2Table[0X00C6] = []rune{0X00E6}
	b2Table[0X00C7] = []rune{0X00E7}
	b2Table[0X00C8] = []rune{0X00E8}
	b2Table[0X00C9] = []rune{0X00E9}
	b2Table[0X00CA] = []rune{0X00EA}
	b2Table[0X00CB] = []rune{0X00EB}
	b2Table[0X00CC] = []rune{0X00EC}
	b2Table[0X00CD] = []rune{0X00ED}
	b2Table[0X00CE] = []rune{0X00EE}
	b2Table[0X00CF] = []rune{0X00EF}
	b2Table[0X00D0] = []rune{0X00F0}
	b2Table[0X00D1] = []rune{0X00F1}
	b2Table[0X00D2] = []rune{0X00F2}
	b2Table[0X00D3] = []rune{0X00F3}
	b2Table[0X00D4] = []rune{0X00F4}
	b2Table[0X00D5] = []rune{0X00F5}
	b2Table[0X00D6] = []rune{0X00F6}
	b2Table[0X00D8] = []rune{0X00F8}
	b2Table[0X00D9] = []rune{0X00F9}
	b2Table[0X00DA] = []rune{0X00FA}
	b2Table[0X00DB] = []rune{0X00FB}
	b2Table[0X00DC] = []rune{0X00FC}
	b2Table[0X00DD] = []rune{0X00FD}
	b2Table[0X00DE] = []rune{0X00FE}
	b2Table[0X00DF] = []rune{0X0073, 0X0073}
	b2Table[0X0100] = []rune{0X0101}
	b2Table[0X0102] = []rune{0X0103}
	b2Table[0X0104] = []rune{0X0105}
	b2Table[0X0106] = []rune{0X0107}
	b2Table[0X0108] = []rune{0X0109}
	b2Table[0X010A] = []rune{0X010B}
	b2Table[0X010C] = []rune{0X010D}
	b2Table[0X010E] = []rune{0X010F}
	b2Table[0X0110] = []rune{0X0111}
	b2Table[0X0112] = []rune{0X0113}
	b2Table[0X0114] = []rune{0X0115}
	b2Table[0X0116] = []rune{0X0117}
	b2Table[0X0118] = []rune{0X0119}
	b2Table[0X011A] = []rune{0X011B}
	b2Table[0X011C] = []rune{0X011D}
	b2Table[0X011E] = []rune{0X011F}
	b2Table[0X0120] = []rune{0X0121}
	b2Table[0X0122] = []rune{0X0123}
	b2Table[0X0124] = []rune{0X0125}
	b2Table[0X0126] = []rune{0X0127}
	b2Table[0X0128] = []rune{0X0129}
	b2Table[0X012A] = []rune{0X012B}
	b2Table[0X012C] = []rune{0X012D}
	b2Table[0X012E] = []rune{0X012F}
	b2Table[0X0130] = []rune{0X0069, 0X0307}
	b2Table[0X0132] = []rune{0X0133}
	b2Table[0X0134] = []rune{0X0135}
	b2Table[0X0136] = []rune{0X0137}
	b2Table[0X0139] = []rune{0X013A}
	b2Table[0X013B] = []rune{0X013C}
	b2Table[0X013D] = []rune{0X013E}
	b2Table[0X013F] = []rune{0X0140}
	b2Table[0X0141] = []rune{0X0142}
	b2Table[0X0143] = []rune{0X0144}
	b2Table[0X0145] = []rune{0X0146}
	b2Table[0X0147] = []rune{0X0148}
	b2Table[0X0149] = []rune{0X02BC, 0X006E}
	b2Table[0X014A] = []rune{0X014B}
	b2Table[0X014C] = []rune{0X014D}
	b2Table[0X014E] = []rune{0X014F}
	b2Table[0X0150] = []rune{0X0151}
	b2Table[0X0152] = []rune{0X0153}
	b2Table[0X0154] = []rune{0X0155}
	b2Table[0X0156] = []rune{0X0157}
	b2Table[0X0158] = []rune{0X0159}
	b2Table[0X015A] = []rune{0X015B}
	b2Table[0X015C] = []rune{0X015D}
	b2Table[0X015E] = []rune{0X015F}
	b2Table[0X0160] = []rune{0X0161}
	b2Table[0X0162] = []rune{0X0163}
	b2Table[0X0164] = []rune{0X0165}
	b2Table[0X0166] = []rune{0X0167}
	b2Table[0X0168] = []rune{0X0169}
	b2Table[0X016A] = []rune{0X016B}
	b2Table[0X016C] = []rune{0X016D}
	b2Table[0X016E] = []rune{0X016F}
	b2Table[0X0170] = []rune{0X0171}
	b2Table[0X0172] = []rune{0X0173}
	b2Table[0X0174] = []rune{0X0175}
	b2Table[0X0176] = []rune{0X0177}
	b2Table[0X0178] = []rune{0X00FF}
	b2Table[0X0179] = []rune{0X017A}
	b2Table[0X017B] = []rune{0X017C}
	b2Table[0X017D] = []rune{0X017E}
	b2Table[0X017F] = []rune{0X0073}
	b2Table[0X0181] = []rune{0X0253}
	b2Table[0X0182] = []rune{0X0183}
	b2Table[0X0184] = []rune{0X0185}
	b2Table[0X0186] = []rune{0X0254}
	b2Table[0X0187] = []rune{0X0188}
	b2Table[0X0189] = []rune{0X0256}
	b2Table[0X018A] = []rune{0X0257}
	b2Table[0X018B] = []rune{0X018C}
	b2Table[0X018E] = []rune{0X01DD}
	b2Table[0X018F] = []rune{0X0259}
	b2Table[0X0190] = []rune{0X025B}
	b2Table[0X0191] = []rune{0X0192}
	b2Table[0X0193] = []rune{0X0260}
	b2Table[0X0194] = []rune{0X0263}
	b2Table[0X0196] = []rune{0X0269}
	b2Table[0X0197] = []rune{0X0268}
	b2Table[0X0198] = []rune{0X0199}
	b2Table[0X019C] = []rune{0X026F}
	b2Table[0X019D] = []rune{0X0272}
	b2Table[0X019F] = []rune{0X0275}
	b2Table[0X01A0] = []rune{0X01A1}
	b2Table[0X01A2] = []rune{0X01A3}
	b2Table[0X01A4] = []rune{0X01A5}
	b2Table[0X01A6] = []rune{0X0280}
	b2Table[0X01A7] = []rune{0X01A8}
	b2Table[0X01A9] = []rune{0X0283}
	b2Table[0X01AC] = []rune{0X01AD}
	b2Table[0X01AE] = []rune{0X0288}
	b2Table[0X01AF] = []rune{0X01B0}
	b2Table[0X01B1] = []rune{0X028A}
	b2Table[0X01B2] = []rune{0X028B}
	b2Table[0X01B3] = []rune{0X01B4}
	b2Table[0X01B5] = []rune{0X01B6}
	b2Table[0X01B7] = []rune{0X0292}
	b2Table[0X01B8] = []rune{0X01B9}
	b2Table[0X01BC] = []rune{0X01BD}
	b2Table[0X01C4] = []rune{0X01C6}
	b2Table[0X01C5] = []rune{0X01C6}
	b2Table[0X01C7] = []rune{0X01C9}
	b2Table[0X01C8] = []rune{0X01C9}
	b2Table[0X01CA] = []rune{0X01CC}
	b2Table[0X01CB] = []rune{0X01CC}
	b2Table[0X01CD] = []rune{0X01CE}
	b2Table[0X01CF] = []rune{0X01D0}
	b2Table[0X01D1] = []rune{0X01D2}
	b2Table[0X01D3] = []rune{0X01D4}
	b2Table[0X01D5] = []rune{0X01D6}
	b2Table[0X01D7] = []rune{0X01D8}
	b2Table[0X01D9] = []rune{0X01DA}
	b2Table[0X01DB] = []rune{0X01DC}
	b2Table[0X01DE] = []rune{0X01DF}
	b2Table[0X01E0] = []rune{0X01E1}
	b2Table[0X01E2] = []rune{0X01E3}
	b2Table[0X01E4] = []rune{0X01E5}
	b2Table[0X01E6] = []rune{0X01E7}
	b2Table[0X01E8] = []rune{0X01E9}
	b2Table[0X01EA] = []rune{0X01EB}
	b2Table[0X01EC] = []rune{0X01ED}
	b2Table[0X01EE] = []rune{0X01EF}
	b2Table[0X01F0] = []rune{0X006A, 0X030C}
	b2Table[0X01F1] = []rune{0X01F3}
	b2Table[0X01F2] = []rune{0X01F3}
	b2Table[0X01F4] = []rune{0X01F5}
	b2Table[0X01F6] = []rune{0X0195}
	b2Table[0X01F7] = []rune{0X01BF}
	b2Table[0X01F8] = []rune{0X01F9}
	b2Table[0X01FA] = []rune{0X01FB}
	b2Table[0X01FC] = []rune{0X01FD}
	b2Table[0X01FE] = []rune{0X01FF}
	b2Table[0X0200] = []rune{0X0201}
	b2Table[0X0202] = []rune{0X0203}
	b2Table[0X0204] = []rune{0X0205}
	b2Table[0X0206] = []rune{0X0207}
	b2Table[0X0208] = []rune{0X0209}
	b2Table[0X020A] = []rune{0X020B}
	b2Table[0X020C] = []rune{0X020D}
	b2Table[0X020E] = []rune{0X020F}
	b2Table[0X0210] = []rune{0X0211}
	b2Table[0X0212] = []rune{0X0213}
	b2Table[0X0214] = []rune{0X0215}
	b2Table[0X0216] = []rune{0X0217}
	b2Table[0X0218] = []rune{0X0219}
	b2Table[0X021A] = []rune{0X021B}
	b2Table[0X021C] = []rune{0X021D}
	b2Table[0X021E] = []rune{0X021F}
	b2Table[0X0220] = []rune{0X019E}
	b2Table[0X0222] = []rune{0X0223}
	b2Table[0X0224] = []rune{0X0225}
	b2Table[0X0226] = []rune{0X0227}
	b2Table[0X0228] = []rune{0X0229}
	b2Table[0X022A] = []rune{0X022B}
	b2Table[0X022C] = []rune{0X022D}
	b2Table[0X022E] = []rune{0X022F}
	b2Table[0X0230] = []rune{0X0231}
	b2Table[0X0232] = []rune{0X0233}
	b2Table[0X0345] = []rune{0X03B9}
	b2Table[0X037A] = []rune{0X0020, 0X03B9}
	b2Table[0X0386] = []rune{0X03AC}
	b2Table[0X0388] = []rune{0X03AD}
	b2Table[0X0389] = []rune{0X03AE}
	b2Table[0X038A] = []rune{0X03AF}
	b2Table[0X038C] = []rune{0X03CC}
	b2Table[0X038E] = []rune{0X03CD}
	b2Table[0X038F] = []rune{0X03CE}
	b2Table[0X0390] = []rune{0X03B9, 0X0308, 0X0301}
	b2Table[0X0391] = []rune{0X03B1}
	b2Table[0X0392] = []rune{0X03B2}
	b2Table[0X0393] = []rune{0X03B3}
	b2Table[0X0394] = []rune{0X03B4}
	b2Table[0X0395] = []rune{0X03B5}
	b2Table[0X0396] = []rune{0X03B6}
	b2Table[0X0397] = []rune{0X03B7}
	b2Table[0X0398] = []rune{0X03B8}
	b2Table[0X0399] = []rune{0X03B9}
	b2Table[0X039A] = []rune{0X03BA}
	b2Table[0X039B] = []rune{0X03BB}
	b2Table[0X039C] = []rune{0X03BC}
	b2Table[0X039D] = []rune{0X03BD}
	b2Table[0X039E] = []rune{0X03BE}
	b2Table[0X039F] = []rune{0X03BF}
	b2Table[0X03A0] = []rune{0X03C0}
	b2Table[0X03A1] = []rune{0X03C1}
	b2Table[0X03A3] = []rune{0X03C3}
	b2Table[0X03A4] = []rune{0X03C4}
	b2Table[0X03A5] = []rune{0X03C5}
	b2Table[0X03A6] = []rune{0X03C6}
	b2Table[0X03A7] = []rune{0X03C7}
	b2Table[0X03A8] = []rune{0X03C8}
	b2Table[0X03A9] = []rune{0X03C9}
	b2Table[0X03AA] = []rune{0X03CA}
	b2Table[0X03AB] = []rune{0X03CB}
	b2Table[0X03B0] = []rune{0X03C5, 0X0308, 0X0301}
	b2Table[0X03C2] = []rune{0X03C3}
	b2Table[0X03D0] = []rune{0X03B2}
	b2Table[0X03D1] = []rune{0X03B8}
	b2Table[0X03D2] = []rune{0X03C5}
	b2Table[0X03D3] = []rune{0X03CD}
	b2Table[0X03D4] = []rune{0X03CB}
	b2Table[0X03D5] = []rune{0X03C6}
	b2Table[0X03D6] = []rune{0X03C0}
	b2Table[0X03D8] = []rune{0X03D9}
	b2Table[0X03DA] = []rune{0X03DB}
	b2Table[0X03DC] = []rune{0X03DD}
	b2Table[0X03DE] = []rune{0X03DF}
	b2Table[0X03E0] = []rune{0X03E1}
	b2Table[0X03E2] = []rune{0X03E3}
	b2Table[0X03E4] = []rune{0X03E5}
	b2Table[0X03E6] = []rune{0X03E7}
	b2Table[0X03E8] = []rune{0X03E9}
	b2Table[0X03EA] = []rune{0X03EB}
	b2Table[0X03EC] = []rune{0X03ED}
	b2Table[0X03EE] = []rune{0X03EF}
	b2Table[0X03F0] = []rune{0X03BA}
	b2Table[0X03F1] = []rune{0X03C1}
	b2Table[0X03F2] = []rune{0X03C3}
	b2Table[0X03F4] = []rune{0X03B8}
	b2Table[0X03F5] = []rune{0X03B5}
	b2Table[0X0400] = []rune{0X0450}
	b2Table[0X0401] = []rune{0X0451}
	b2Table[0X0402] = []rune{0X0452}
	b2Table[0X0403] = []rune{0X0453}
	b2Table[0X0404] = []rune{0X0454}
	b2Table[0X0405] = []rune{0X0455}
	b2Table[0X0406] = []rune{0X0456}
	b2Table[0X0407] = []rune{0X0457}
	b2Table[0X0408] = []rune{0X0458}
	b2Table[0X0409] = []rune{0X0459}
	b2Table[0X040A] = []rune{0X045A}
	b2Table[0X040B] = []rune{0X045B}
	b2Table[0X040C] = []rune{0X045C}
	b2Table[0X040D] = []rune{0X045D}
	b2Table[0X040E] = []rune{0X045E}
	b2Table[0X040F] = []rune{0X045F}
	b2Table[0X0410] = []rune{0X0430}
	b2Table[0X0411] = []rune{0X0431}
	b2Table[0X0412] = []rune{0X0432}
	b2Table[0X0413] = []rune{0X0433}
	b2Table[0X0414] = []rune{0X0434}
	b2Table[0X0415] = []rune{0X0435}
	b2Table[0X0416] = []rune{0X0436}
	b2Table[0X0417] = []rune{0X0437}
	b2Table[0X0418] = []rune{0X0438}
	b2Table[0X0419] = []rune{0X0439}
	b2Table[0X041A] = []rune{0X043A}
	b2Table[0X041B] = []rune{0X043B}
	b2Table[0X041C] = []rune{0X043C}
	b2Table[0X041D] = []rune{0X043D}
	b2Table[0X041E] = []rune{0X043E}
	b2Table[0X041F] = []rune{0X043F}
	b2Table[0X0420] = []rune{0X0440}
	b2Table[0X0421] = []rune{0X0441}
	b2Table[0X0422] = []rune{0X0442}
	b2Table[0X0423] = []rune{0X0443}
	b2Table[0X0424] = []rune{0X0444}
	b2Table[0X0425] = []rune{0X0445}
	b2Table[0X0426] = []rune{0X0446}
	b2Table[0X0427] = []rune{0X0447}
	b2Table[0X0428] = []rune{0X0448}
	b2Table[0X0429] = []rune{0X0449}
	b2Table[0X042A] = []rune{0X044A}
	b2Table[0X042B] = []rune{0X044B}
	b2Table[0X042C] = []rune{0X044C}
	b2Table[0X042D] = []rune{0X044D}
	b2Table[0X042E] = []rune{0X044E}
	b2Table[0X042F] = []rune{0X044F}
	b2Table[0X0460] = []rune{0X0461}
	b2Table[0X0462] = []rune{0X0463}
	b2Table[0X0464] = []rune{0X0465}
	b2Table[0X0466] = []rune{0X0467}
	b2Table[0X0468] = []rune{0X0469}
	b2Table[0X046A] = []rune{0X046B}
	b2Table[0X046C] = []rune{0X046D}
	b2Table[0X046E] = []rune{0X046F}
	b2Table[0X0470] = []rune{0X0471}
	b2Table[0X0472] = []rune{0X0473}
	b2Table[0X0474] = []rune{0X0475}
	b2Table[0X0476] = []rune{0X0477}
	b2Table[0X0478] = []rune{0X0479}
	b2Table[0X047A] = []rune{0X047B}
	b2Table[0X047C] = []rune{0X047D}
	b2Table[0X047E] = []rune{0X047F}
	b2Table[0X0480] = []rune{0X0481}
	b2Table[0X048A] = []rune{0X048B}
	b2Table[0X048C] = []rune{0X048D}
	b2Table[0X048E] = []rune{0X048F}
	b2Table[0X0490] = []rune{0X0491}
	b2Table[0X0492] = []rune{0X0493}
	b2Table[0X0494] = []rune{0X0495}
	b2Table[0X0496] = []rune{0X0497}
	b2Table[0X0498] = []rune{0X0499}
	b2Table[0X049A] = []rune{0X049B}
	b2Table[0X049C] = []rune{0X049D}
	b2Table[0X049E] = []rune{0X049F}
	b2Table[0X04A0] = []rune{0X04A1}
	b2Table[0X04A2] = []rune{0X04A3}
	b2Table[0X04A4] = []rune{0X04A5}
	b2Table[0X04A6] = []rune{0X04A7}
	b2Table[0X04A8] = []rune{0X04A9}
	b2Table[0X04AA] = []rune{0X04AB}
	b2Table[0X04AC] = []rune{0X04AD}
	b2Table[0X04AE] = []rune{0X04AF}
	b2Table[0X04B0] = []rune{0X04B1}
	b2Table[0X04B2] = []rune{0X04B3}
	b2Table[0X04B4] = []rune{0X04B5}
	b2Table[0X04B6] = []rune{0X04B7}
	b2Table[0X04B8] = []rune{0X04B9}
	b2Table[0X04BA] = []rune{0X04BB}
	b2Table[0X04BC] = []rune{0X04BD}
	b2Table[0X04BE] = []rune{0X04BF}
	b2Table[0X04C1] = []rune{0X04C2}
	b2Table[0X04C3] = []rune{0X04C4}
	b2Table[0X04C5] = []rune{0X04C6}
	b2Table[0X04C7] = []rune{0X04C8}
	b2Table[0X04C9] = []rune{0X04CA}
	b2Table[0X04CB] = []rune{0X04CC}
	b2Table[0X04CD] = []rune{0X04CE}
	b2Table[0X04D0] = []rune{0X04D1}
	b2Table[0X04D2] = []rune{0X04D3}
	b2Table[0X04D4] = []rune{0X04D5}
	b2Table[0X04D6] = []rune{0X04D7}
	b2Table[0X04D8] = []rune{0X04D9}
	b2Table[0X04DA] = []rune{0X04DB}
	b2Table[0X04DC] = []rune{0X04DD}
	b2Table[0X04DE] = []rune{0X04DF}
	b2Table[0X04E0] = []rune{0X04E1}
	b2Table[0X04E2] = []rune{0X04E3}
	b2Table[0X04E4] = []rune{0X04E5}
	b2Table[0X04E6] = []rune{0X04E7}
	b2Table[0X04E8] = []rune{0X04E9}
	b2Table[0X04EA] = []rune{0X04EB}
	b2Table[0X04EC] = []rune{0X04ED}
	b2Table[0X04EE] = []rune{0X04EF}
	b2Table[0X04F0] = []rune{0X04F1}
	b2Table[0X04F2] = []rune{0X04F3}
	b2Table[0X04F4] = []rune{0X04F5}
	b2Table[0X04F8] = []rune{0X04F9}
	b2Table[0X0500] = []rune{0X0501}
	b2Table[0X0502] = []rune{0X0503}
	b2Table[0X0504] = []rune{0X0505}
	b2Table[0X0506] = []rune{0X0507}
	b2Table[0X0508] = []rune{0X0509}
	b2Table[0X050A] = []rune{0X050B}
	b2Table[0X050C] = []rune{0X050D}
	b2Table[0X050E] = []rune{0X050F}
	b2Table[0X0531] = []rune{0X0561}
	b2Table[0X0532] = []rune{0X0562}
	b2Table[0X0533] = []rune{0X0563}
	b2Table[0X0534] = []rune{0X0564}
	b2Table[0X0535] = []rune{0X0565}
	b2Table[0X0536] = []rune{0X0566}
	b2Table[0X0537] = []rune{0X0567}
	b2Table[0X0538] = []rune{0X0568}
	b2Table[0X0539] = []rune{0X0569}
	b2Table[0X053A] = []rune{0X056A}
	b2Table[0X053B] = []rune{0X056B}
	b2Table[0X053C] = []rune{0X056C}
	b2Table[0X053D] = []rune{0X056D}
	b2Table[0X053E] = []rune{0X056E}
	b2Table[0X053F] = []rune{0X056F}
	b2Table[0X0540] = []rune{0X0570}
	b2Table[0X0541] = []rune{0X0571}
	b2Table[0X0542] = []rune{0X0572}
	b2Table[0X0543] = []rune{0X0573}
	b2Table[0X0544] = []rune{0X0574}
	b2Table[0X0545] = []rune{0X0575}
	b2Table[0X0546] = []rune{0X0576}
	b2Table[0X0547] = []rune{0X0577}
	b2Table[0X0548] = []rune{0X0578}
	b2Table[0X0549] = []rune{0X0579}
	b2Table[0X054A] = []rune{0X057A}
	b2Table[0X054B] = []rune{0X057B}
	b2Table[0X054C] = []rune{0X057C}
	b2Table[0X054D] = []rune{0X057D}
	b2Table[0X054E] = []rune{0X057E}
	b2Table[0X054F] = []rune{0X057F}
	b2Table[0X0550] = []rune{0X0580}
	b2Table[0X0551] = []rune{0X0581}
	b2Table[0X0552] = []rune{0X0582}
	b2Table[0X0553] = []rune{0X0583}
	b2Table[0X0554] = []rune{0X0584}
	b2Table[0X0555] = []rune{0X0585}
	b2Table[0X0556] = []rune{0X0586}
	b2Table[0X0587] = []rune{0X0565, 0X0582}
	b2Table[0X1E00] = []rune{0X1E01}
	b2Table[0X1E02] = []rune{0X1E03}
	b2Table[0X1E04] = []rune{0X1E05}
	b2Table[0X1E06] = []rune{0X1E07}
	b2Table[0X1E08] = []rune{0X1E09}
	b2Table[0X1E0A] = []rune{0X1E0B}
	b2Table[0X1E0C] = []rune{0X1E0D}
	b2Table[0X1E0E] = []rune{0X1E0F}
	b2Table[0X1E10] = []rune{0X1E11}
	b2Table[0X1E12] = []rune{0X1E13}
	b2Table[0X1E14] = []rune{0X1E15}
	b2Table[0X1E16] = []rune{0X1E17}
	b2Table[0X1E18] = []rune{0X1E19}
	b2Table[0X1E1A] = []rune{0X1E1B}
	b2Table[0X1E1C] = []rune{0X1E1D}
	b2Table[0X1E1E] = []rune{0X1E1F}
	b2Table[0X1E20] = []rune{0X1E21}
	b2Table[0X1E22] = []rune{0X1E23}
	b2Table[0X1E24] = []rune{0X1E25}
	b2Table[0X1E26] = []rune{0X1E27}
	b2Table[0X1E28] = []rune{0X1E29}
	b2Table[0X1E2A] = []rune{0X1E2B}
	b2Table[0X1E2C] = []rune{0X1E2D}
	b2Table[0X1E2E] = []rune{0X1E2F}
	b2Table[0X1E30] = []rune{0X1E31}
	b2Table[0X1E32] = []rune{0X1E33}
	b2Table[0X1E34] = []rune{0X1E35}
	b2Table[0X1E36] = []rune{0X1E37}
	b2Table[0X1E38] = []rune{0X1E39}
	b2Table[0X1E3A] = []rune{0X1E3B}
	b2Table[0X1E3C] = []rune{0X1E3D}
	b2Table[0X1E3E] = []rune{0X1E3F}
	b2Table[0X1E40] = []rune{0X1E41}
	b2Table[0X1E42] = []rune{0X1E43}
	b2Table[0X1E44] = []rune{0X1E45}
	b2Table[0X1E46] = []rune{0X1E47}
	b2Table[0X1E48] = []rune{0X1E49}
	b2Table[0X1E4A] = []rune{0X1E4B}
	b2Table[0X1E4C] = []rune{0X1E4D}
	b2Table[0X1E4E] = []rune{0X1E4F}
	b2Table[0X1E50] = []rune{0X1E51}
	b2Table[0X1E52] = []rune{0X1E53}
	b2Table[0X1E54] = []rune{0X1E55}
	b2Table[0X1E56] = []rune{0X1E57}
	b2Table[0X1E58] = []rune{0X1E59}
	b2Table[0X1E5A] = []rune{0X1E5B}
	b2Table[0X1E5C] = []rune{0X1E5D}
	b2Table[0X1E5E] = []rune{0X1E5F}
	b2Table[0X1E60] = []rune{0X1E61}
	b2Table[0X1E62] = []rune{0X1E63}
	b2Table[0X1E64] = []rune{0X1E65}
	b2Table[0X1E66] = []rune{0X1E67}
	b2Table[0X1E68] = []rune{0X1E69}
	b2Table[0X1E6A] = []rune{0X1E6B}
	b2Table[0X1E6C] = []rune{0X1E6D}
	b2Table[0X1E6E] = []rune{0X1E6F}
	b2Table[0X1E70] = []rune{0X1E71}
	b2Table[0X1E72] = []rune{0X1E73}
	b2Table[0X1E74] = []rune{0X1E75}
	b2Table[0X1E76] = []rune{0X1E77}
	b2Table[0X1E78] = []rune{0X1E79}
	b2Table[0X1E7A] = []rune{0X1E7B}
	b2Table[0X1E7C] = []rune{0X1E7D}
	b2Table[0X1E7E] = []rune{0X1E7F}
	b2Table[0X1E80] = []rune{0X1E81}
	b2Table[0X1E82] = []rune{0X1E83}
	b2Table[0X1E84] = []rune{0X1E85}
	b2Table[0X1E86] = []rune{0X1E87}
	b2Table[0X1E88] = []rune{0X1E89}
	b2Table[0X1E8A] = []rune{0X1E8B}
	b2Table[0X1E8C] = []rune{0X1E8D}
	b2Table[0X1E8E] = []rune{0X1E8F}
	b2Table[0X1E90] = []rune{0X1E91}
	b2Table[0X1E92] = []rune{0X1E93}
	b2Table[0X1E94] = []rune{0X1E95}
	b2Table[0X1E96] = []rune{0X0068, 0X0331}
	b2Table[0X1E97] = []rune{0X0074, 0X0308}
	b2Table[0X1E98] = []rune{0X0077, 0X030A}
	b2Table[0X1E99] = []rune{0X0079, 0X030A}
	b2Table[0X1E9A] = []rune{0X0061, 0X02BE}
	b2Table[0X1E9B] = []rune{0X1E61}
	b2Table[0X1EA0] = []rune{0X1EA1}
	b2Table[0X1EA2] = []rune{0X1EA3}
	b2Table[0X1EA4] = []rune{0X1EA5}
	b2Table[0X1EA6] = []rune{0X1EA7}
	b2Table[0X1EA8] = []rune{0X1EA9}
	b2Table[0X1EAA] = []rune{0X1EAB}
	b2Table[0X1EAC] = []rune{0X1EAD}
	b2Table[0X1EAE] = []rune{0X1EAF}
	b2Table[0X1EB0] = []rune{0X1EB1}
	b2Table[0X1EB2] = []rune{0X1EB3}
	b2Table[0X1EB4] = []rune{0X1EB5}
	b2Table[0X1EB6] = []rune{0X1EB7}
	b2Table[0X1EB8] = []rune{0X1EB9}
	b2Table[0X1EBA] = []rune{0X1EBB}
	b2Table[0X1EBC] = []rune{0X1EBD}
	b2Table[0X1EBE] = []rune{0X1EBF}
	b2Table[0X1EC0] = []rune{0X1EC1}
	b2Table[0X1EC2] = []rune{0X1EC3}
	b2Table[0X1EC4] = []rune{0X1EC5}
	b2Table[0X1EC6] = []rune{0X1EC7}
	b2Table[0X1EC8] = []rune{0X1EC9}
	b2Table[0X1ECA] = []rune{0X1ECB}
	b2Table[0X1ECC] = []rune{0X1ECD}
	b2Table[0X1ECE] = []rune{0X1ECF}
	b2Table[0X1ED0] = []rune{0X1ED1}
	b2Table[0X1ED2] = []rune{0X1ED3}
	b2Table[0X1ED4] = []rune{0X1ED5}
	b2Table[0X1ED6] = []rune{0X1ED7}
	b2Table[0X1ED8] = []rune{0X1ED9}
	b2Table[0X1EDA] = []rune{0X1EDB}
	b2Table[0X1EDC] = []rune{0X1EDD}
	b2Table[0X1EDE] = []rune{0X1EDF}
	b2Table[0X1EE0] = []rune{0X1EE1}
	b2Table[0X1EE2] = []rune{0X1EE3}
	b2Table[0X1EE4] = []rune{0X1EE5}
	b2Table[0X1EE6] = []rune{0X1EE7}
	b2Table[0X1EE8] = []rune{0X1EE9}
	b2Table[0X1EEA] = []rune{0X1EEB}
	b2Table[0X1EEC] = []rune{0X1EED}
	b2Table[0X1EEE] = []rune{0X1EEF}
	b2Table[0X1EF0] = []rune{0X1EF1}
	b2Table[0X1EF2] = []rune{0X1EF3}
	b2Table[0X1EF4] = []rune{0X1EF5}
	b2Table[0X1EF6] = []rune{0X1EF7}
	b2Table[0X1EF8] = []rune{0X1EF9}
	b2Table[0X1F08] = []rune{0X1F00}
	b2Table[0X1F09] = []rune{0X1F01}
	b2Table[0X1F0A] = []rune{0X1F02}
	b2Table[0X1F0B] = []rune{0X1F03}
	b2Table[0X1F0C] = []rune{0X1F04}
	b2Table[0X1F0D] = []rune{0X1F05}
	b2Table[0X1F0E] = []rune{0X1F06}
	b2Table[0X1F0F] = []rune{0X1F07}
	b2Table[0X1F18] = []rune{0X1F10}
	b2Table[0X1F19] = []rune{0X1F11}
	b2Table[0X1F1A] = []rune{0X1F12}
	b2Table[0X1F1B] = []rune{0X1F13}
	b2Table[0X1F1C] = []rune{0X1F14}
	b2Table[0X1F1D] = []rune{0X1F15}
	b2Table[0X1F28] = []rune{0X1F20}
	b2Table[0X1F29] = []rune{0X1F21}
	b2Table[0X1F2A] = []rune{0X1F22}
	b2Table[0X1F2B] = []rune{0X1F23}
	b2Table[0X1F2C] = []rune{0X1F24}
	b2Table[0X1F2D] = []rune{0X1F25}
	b2Table[0X1F2E] = []rune{0X1F26}
	b2Table[0X1F2F] = []rune{0X1F27}
	b2Table[0X1F38] = []rune{0X1F30}
	b2Table[0X1F39] = []rune{0X1F31}
	b2Table[0X1F3A] = []rune{0X1F32}
	b2Table[0X1F3B] = []rune{0X1F33}
	b2Table[0X1F3C] = []rune{0X1F34}
	b2Table[0X1F3D] = []rune{0X1F35}
	b2Table[0X1F3E] = []rune{0X1F36}
	b2Table[0X1F3F] = []rune{0X1F37}
	b2Table[0X1F48] = []rune{0X1F40}
	b2Table[0X1F49] = []rune{0X1F41}
	b2Table[0X1F4A] = []rune{0X1F42}
	b2Table[0X1F4B] = []rune{0X1F43}
	b2Table[0X1F4C] = []rune{0X1F44}
	b2Table[0X1F4D] = []rune{0X1F45}
	b2Table[0X1F50] = []rune{0X03C5, 0X0313}
	b2Table[0X1F52] = []rune{0X03C5, 0X0313, 0X0300}
	b2Table[0X1F54] = []rune{0X03C5, 0X0313, 0X0301}
	b2Table[0X1F56] = []rune{0X03C5, 0X0313, 0X0342}
	b2Table[0X1F59] = []rune{0X1F51}
	b2Table[0X1F5B] = []rune{0X1F53}
	b2Table[0X1F5D] = []rune{0X1F55}
	b2Table[0X1F5F] = []rune{0X1F57}
	b2Table[0X1F68] = []rune{0X1F60}
	b2Table[0X1F69] = []rune{0X1F61}
	b2Table[0X1F6A] = []rune{0X1F62}
	b2Table[0X1F6B] = []rune{0X1F63}
	b2Table[0X1F6C] = []rune{0X1F64}
	b2Table[0X1F6D] = []rune{0X1F65}
	b2Table[0X1F6E] = []rune{0X1F66}
	b2Table[0X1F6F] = []rune{0X1F67}
	b2Table[0X1F80] = []rune{0X1F00, 0X03B9}
	b2Table[0X1F81] = []rune{0X1F01, 0X03B9}
	b2Table[0X1F82] = []rune{0X1F02, 0X03B9}
	b2Table[0X1F83] = []rune{0X1F03, 0X03B9}
	b2Table[0X1F84] = []rune{0X1F04, 0X03B9}
	b2Table[0X1F85] = []rune{0X1F05, 0X03B9}
	b2Table[0X1F86] = []rune{0X1F06, 0X03B9}
	b2Table[0X1F87] = []rune{0X1F07, 0X03B9}
	b2Table[0X1F88] = []rune{0X1F00, 0X03B9}
	b2Table[0X1F89] = []rune{0X1F01, 0X03B9}
	b2Table[0X1F8A] = []rune{0X1F02, 0X03B9}
	b2Table[0X1F8B] = []rune{0X1F03, 0X03B9}
	b2Table[0X1F8C] = []rune{0X1F04, 0X03B9}
	b2Table[0X1F8D] = []rune{0X1F05, 0X03B9}
	b2Table[0X1F8E] = []rune{0X1F06, 0X03B9}
	b2Table[0X1F8F] = []rune{0X1F07, 0X03B9}
	b2Table[0X1F90] = []rune{0X1F20, 0X03B9}
	b2Table[0X1F91] = []rune{0X1F21, 0X03B9}
	b2Table[0X1F92] = []rune{0X1F22, 0X03B9}
	b2Table[0X1F93] = []rune{0X1F23, 0X03B9}
	b2Table[0X1F94] = []rune{0X1F24, 0X03B9}
	b2Table[0X1F95] = []rune{0X1F25, 0X03B9}
	b2Table[0X1F96] = []rune{0X1F26, 0X03B9}
	b2Table[0X1F97] = []rune{0X1F27, 0X03B9}
	b2Table[0X1F98] = []rune{0X1F20, 0X03B9}
	b2Table[0X1F99] = []rune{0X1F21, 0X03B9}
	b2Table[0X1F9A] = []rune{0X1F22, 0X03B9}
	b2Table[0X1F9B] = []rune{0X1F23, 0X03B9}
	b2Table[0X1F9C] = []rune{0X1F24, 0X03B9}
	b2Table[0X1F9D] = []rune{0X1F25, 0X03B9}
	b2Table[0X1F9E] = []rune{0X1F26, 0X03B9}
	b2Table[0X1F9F] = []rune{0X1F27, 0X03B9}
	b2Table[0X1FA0] = []rune{0X1F60, 0X03B9}
	b2Table[0X1FA1] = []rune{0X1F61, 0X03B9}
	b2Table[0X1FA2] = []rune{0X1F62, 0X03B9}
	b2Table[0X1FA3] = []rune{0X1F63, 0X03B9}
	b2Table[0X1FA4] = []rune{0X1F64, 0X03B9}
	b2Table[0X1FA5] = []rune{0X1F65, 0X03B9}
	b2Table[0X1FA6] = []rune{0X1F66, 0X03B9}
	b2Table[0X1FA7] = []rune{0X1F67, 0X03B9}
	b2Table[0X1FA8] = []rune{0X1F60, 0X03B9}
	b2Table[0X1FA9] = []rune{0X1F61, 0X03B9}
	b2Table[0X1FAA] = []rune{0X1F62, 0X03B9}
	b2Table[0X1FAB] = []rune{0X1F63, 0X03B9}
	b2Table[0X1FAC] = []rune{0X1F64, 0X03B9}
	b2Table[0X1FAD] = []rune{0X1F65, 0X03B9}
	b2Table[0X1FAE] = []rune{0X1F66, 0X03B9}
	b2Table[0X1FAF] = []rune{0X1F67, 0X03B9}
	b2Table[0X1FB2] = []rune{0X1F70, 0X03B9}
	b2Table[0X1FB3] = []rune{0X03B1, 0X03B9}
	b2Table[0X1FB4] = []rune{0X03AC, 0X03B9}
	b2Table[0X1FB6] = []rune{0X03B1, 0X0342}
	b2Table[0X1FB7] = []rune{0X03B1, 0X0342, 0X03B9}
	b2Table[0X1FB8] = []rune{0X1FB0}
	b2Table[0X1FB9] = []rune{0X1FB1}
	b2Table[0X1FBA] = []rune{0X1F70}
	b2Table[0X1FBB] = []rune{0X1F71}
	b2Table[0X1FBC] = []rune{0X03B1, 0X03B9}
	b2Table[0X1FBE] = []rune{0X03B9}
	b2Table[0X1FC2] = []rune{0X1F74, 0X03B9}
	b2Table[0X1FC3] = []rune{0X03B7, 0X03B9}
	b2Table[0X1FC4] = []rune{0X03AE, 0X03B9}
	b2Table[0X1FC6] = []rune{0X03B7, 0X0342}
	b2Table[0X1FC7] = []rune{0X03B7, 0X0342, 0X03B9}
	b2Table[0X1FC8] = []rune{0X1F72}
	b2Table[0X1FC9] = []rune{0X1F73}
	b2Table[0X1FCA] = []rune{0X1F74}
	b2Table[0X1FCB] = []rune{0X1F75}
	b2Table[0X1FCC] = []rune{0X03B7, 0X03B9}
	b2Table[0X1FD2] = []rune{0X03B9, 0X0308, 0X0300}
	b2Table[0X1FD3] = []rune{0X03B9, 0X0308, 0X0301}
	b2Table[0X1FD6] = []rune{0X03B9, 0X0342}
	b2Table[0X1FD7] = []rune{0X03B9, 0X0308, 0X0342}
	b2Table[0X1FD8] = []rune{0X1FD0}
	b2Table[0X1FD9] = []rune{0X1FD1}
	b2Table[0X1FDA] = []rune{0X1F76}
	b2Table[0X1FDB] = []rune{0X1F77}
	b2Table[0X1FE2] = []rune{0X03C5, 0X0308, 0X0300}
	b2Table[0X1FE3] = []rune{0X03C5, 0X0308, 0X0301}
	b2Table[0X1FE4] = []rune{0X03C1, 0X0313}
	b2Table[0X1FE6] = []rune{0X03C5, 0X0342}
	b2Table[0X1FE7] = []rune{0X03C5, 0X0308, 0X0342}
	b2Table[0X1FE8] = []rune{0X1FE0}
	b2Table[0X1FE9] = []rune{0X1FE1}
	b2Table[0X1FEA] = []rune{0X1F7A}
	b2Table[0X1FEB] = []rune{0X1F7B}
	b2Table[0X1FEC] = []rune{0X1FE5}
	b2Table[0X1FF2] = []rune{0X1F7C, 0X03B9}
	b2Table[0X1FF3] = []rune{0X03C9, 0X03B9}
	b2Table[0X1FF4] = []rune{0X03CE, 0X03B9}
	b2Table[0X1FF6] = []rune{0X03C9, 0X0342}
	b2Table[0X1FF7] = []rune{0X03C9, 0X0342, 0X03B9}
	b2Table[0X1FF8] = []rune{0X1F78}
	b2Table[0X1FF9] = []rune{0X1F79}
	b2Table[0X1FFA] = []rune{0X1F7C}
	b2Table[0X1FFB] = []rune{0X1F7D}
	b2Table[0X1FFC] = []rune{0X03C9, 0X03B9}
	b2Table[0X20A8] = []rune{0X0072, 0X0073}
	b2Table[0X2102] = []rune{0X0063}
	b2Table[0X2103] = []rune{0X00B0, 0X0063}
	b2Table[0X2107] = []rune{0X025B}
	b2Table[0X2109] = []rune{0X00B0, 0X0066}
	b2Table[0X210B] = []rune{0X0068}
	b2Table[0X210C] = []rune{0X0068}
	b2Table[0X210D] = []rune{0X0068}
	b2Table[0X2110] = []rune{0X0069}
	b2Table[0X2111] = []rune{0X0069}
	b2Table[0X2112] = []rune{0X006C}
	b2Table[0X2115] = []rune{0X006E}
	b2Table[0X2116] = []rune{0X006E, 0X006F}
	b2Table[0X2119] = []rune{0X0070}
	b2Table[0X211A] = []rune{0X0071}
	b2Table[0X211B] = []rune{0X0072}
	b2Table[0X211C] = []rune{0X0072}
	b2Table[0X211D] = []rune{0X0072}
	b2Table[0X2120] = []rune{0X0073, 0X006D}
	b2Table[0X2121] = []rune{0X0074, 0X0065, 0X006C}
	b2Table[0X2122] = []rune{0X0074, 0X006D}
	b2Table[0X2124] = []rune{0X007A}
	b2Table[0X2126] = []rune{0X03C9}
	b2Table[0X2128] = []rune{0X007A}
	b2Table[0X212A] = []rune{0X006B}
	b2Table[0X212B] = []rune{0X00E5}
	b2Table[0X212C] = []rune{0X0062}
	b2Table[0X212D] = []rune{0X0063}
	b2Table[0X2130] = []rune{0X0065}
	b2Table[0X2131] = []rune{0X0066}
	b2Table[0X2133] = []rune{0X006D}
	b2Table[0X213E] = []rune{0X03B3}
	b2Table[0X213F] = []rune{0X03C0}
	b2Table[0X2145] = []rune{0X0064}
	b2Table[0X2160] = []rune{0X2170}
	b2Table[0X2161] = []rune{0X2171}
	b2Table[0X2162] = []rune{0X2172}
	b2Table[0X2163] = []rune{0X2173}
	b2Table[0X2164] = []rune{0X2174}
	b2Table[0X2165] = []rune{0X2175}
	b2Table[0X2166] = []rune{0X2176}
	b2Table[0X2167] = []rune{0X2177}
	b2Table[0X2168] = []rune{0X2178}
	b2Table[0X2169] = []rune{0X2179}
	b2Table[0X216A] = []rune{0X217A}
	b2Table[0X216B] = []rune{0X217B}
	b2Table[0X216C] = []rune{0X217C}
	b2Table[0X216D] = []rune{0X217D}
	b2Table[0X216E] = []rune{0X217E}
	b2Table[0X216F] = []rune{0X217F}
	b2Table[0X24B6] = []rune{0X24D0}
	b2Table[0X24B7] = []rune{0X24D1}
	b2Table[0X24B8] = []rune{0X24D2}
	b2Table[0X24B9] = []rune{0X24D3}
	b2Table[0X24BA] = []rune{0X24D4}
	b2Table[0X24BB] = []rune{0X24D5}
	b2Table[0X24BC] = []rune{0X24D6}
	b2Table[0X24BD] = []rune{0X24D7}
	b2Table[0X24BE] = []rune{0X24D8}
	b2Table[0X24BF] = []rune{0X24D9}
	b2Table[0X24C0] = []rune{0X24DA}
	b2Table[0X24C1] = []rune{0X24DB}
	b2Table[0X24C2] = []rune{0X24DC}
	b2Table[0X24C3] = []rune{0X24DD}
	b2Table[0X24C4] = []rune{0X24DE}
	b2Table[0X24C5] = []rune{0X24DF}
	b2Table[0X24C6] = []rune{0X24E0}
	b2Table[0X24C7] = []rune{0X24E1}
	b2Table[0X24C8] = []rune{0X24E2}
	b2Table[0X24C9] = []rune{0X24E3}
	b2Table[0X24CA] = []rune{0X24E4}
	b2Table[0X24CB] = []rune{0X24E5}
	b2Table[0X24CC] = []rune{0X24E6}
	b2Table[0X24CD] = []rune{0X24E7}
	b2Table[0X24CE] = []rune{0X24E8}
	b2Table[0X24CF] = []rune{0X24E9}
	b2Table[0X3371] = []rune{0X0068, 0X0070, 0X0061}
	b2Table[0X3373] = []rune{0X0061, 0X0075}
	b2Table[0X3375] = []rune{0X006F, 0X0076}
	b2Table[0X3380] = []rune{0X0070, 0X0061}
	b2Table[0X3381] = []rune{0X006E, 0X0061}
	b2Table[0X3382] = []rune{0X03BC, 0X0061}
	b2Table[0X3383] = []rune{0X006D, 0X0061}
	b2Table[0X3384] = []rune{0X006B, 0X0061}
	b2Table[0X3385] = []rune{0X006B, 0X0062}
	b2Table[0X3386] = []rune{0X006D, 0X0062}
	b2Table[0X3387] = []rune{0X0067, 0X0062}
	b2Table[0X338A] = []rune{0X0070, 0X0066}
	b2Table[0X338B] = []rune{0X006E, 0X0066}
	b2Table[0X338C] = []rune{0X03BC, 0X0066}
	b2Table[0X3390] = []rune{0X0068, 0X007A}
	b2Table[0X3391] = []rune{0X006B, 0X0068, 0X007A}
	b2Table[0X3392] = []rune{0X006D, 0X0068, 0X007A}
	b2Table[0X3393] = []rune{0X0067, 0X0068, 0X007A}
	b2Table[0X3394] = []rune{0X0074, 0X0068, 0X007A}
	b2Table[0X33A9] = []rune{0X0070, 0X0061}
	b2Table[0X33AA] = []rune{0X006B, 0X0070, 0X0061}
	b2Table[0X33AB] = []rune{0X006D, 0X0070, 0X0061}
	b2Table[0X33AC] = []rune{0X0067, 0X0070, 0X0061}
	b2Table[0X33B4] = []rune{0X0070, 0X0076}
	b2Table[0X33B5] = []rune{0X006E, 0X0076}
	b2Table[0X33B6] = []rune{0X03BC, 0X0076}
	b2Table[0X33B7] = []rune{0X006D, 0X0076}
	b2Table[0X33B8] = []rune{0X006B, 0X0076}
	b2Table[0X33B9] = []rune{0X006D, 0X0076}
	b2Table[0X33BA] = []rune{0X0070, 0X0077}
	b2Table[0X33BB] = []rune{0X006E, 0X0077}
	b2Table[0X33BC] = []rune{0X03BC, 0X0077}
	b2Table[0X33BD] = []rune{0X006D, 0X0077}
	b2Table[0X33BE] = []rune{0X006B, 0X0077}
	b2Table[0X33BF] = []rune{0X006D, 0X0077}
	b2Table[0X33C0] = []rune{0X006B, 0X03C9}
	b2Table[0X33C1] = []rune{0X006D, 0X03C9}
	b2Table[0X33C3] = []rune{0X0062, 0X0071}
	b2Table[0X33C6] = []rune{0X0063, 0X2215, 0X006B, 0X0067}
	b2Table[0X33C7] = []rune{0X0063, 0X006F, 0X002E}
	b2Table[0X33C8] = []rune{0X0064, 0X0062}
	b2Table[0X33C9] = []rune{0X0067, 0X0079}
	b2Table[0X33CB] = []rune{0X0068, 0X0070}
	b2Table[0X33CD] = []rune{0X006B, 0X006B}
	b2Table[0X33CE] = []rune{0X006B, 0X006D}
	b2Table[0X33D7] = []rune{0X0070, 0X0068}
	b2Table[0X33D9] = []rune{0X0070, 0X0070, 0X006D}
	b2Table[0X33DA] = []rune{0X0070, 0X0072}
	b2Table[0X33DC] = []rune{0X0073, 0X0076}
	b2Table[0X33DD] = []rune{0X0077, 0X0062}
	b2Table[0XFB00] = []rune{0X0066, 0X0066}
	b2Table[0XFB01] = []rune{0X0066, 0X0069}
	b2Table[0XFB02] = []rune{0X0066, 0X006C}
	b2Table[0XFB03] = []rune{0X0066, 0X0066, 0X0069}
	b2Table[0XFB04] = []rune{0X0066, 0X0066, 0X006C}
	b2Table[0XFB05] = []rune{0X0073, 0X0074}
	b2Table[0XFB06] = []rune{0X0073, 0X0074}
	b2Table[0XFB13] = []rune{0X0574, 0X0576}
	b2Table[0XFB14] = []rune{0X0574, 0X0565}
	b2Table[0XFB15] = []rune{0X0574, 0X056B}
	b2Table[0XFB16] = []rune{0X057E, 0X0576}
	b2Table[0XFB17] = []rune{0X0574, 0X056D}
	b2Table[0XFF21] = []rune{0XFF41}
	b2Table[0XFF22] = []rune{0XFF42}
	b2Table[0XFF23] = []rune{0XFF43}
	b2Table[0XFF24] = []rune{0XFF44}
	b2Table[0XFF25] = []rune{0XFF45}
	b2Table[0XFF26] = []rune{0XFF46}
	b2Table[0XFF27] = []rune{0XFF47}
	b2Table[0XFF28] = []rune{0XFF48}
	b2Table[0XFF29] = []rune{0XFF49}
	b2Table[0XFF2A] = []rune{0XFF4A}
	b2Table[0XFF2B] = []rune{0XFF4B}
	b2Table[0XFF2C] = []rune{0XFF4C}
	b2Table[0XFF2D] = []rune{0XFF4D}
	b2Table[0XFF2E] = []rune{0XFF4E}
	b2Table[0XFF2F] = []rune{0XFF4F}
	b2Table[0XFF30] = []rune{0XFF50}
	b2Table[0XFF31] = []rune{0XFF51}
	b2Table[0XFF32] = []rune{0XFF52}
	b2Table[0XFF33] = []rune{0XFF53}
	b2Table[0XFF34] = []rune{0XFF54}
	b2Table[0XFF35] = []rune{0XFF55}
	b2Table[0XFF36] = []rune{0XFF56}
	b2Table[0XFF37] = []rune{0XFF57}
	b2Table[0XFF38] = []rune{0XFF58}
	b2Table[0XFF39] = []rune{0XFF59}
	b2Table[0XFF3A] = []rune{0XFF5A}
	b2Table[0X10400] = []rune{0X10428}
	b2Table[0X10401] = []rune{0X10429}
	b2Table[0X10402] = []rune{0X1042A}
	b2Table[0X10403] = []rune{0X1042B}
	b2Table[0X10404] = []rune{0X1042C}
	b2Table[0X10405] = []rune{0X1042D}
	b2Table[0X10406] = []rune{0X1042E}
	b2Table[0X10407] = []rune{0X1042F}
	b2Table[0X10408] = []rune{0X10430}
	b2Table[0X10409] = []rune{0X10431}
	b2Table[0X1040A] = []rune{0X10432}
	b2Table[0X1040B] = []rune{0X10433}
	b2Table[0X1040C] = []rune{0X10434}
	b2Table[0X1040D] = []rune{0X10435}
	b2Table[0X1040E] = []rune{0X10436}
	b2Table[0X1040F] = []rune{0X10437}
	b2Table[0X10410] = []rune{0X10438}
	b2Table[0X10411] = []rune{0X10439}
	b2Table[0X10412] = []rune{0X1043A}
	b2Table[0X10413] = []rune{0X1043B}
	b2Table[0X10414] = []rune{0X1043C}
	b2Table[0X10415] = []rune{0X1043D}
	b2Table[0X10416] = []rune{0X1043E}
	b2Table[0X10417] = []rune{0X1043F}
	b2Table[0X10418] = []rune{0X10440}
	b2Table[0X10419] = []rune{0X10441}
	b2Table[0X1041A] = []rune{0X10442}
	b2Table[0X1041B] = []rune{0X10443}
	b2Table[0X1041C] = []rune{0X10444}
	b2Table[0X1041D] = []rune{0X10445}
	b2Table[0X1041E] = []rune{0X10446}
	b2Table[0X1041F] = []rune{0X10447}
	b2Table[0X10420] = []rune{0X10448}
	b2Table[0X10421] = []rune{0X10449}
	b2Table[0X10422] = []rune{0X1044A}
	b2Table[0X10423] = []rune{0X1044B}
	b2Table[0X10424] = []rune{0X1044C}
	b2Table[0X10425] = []rune{0X1044D}
	b2Table[0X1D400] = []rune{0X0061}
	b2Table[0X1D401] = []rune{0X0062}
	b2Table[0X1D402] = []rune{0X0063}
	b2Table[0X1D403] = []rune{0X0064}
	b2Table[0X1D404] = []rune{0X0065}
	b2Table[0X1D405] = []rune{0X0066}
	b2Table[0X1D406] = []rune{0X0067}
	b2Table[0X1D407] = []rune{0X0068}
	b2Table[0X1D408] = []rune{0X0069}
	b2Table[0X1D409] = []rune{0X006A}
	b2Table[0X1D40A] = []rune{0X006B}
	b2Table[0X1D40B] = []rune{0X006C}
	b2Table[0X1D40C] = []rune{0X006D}
	b2Table[0X1D40D] = []rune{0X006E}
	b2Table[0X1D40E] = []rune{0X006F}
	b2Table[0X1D40F] = []rune{0X0070}
	b2Table[0X1D410] = []rune{0X0071}
	b2Table[0X1D411] = []rune{0X0072}
	b2Table[0X1D412] = []rune{0X0073}
	b2Table[0X1D413] = []rune{0X0074}
	b2Table[0X1D414] = []rune{0X0075}
	b2Table[0X1D415] = []rune{0X0076}
	b2Table[0X1D416] = []rune{0X0077}
	b2Table[0X1D417] = []rune{0X0078}
	b2Table[0X1D418] = []rune{0X0079}
	b2Table[0X1D419] = []rune{0X007A}
	b2Table[0X1D434] = []rune{0X0061}
	b2Table[0X1D435] = []rune{0X0062}
	b2Table[0X1D436] = []rune{0X0063}
	b2Table[0X1D437] = []rune{0X0064}
	b2Table[0X1D438] = []rune{0X0065}
	b2Table[0X1D439] = []rune{0X0066}
	b2Table[0X1D43A] = []rune{0X0067}
	b2Table[0X1D43B] = []rune{0X0068}
	b2Table[0X1D43C] = []rune{0X0069}
	b2Table[0X1D43D] = []rune{0X006A}
	b2Table[0X1D43E] = []rune{0X006B}
	b2Table[0X1D43F] = []rune{0X006C}
	b2Table[0X1D440] = []rune{0X006D}
	b2Table[0X1D441] = []rune{0X006E}
	b2Table[0X1D442] = []rune{0X006F}
	b2Table[0X1D443] = []rune{0X0070}
	b2Table[0X1D444] = []rune{0X0071}
	b2Table[0X1D445] = []rune{0X0072}
	b2Table[0X1D446] = []rune{0X0073}
	b2Table[0X1D447] = []rune{0X0074}
	b2Table[0X1D448] = []rune{0X0075}
	b2Table[0X1D449] = []rune{0X0076}
	b2Table[0X1D44A] = []rune{0X0077}
	b2Table[0X1D44B] = []rune{0X0078}
	b2Table[0X1D44C] = []rune{0X0079}
	b2Table[0X1D44D] = []rune{0X007A}
	b2Table[0X1D468] = []rune{0X0061}
	b2Table[0X1D469] = []rune{0X0062}
	b2Table[0X1D46A] = []rune{0X0063}
	b2Table[0X1D46B] = []rune{0X0064}
	b2Table[0X1D46C] = []rune{0X0065}
	b2Table[0X1D46D] = []rune{0X0066}
	b2Table[0X1D46E] = []rune{0X0067}
	b2Table[0X1D46F] = []rune{0X0068}
	b2Table[0X1D470] = []rune{0X0069}
	b2Table[0X1D471] = []rune{0X006A}
	b2Table[0X1D472] = []rune{0X006B}
	b2Table[0X1D473] = []rune{0X006C}
	b2Table[0X1D474] = []rune{0X006D}
	b2Table[0X1D475] = []rune{0X006E}
	b2Table[0X1D476] = []rune{0X006F}
	b2Table[0X1D477] = []rune{0X0070}
	b2Table[0X1D478] = []rune{0X0071}
	b2Table[0X1D479] = []rune{0X0072}
	b2Table[0X1D47A] = []rune{0X0073}
	b2Table[0X1D47B] = []rune{0X0074}
	b2Table[0X1D47C] = []rune{0X0075}
	b2Table[0X1D47D] = []rune{0X0076}
	b2Table[0X1D47E] = []rune{0X0077}
	b2Table[0X1D47F] = []rune{0X0078}
	b2Table[0X1D480] = []rune{0X0079}
	b2Table[0X1D481] = []rune{0X007A}
	b2Table[0X1D49C] = []rune{0X0061}
	b2Table[0X1D49E] = []rune{0X0063}
	b2Table[0X1D49F] = []rune{0X0064}
	b2Table[0X1D4A2] = []rune{0X0067}
	b2Table[0X1D4A5] = []rune{0X006A}
	b2Table[0X1D4A6] = []rune{0X006B}
	b2Table[0X1D4A9] = []rune{0X006E}
	b2Table[0X1D4AA] = []rune{0X006F}
	b2Table[0X1D4AB] = []rune{0X0070}
	b2Table[0X1D4AC] = []rune{0X0071}
	b2Table[0X1D4AE] = []rune{0X0073}
	b2Table[0X1D4AF] = []rune{0X0074}
	b2Table[0X1D4B0] = []rune{0X0075}
	b2Table[0X1D4B1] = []rune{0X0076}
	b2Table[0X1D4B2] = []rune{0X0077}
	b2Table[0X1D4B3] = []rune{0X0078}
	b2Table[0X1D4B4] = []rune{0X0079}
	b2Table[0X1D4B5] = []rune{0X007A}
	b2Table[0X1D4D0] = []rune{0X0061}
	b2Table[0X1D4D1] = []rune{0X0062}
	b2Table[0X1D4D2] = []rune{0X0063}
	b2Table[0X1D4D3] = []rune{0X0064}
	b2Table[0X1D4D4] = []rune{0X0065}
	b2Table[0X1D4D5] = []rune{0X0066}
	b2Table[0X1D4D6] = []rune{0X0067}
	b2Table[0X1D4D7] = []rune{0X0068}
	b2Table[0X1D4D8] = []rune{0X0069}
	b2Table[0X1D4D9] = []rune{0X006A}
	b2Table[0X1D4DA] = []rune{0X006B}
	b2Table[0X1D4DB] = []rune{0X006C}
	b2Table[0X1D4DC] = []rune{0X006D}
	b2Table[0X1D4DD] = []rune{0X006E}
	b2Table[0X1D4DE] = []rune{0X006F}
	b2Table[0X1D4DF] = []rune{0X0070}
	b2Table[0X1D4E0] = []rune{0X0071}
	b2Table[0X1D4E1] = []rune{0X0072}
	b2Table[0X1D4E2] = []rune{0X0073}
	b2Table[0X1D4E3] = []rune{0X0074}
	b2Table[0X1D4E4] = []rune{0X0075}
	b2Table[0X1D4E5] = []rune{0X0076}
	b2Table[0X1D4E6] = []rune{0X0077}
	b2Table[0X1D4E7] = []rune{0X0078}
	b2Table[0X1D4E8] = []rune{0X0079}
	b2Table[0X1D4E9] = []rune{0X007A}
	b2Table[0X1D504] = []rune{0X0061}
	b2Table[0X1D505] = []rune{0X0062}
	b2Table[0X1D507] = []rune{0X0064}
	b2Table[0X1D508] = []rune{0X0065}
	b2Table[0X1D509] = []rune{0X0066}
	b2Table[0X1D50A] = []rune{0X0067}
	b2Table[0X1D50D] = []rune{0X006A}
	b2Table[0X1D50E] = []rune{0X006B}
	b2Table[0X1D50F] = []rune{0X006C}
	b2Table[0X1D510] = []rune{0X006D}
	b2Table[0X1D511] = []rune{0X006E}
	b2Table[0X1D512] = []rune{0X006F}
	b2Table[0X1D513] = []rune{0X0070}
	b2Table[0X1D514] = []rune{0X0071}
	b2Table[0X1D516] = []rune{0X0073}
	b2Table[0X1D517] = []rune{0X0074}
	b2Table[0X1D518] = []rune{0X0075}
	b2Table[0X1D519] = []rune{0X0076}
	b2Table[0X1D51A] = []rune{0X0077}
	b2Table[0X1D51B] = []rune{0X0078}
	b2Table[0X1D51C] = []rune{0X0079}
	b2Table[0X1D538] = []rune{0X0061}
	b2Table[0X1D539] = []rune{0X0062}
	b2Table[0X1D53B] = []rune{0X0064}
	b2Table[0X1D53C] = []rune{0X0065}
	b2Table[0X1D53D] = []rune{0X0066}
	b2Table[0X1D53E] = []rune{0X0067}
	b2Table[0X1D540] = []rune{0X0069}
	b2Table[0X1D541] = []rune{0X006A}
	b2Table[0X1D542] = []rune{0X006B}
	b2Table[0X1D543] = []rune{0X006C}
	b2Table[0X1D544] = []rune{0X006D}
	b2Table[0X1D546] = []rune{0X006F}
	b2Table[0X1D54A] = []rune{0X0073}
	b2Table[0X1D54B] = []rune{0X0074}
	b2Table[0X1D54C] = []rune{0X0075}
	b2Table[0X1D54D] = []rune{0X0076}
	b2Table[0X1D54E] = []rune{0X0077}
	b2Table[0X1D54F] = []rune{0X0078}
	b2Table[0X1D550] = []rune{0X0079}
	b2Table[0X1D56C] = []rune{0X0061}
	b2Table[0X1D56D] = []rune{0X0062}
	b2Table[0X1D56E] = []rune{0X0063}
	b2Table[0X1D56F] = []rune{0X0064}
	b2Table[0X1D570] = []rune{0X0065}
	b2Table[0X1D571] = []rune{0X0066}
	b2Table[0X1D572] = []rune{0X0067}
	b2Table[0X1D573] = []rune{0X0068}
	b2Table[0X1D574] = []rune{0X0069}
	b2Table[0X1D575] = []rune{0X006A}
	b2Table[0X1D576] = []rune{0X006B}
	b2Table[0X1D577] = []rune{0X006C}
	b2Table[0X1D578] = []rune{0X006D}
	b2Table[0X1D579] = []rune{0X006E}
	b2Table[0X1D57A] = []rune{0X006F}
	b2Table[0X1D57B] = []rune{0X0070}
	b2Table[0X1D57C] = []rune{0X0071}
	b2Table[0X1D57D] = []rune{0X0072}
	b2Table[0X1D57E] = []rune{0X0073}
	b2Table[0X1D57F] = []rune{0X0074}
	b2Table[0X1D580] = []rune{0X0075}
	b2Table[0X1D581] = []rune{0X0076}
	b2Table[0X1D582] = []rune{0X0077}
	b2Table[0X1D583] = []rune{0X0078}
	b2Table[0X1D584] = []rune{0X0079}
	b2Table[0X1D585] = []rune{0X007A}
	b2Table[0X1D5A0] = []rune{0X0061}
	b2Table[0X1D5A1] = []rune{0X0062}
	b2Table[0X1D5A2] = []rune{0X0063}
	b2Table[0X1D5A3] = []rune{0X0064}
	b2Table[0X1D5A4] = []rune{0X0065}
	b2Table[0X1D5A5] = []rune{0X0066}
	b2Table[0X1D5A6] = []rune{0X0067}
	b2Table[0X1D5A7] = []rune{0X0068}
	b2Table[0X1D5A8] = []rune{0X0069}
	b2Table[0X1D5A9] = []rune{0X006A}
	b2Table[0X1D5AA] = []rune{0X006B}
	b2Table[0X1D5AB] = []rune{0X006C}
	b2Table[0X1D5AC] = []rune{0X006D}
	b2Table[0X1D5AD] = []rune{0X006E}
	b2Table[0X1D5AE] = []rune{0X006F}
	b2Table[0X1D5AF] = []rune{0X0070}
	b2Table[0X1D5B0] = []rune{0X0071}
	b2Table[0X1D5B1] = []rune{0X0072}
	b2Table[0X1D5B2] = []rune{0X0073}
	b2Table[0X1D5B3] = []rune{0X0074}
	b2Table[0X1D5B4] = []rune{0X0075}
	b2Table[0X1D5B5] = []rune{0X0076}
	b2Table[0X1D5B6] = []rune{0X0077}
	b2Table[0X1D5B7] = []rune{0X0078}
	b2Table[0X1D5B8] = []rune{0X0079}
	b2Table[0X1D5B9] = []rune{0X007A}
	b2Table[0X1D5D4] = []rune{0X0061}
	b2Table[0X1D5D5] = []rune{0X0062}
	b2Table[0X1D5D6] = []rune{0X0063}
	b2Table[0X1D5D7] = []rune{0X0064}
	b2Table[0X1D5D8] = []rune{0X0065}
	b2Table[0X1D5D9] = []rune{0X0066}
	b2Table[0X1D5DA] = []rune{0X0067}
	b2Table[0X1D5DB] = []rune{0X0068}
	b2Table[0X1D5DC] = []rune{0X0069}
	b2Table[0X1D5DD] = []rune{0X006A}
	b2Table[0X1D5DE] = []rune{0X006B}
	b2Table[0X1D5DF] = []rune{0X006C}
	b2Table[0X1D5E0] = []rune{0X006D}
	b2Table[0X1D5E1] = []rune{0X006E}
	b2Table[0X1D5E2] = []rune{0X006F}
	b2Table[0X1D5E3] = []rune{0X0070}
	b2Table[0X1D5E4] = []rune{0X0071}
	b2Table[0X1D5E5] = []rune{0X0072}
	b2Table[0X1D5E6] = []rune{0X0073}
	b2Table[0X1D5E7] = []rune{0X0074}
	b2Table[0X1D5E8] = []rune{0X0075}
	b2Table[0X1D5E9] = []rune{0X0076}
	b2Table[0X1D5EA] = []rune{0X0077}
	b2Table[0X1D5EB] = []rune{0X0078}
	b2Table[0X1D5EC] = []rune{0X0079}
	b2Table[0X1D5ED] = []rune{0X007A}
	b2Table[0X1D608] = []rune{0X0061}
	b2Table[0X1D609] = []rune{0X0062}
	b2Table[0X1D60A] = []rune{0X0063}
	b2Table[0X1D60B] = []rune{0X0064}
	b2Table[0X1D60C] = []rune{0X0065}
	b2Table[0X1D60D] = []rune{0X0066}
	b2Table[0X1D60E] = []rune{0X0067}
	b2Table[0X1D60F] = []rune{0X0068}
	b2Table[0X1D610] = []rune{0X0069}
	b2Table[0X1D611] = []rune{0X006A}
	b2Table[0X1D612] = []rune{0X006B}
	b2Table[0X1D613] = []rune{0X006C}
	b2Table[0X1D614] = []rune{0X006D}
	b2Table[0X1D615] = []rune{0X006E}
	b2Table[0X1D616] = []rune{0X006F}
	b2Table[0X1D617] = []rune{0X0070}
	b2Table[0X1D618] = []rune{0X0071}
	b2Table[0X1D619] = []rune{0X0072}
	b2Table[0X1D61A] = []rune{0X0073}
	b2Table[0X1D61B] = []rune{0X0074}
	b2Table[0X1D61C] = []rune{0X0075}
	b2Table[0X1D61D] = []rune{0X0076}
	b2Table[0X1D61E] = []rune{0X0077}
	b2Table[0X1D61F] = []rune{0X0078}
	b2Table[0X1D620] = []rune{0X0079}
	b2Table[0X1D621] = []rune{0X007A}
	b2Table[0X1D63C] = []rune{0X0061}
	b2Table[0X1D63D] = []rune{0X0062}
	b2Table[0X1D63E] = []rune{0X0063}
	b2Table[0X1D63F] = []rune{0X0064}
	b2Table[0X1D640] = []rune{0X0065}
	b2Table[0X1D641] = []rune{0X0066}
	b2Table[0X1D642] = []rune{0X0067}
	b2Table[0X1D643] = []rune{0X0068}
	b2Table[0X1D644] = []rune{0X0069}
	b2Table[0X1D645] = []rune{0X006A}
	b2Table[0X1D646] = []rune{0X006B}
	b2Table[0X1D647] = []rune{0X006C}
	b2Table[0X1D648] = []rune{0X006D}
	b2Table[0X1D649] = []rune{0X006E}
	b2Table[0X1D64A] = []rune{0X006F}
	b2Table[0X1D64B] = []rune{0X0070}
	b2Table[0X1D64C] = []rune{0X0071}
	b2Table[0X1D64D] = []rune{0X0072}
	b2Table[0X1D64E] = []rune{0X0073}
	b2Table[0X1D64F] = []rune{0X0074}
	b2Table[0X1D650] = []rune{0X0075}
	b2Table[0X1D651] = []rune{0X0076}
	b2Table[0X1D652] = []rune{0X0077}
	b2Table[0X1D653] = []rune{0X0078}
	b2Table[0X1D654] = []rune{0X0079}
	b2Table[0X1D655] = []rune{0X007A}
	b2Table[0X1D670] = []rune{0X0061}
	b2Table[0X1D671] = []rune{0X0062}
	b2Table[0X1D672] = []rune{0X0063}
	b2Table[0X1D673] = []rune{0X0064}
	b2Table[0X1D674] = []rune{0X0065}
	b2Table[0X1D675] = []rune{0X0066}
	b2Table[0X1D676] = []rune{0X0067}
	b2Table[0X1D677] = []rune{0X0068}
	b2Table[0X1D678] = []rune{0X0069}
	b2Table[0X1D679] = []rune{0X006A}
	b2Table[0X1D67A] = []rune{0X006B}
	b2Table[0X1D67B] = []rune{0X006C}
	b2Table[0X1D67C] = []rune{0X006D}
	b2Table[0X1D67D] = []rune{0X006E}
	b2Table[0X1D67E] = []rune{0X006F}
	b2Table[0X1D67F] = []rune{0X0070}
	b2Table[0X1D680] = []rune{0X0071}
	b2Table[0X1D681] = []rune{0X0072}
	b2Table[0X1D682] = []rune{0X0073}
	b2Table[0X1D683] = []rune{0X0074}
	b2Table[0X1D684] = []rune{0X0075}
	b2Table[0X1D685] = []rune{0X0076}
	b2Table[0X1D686] = []rune{0X0077}
	b2Table[0X1D687] = []rune{0X0078}
	b2Table[0X1D688] = []rune{0X0079}
	b2Table[0X1D689] = []rune{0X007A}
	b2Table[0X1D6A8] = []rune{0X03B1}
	b2Table[0X1D6A9] = []rune{0X03B2}
	b2Table[0X1D6AA] = []rune{0X03B3}
	b2Table[0X1D6AB] = []rune{0X03B4}
	b2Table[0X1D6AC] = []rune{0X03B5}
	b2Table[0X1D6AD] = []rune{0X03B6}
	b2Table[0X1D6AE] = []rune{0X03B7}
	b2Table[0X1D6AF] = []rune{0X03B8}
	b2Table[0X1D6B0] = []rune{0X03B9}
	b2Table[0X1D6B1] = []rune{0X03BA}
	b2Table[0X1D6B2] = []rune{0X03BB}
	b2Table[0X1D6B3] = []rune{0X03BC}
	b2Table[0X1D6B4] = []rune{0X03BD}
	b2Table[0X1D6B5] = []rune{0X03BE}
	b2Table[0X1D6B6] = []rune{0X03BF}
	b2Table[0X1D6B7] = []rune{0X03C0}
	b2Table[0X1D6B8] = []rune{0X03C1}
	b2Table[0X1D6B9] = []rune{0X03B8}
	b2Table[0X1D6BA] = []rune{0X03C3}
	b2Table[0X1D6BB] = []rune{0X03C4}
	b2Table[0X1D6BC] = []rune{0X03C5}
	b2Table[0X1D6BD] = []rune{0X03C6}
	b2Table[0X1D6BE] = []rune{0X03C7}
	b2Table[0X1D6BF] = []rune{0X03C8}
	b2Table[0X1D6C0] = []rune{0X03C9}
	b2Table[0X1D6D3] = []rune{0X03C3}
	b2Table[0X1D6E2] = []rune{0X03B1}
	b2Table[0X1D6E3] = []rune{0X03B2}
	b2Table[0X1D6E4] = []rune{0X03B3}
	b2Table[0X1D6E5] = []rune{0X03B4}
	b2Table[0X1D6E6] = []rune{0X03B5}
	b2Table[0X1D6E7] = []rune{0X03B6}
	b2Table[0X1D6E8] = []rune{0X03B7}
	b2Table[0X1D6E9] = []rune{0X03B8}
	b2Table[0X1D6EA] = []rune{0X03B9}
	b2Table[0X1D6EB] = []rune{0X03BA}
	b2Table[0X1D6EC] = []rune{0X03BB}
	b2Table[0X1D6ED] = []rune{0X03BC}
	b2Table[0X1D6EE] = []rune{0X03BD}
	b2Table[0X1D6EF] = []rune{0X03BE}
	b2Table[0X1D6F0] = []rune{0X03BF}
	b2Table[0X1D6F1] = []rune{0X03C0}
	b2Table[0X1D6F2] = []rune{0X03C1}
	b2Table[0X1D6F3] = []rune{0X03B8}
	b2Table[0X1D6F4] = []rune{0X03C3}
	b2Table[0X1D6F5] = []rune{0X03C4}
	b2Table[0X1D6F6] = []rune{0X03C5}
	b2Table[0X1D6F7] = []rune{0X03C6}
	b2Table[0X1D6F8] = []rune{0X03C7}
	b2Table[0X1D6F9] = []rune{0X03C8}
	b2Table[0X1D6FA] = []rune{0X03C9}
	b2Table[0X1D70D] = []rune{0X03C3}
	b2Table[0X1D71C] = []rune{0X03B1}
	b2Table[0X1D71D] = []rune{0X03B2}
	b2Table[0X1D71E] = []rune{0X03B3}
	b2Table[0X1D71F] = []rune{0X03B4}
	b2Table[0X1D720] = []rune{0X03B5}
	b2Table[0X1D721] = []rune{0X03B6}
	b2Table[0X1D722] = []rune{0X03B7}
	b2Table[0X1D723] = []rune{0X03B8}
	b2Table[0X1D724] = []rune{0X03B9}
	b2Table[0X1D725] = []rune{0X03BA}
	b2Table[0X1D726] = []rune{0X03BB}
	b2Table[0X1D727] = []rune{0X03BC}
	b2Table[0X1D728] = []rune{0X03BD}
	b2Table[0X1D729] = []rune{0X03BE}
	b2Table[0X1D72A] = []rune{0X03BF}
	b2Table[0X1D72B] = []rune{0X03C0}
	b2Table[0X1D72C] = []rune{0X03C1}
	b2Table[0X1D72D] = []rune{0X03B8}
	b2Table[0X1D72E] = []rune{0X03C3}
	b2Table[0X1D72F] = []rune{0X03C4}
	b2Table[0X1D730] = []rune{0X03C5}
	b2Table[0X1D731] = []rune{0X03C6}
	b2Table[0X1D732] = []rune{0X03C7}
	b2Table[0X1D733] = []rune{0X03C8}
	b2Table[0X1D734] = []rune{0X03C9}
	b2Table[0X1D747] = []rune{0X03C3}
	b2Table[0X1D756] = []rune{0X03B1}
	b2Table[0X1D757] = []rune{0X03B2}
	b2Table[0X1D758] = []rune{0X03B3}
	b2Table[0X1D759] = []rune{0X03B4}
	b2Table[0X1D75A] = []rune{0X03B5}
	b2Table[0X1D75B] = []rune{0X03B6}
	b2Table[0X1D75C] = []rune{0X03B7}
	b2Table[0X1D75D] = []rune{0X03B8}
	b2Table[0X1D75E] = []rune{0X03B9}
	b2Table[0X1D75F] = []rune{0X03BA}
	b2Table[0X1D760] = []rune{0X03BB}
	b2Table[0X1D761] = []rune{0X03BC}
	b2Table[0X1D762] = []rune{0X03BD}
	b2Table[0X1D763] = []rune{0X03BE}
	b2Table[0X1D764] = []rune{0X03BF}
	b2Table[0X1D765] = []rune{0X03C0}
	b2Table[0X1D766] = []rune{0X03C1}
	b2Table[0X1D767] = []rune{0X03B8}
	b2Table[0X1D768] = []rune{0X03C3}
	b2Table[0X1D769] = []rune{0X03C4}
	b2Table[0X1D76A] = []rune{0X03C5}
	b2Table[0X1D76B] = []rune{0X03C6}
	b2Table[0X1D76C] = []rune{0X03C7}
	b2Table[0X1D76D] = []rune{0X03C8}
	b2Table[0X1D76E] = []rune{0X03C9}
	b2Table[0X1D781] = []rune{0X03C3}
	b2Table[0X1D790] = []rune{0X03B1}
	b2Table[0X1D791] = []rune{0X03B2}
	b2Table[0X1D792] = []rune{0X03B3}
	b2Table[0X1D793] = []rune{0X03B4}
	b2Table[0X1D794] = []rune{0X03B5}
	b2Table[0X1D795] = []rune{0X03B6}
	b2Table[0X1D796] = []rune{0X03B7}
	b2Table[0X1D797] = []rune{0X03B8}
	b2Table[0X1D798] = []rune{0X03B9}
	b2Table[0X1D799] = []rune{0X03BA}
	b2Table[0X1D79A] = []rune{0X03BB}
	b2Table[0X1D79B] = []rune{0X03BC}
	b2Table[0X1D79C] = []rune{0X03BD}
	b2Table[0X1D79D] = []rune{0X03BE}
	b2Table[0X1D79E] = []rune{0X03BF}
	b2Table[0X1D79F] = []rune{0X03C0}
	b2Table[0X1D7A0] = []rune{0X03C1}
	b2Table[0X1D7A1] = []rune{0X03B8}
	b2Table[0X1D7A2] = []rune{0X03C3}
	b2Table[0X1D7A3] = []rune{0X03C4}
	b2Table[0X1D7A4] = []rune{0X03C5}
	b2Table[0X1D7A5] = []rune{0X03C6}
	b2Table[0X1D7A6] = []rune{0X03C7}
	b2Table[0X1D7A7] = []rune{0X03C8}
	b2Table[0X1D7A8] = []rune{0X03C9}
	b2Table[0X1D7BB] = []rune{0X03C3}
	spaceTable[0X0009] = struct{}{}
	spaceTable[0X000A] = struct{}{}
	spaceTable[0X000B] = struct{}{}
	spaceTable[0X000C] = struct{}{}
	spaceTable[0X000D] = struct{}{}
	spaceTable[0X0085] = struct{}{}
	spaceTable[0X0020] = struct{}{}
	spaceTable[0X00A0] = struct{}{}
	spaceTable[0X1680] = struct{}{}
	spaceTable[0X2000] = struct{}{}
	spaceTable[0X2001] = struct{}{}
	spaceTable[0X2002] = struct{}{}
	spaceTable[0X2003] = struct{}{}
	spaceTable[0X2004] = struct{}{}
	spaceTable[0X2005] = struct{}{}
	spaceTable[0X2006] = struct{}{}
	spaceTable[0X2007] = struct{}{}
	spaceTable[0X2008] = struct{}{}
	spaceTable[0X2009] = struct{}{}
	spaceTable[0X200A] = struct{}{}
	spaceTable[0X2028] = struct{}{}
	spaceTable[0X2029] = struct{}{}
	spaceTable[0X202F] = struct{}{}
	spaceTable[0X205F] = struct{}{}
	spaceTable[0X3000] = struct{}{}
	nothingTable[0X00AD] = struct{}{}
	nothingTable[0X1806] = struct{}{}
	nothingTable[0X034F] = struct{}{}
	nothingTable[0X180B] = struct{}{}
	nothingTable[0X180C] = struct{}{}
	nothingTable[0X180D] = struct{}{}
	nothingTable[0XFE0F] = struct{}{}
	nothingTable[0XFE10] = struct{}{}
	nothingTable[0XFE11] = struct{}{}
	nothingTable[0XFE12] = struct{}{}
	nothingTable[0XFE13] = struct{}{}
	nothingTable[0XFE14] = struct{}{}
	nothingTable[0XFE15] = struct{}{}
	nothingTable[0XFE16] = struct{}{}
	nothingTable[0XFE17] = struct{}{}
	nothingTable[0XFE18] = struct{}{}
	nothingTable[0XFE19] = struct{}{}
	nothingTable[0XFE1A] = struct{}{}
	nothingTable[0XFE1B] = struct{}{}
	nothingTable[0XFE1C] = struct{}{}
	nothingTable[0XFE1D] = struct{}{}
	nothingTable[0XFE1E] = struct{}{}
	nothingTable[0XFE1F] = struct{}{}
	nothingTable[0XFE20] = struct{}{}
	nothingTable[0XFE21] = struct{}{}
	nothingTable[0XFE22] = struct{}{}
	nothingTable[0XFE23] = struct{}{}
	nothingTable[0XFE24] = struct{}{}
	nothingTable[0XFE25] = struct{}{}
	nothingTable[0XFE26] = struct{}{}
	nothingTable[0XFE27] = struct{}{}
	nothingTable[0XFE28] = struct{}{}
	nothingTable[0XFE29] = struct{}{}
	nothingTable[0XFE2A] = struct{}{}
	nothingTable[0XFE2B] = struct{}{}
	nothingTable[0XFE2C] = struct{}{}
	nothingTable[0XFE2D] = struct{}{}
	nothingTable[0XFE2E] = struct{}{}
	nothingTable[0XFE2F] = struct{}{}
	nothingTable[0XFE30] = struct{}{}
	nothingTable[0XFE31] = struct{}{}
	nothingTable[0XFE32] = struct{}{}
	nothingTable[0XFE33] = struct{}{}
	nothingTable[0XFE34] = struct{}{}
	nothingTable[0XFE35] = struct{}{}
	nothingTable[0XFE36] = struct{}{}
	nothingTable[0XFE37] = struct{}{}
	nothingTable[0XFE38] = struct{}{}
	nothingTable[0XFE39] = struct{}{}
	nothingTable[0XFE3A] = struct{}{}
	nothingTable[0XFE3B] = struct{}{}
	nothingTable[0XFE3C] = struct{}{}
	nothingTable[0XFE3D] = struct{}{}
	nothingTable[0XFE3E] = struct{}{}
	nothingTable[0XFE3F] = struct{}{}
	nothingTable[0XFE40] = struct{}{}
	nothingTable[0XFE41] = struct{}{}
	nothingTable[0XFE42] = struct{}{}
	nothingTable[0XFE43] = struct{}{}
	nothingTable[0XFE44] = struct{}{}
	nothingTable[0XFE45] = struct{}{}
	nothingTable[0XFE46] = struct{}{}
	nothingTable[0XFE47] = struct{}{}
	nothingTable[0XFE48] = struct{}{}
	nothingTable[0XFE49] = struct{}{}
	nothingTable[0XFE4A] = struct{}{}
	nothingTable[0XFE4B] = struct{}{}
	nothingTable[0XFE4C] = struct{}{}
	nothingTable[0XFE4D] = struct{}{}
	nothingTable[0XFE4E] = struct{}{}
	nothingTable[0XFE4F] = struct{}{}
	nothingTable[0XFE50] = struct{}{}
	nothingTable[0XFE51] = struct{}{}
	nothingTable[0XFE52] = struct{}{}
	nothingTable[0XFE53] = struct{}{}
	nothingTable[0XFE54] = struct{}{}
	nothingTable[0XFE55] = struct{}{}
	nothingTable[0XFE56] = struct{}{}
	nothingTable[0XFE57] = struct{}{}
	nothingTable[0XFE58] = struct{}{}
	nothingTable[0XFE59] = struct{}{}
	nothingTable[0XFE5A] = struct{}{}
	nothingTable[0XFE5B] = struct{}{}
	nothingTable[0XFE5C] = struct{}{}
	nothingTable[0XFE5D] = struct{}{}
	nothingTable[0XFE5E] = struct{}{}
	nothingTable[0XFE5F] = struct{}{}
	nothingTable[0XFE60] = struct{}{}
	nothingTable[0XFE61] = struct{}{}
	nothingTable[0XFE62] = struct{}{}
	nothingTable[0XFE63] = struct{}{}
	nothingTable[0XFE64] = struct{}{}
	nothingTable[0XFE65] = struct{}{}
	nothingTable[0XFE66] = struct{}{}
	nothingTable[0XFE67] = struct{}{}
	nothingTable[0XFE68] = struct{}{}
	nothingTable[0XFE69] = struct{}{}
	nothingTable[0XFE6A] = struct{}{}
	nothingTable[0XFE6B] = struct{}{}
	nothingTable[0XFE6C] = struct{}{}
	nothingTable[0XFE6D] = struct{}{}
	nothingTable[0XFE6E] = struct{}{}
	nothingTable[0XFE6F] = struct{}{}
	nothingTable[0XFE70] = struct{}{}
	nothingTable[0XFE71] = struct{}{}
	nothingTable[0XFE72] = struct{}{}
	nothingTable[0XFE73] = struct{}{}
	nothingTable[0XFE74] = struct{}{}
	nothingTable[0XFE75] = struct{}{}
	nothingTable[0XFE76] = struct{}{}
	nothingTable[0XFE77] = struct{}{}
	nothingTable[0XFE78] = struct{}{}
	nothingTable[0XFE79] = struct{}{}
	nothingTable[0XFE7A] = struct{}{}
	nothingTable[0XFE7B] = struct{}{}
	nothingTable[0XFE7C] = struct{}{}
	nothingTable[0XFE7D] = struct{}{}
	nothingTable[0XFE7E] = struct{}{}
	nothingTable[0XFE7F] = struct{}{}
	nothingTable[0XFE80] = struct{}{}
	nothingTable[0XFE81] = struct{}{}
	nothingTable[0XFE82] = struct{}{}
	nothingTable[0XFE83] = struct{}{}
	nothingTable[0XFE84] = struct{}{}
	nothingTable[0XFE85] = struct{}{}
	nothingTable[0XFE86] = struct{}{}
	nothingTable[0XFE87] = struct{}{}
	nothingTable[0XFE88] = struct{}{}
	nothingTable[0XFE89] = struct{}{}
	nothingTable[0XFE8A] = struct{}{}
	nothingTable[0XFE8B] = struct{}{}
	nothingTable[0XFE8C] = struct{}{}
	nothingTable[0XFE8D] = struct{}{}
	nothingTable[0XFE8E] = struct{}{}
	nothingTable[0XFE8F] = struct{}{}
	nothingTable[0XFE90] = struct{}{}
	nothingTable[0XFE91] = struct{}{}
	nothingTable[0XFE92] = struct{}{}
	nothingTable[0XFE93] = struct{}{}
	nothingTable[0XFE94] = struct{}{}
	nothingTable[0XFE95] = struct{}{}
	nothingTable[0XFE96] = struct{}{}
	nothingTable[0XFE97] = struct{}{}
	nothingTable[0XFE98] = struct{}{}
	nothingTable[0XFE99] = struct{}{}
	nothingTable[0XFE9A] = struct{}{}
	nothingTable[0XFE9B] = struct{}{}
	nothingTable[0XFE9C] = struct{}{}
	nothingTable[0XFE9D] = struct{}{}
	nothingTable[0XFE9E] = struct{}{}
	nothingTable[0XFE9F] = struct{}{}
	nothingTable[0XFEA0] = struct{}{}
	nothingTable[0XFEA1] = struct{}{}
	nothingTable[0XFEA2] = struct{}{}
	nothingTable[0XFEA3] = struct{}{}
	nothingTable[0XFEA4] = struct{}{}
	nothingTable[0XFEA5] = struct{}{}
	nothingTable[0XFEA6] = struct{}{}
	nothingTable[0XFEA7] = struct{}{}
	nothingTable[0XFEA8] = struct{}{}
	nothingTable[0XFEA9] = struct{}{}
	nothingTable[0XFEAA] = struct{}{}
	nothingTable[0XFEAB] = struct{}{}
	nothingTable[0XFEAC] = struct{}{}
	nothingTable[0XFEAD] = struct{}{}
	nothingTable[0XFEAE] = struct{}{}
	nothingTable[0XFEAF] = struct{}{}
	nothingTable[0XFEB0] = struct{}{}
	nothingTable[0XFEB1] = struct{}{}
	nothingTable[0XFEB2] = struct{}{}
	nothingTable[0XFEB3] = struct{}{}
	nothingTable[0XFEB4] = struct{}{}
	nothingTable[0XFEB5] = struct{}{}
	nothingTable[0XFEB6] = struct{}{}
	nothingTable[0XFEB7] = struct{}{}
	nothingTable[0XFEB8] = struct{}{}
	nothingTable[0XFEB9] = struct{}{}
	nothingTable[0XFEBA] = struct{}{}
	nothingTable[0XFEBB] = struct{}{}
	nothingTable[0XFEBC] = struct{}{}
	nothingTable[0XFEBD] = struct{}{}
	nothingTable[0XFEBE] = struct{}{}
	nothingTable[0XFEBF] = struct{}{}
	nothingTable[0XFEC0] = struct{}{}
	nothingTable[0XFEC1] = struct{}{}
	nothingTable[0XFEC2] = struct{}{}
	nothingTable[0XFEC3] = struct{}{}
	nothingTable[0XFEC4] = struct{}{}
	nothingTable[0XFEC5] = struct{}{}
	nothingTable[0XFEC6] = struct{}{}
	nothingTable[0XFEC7] = struct{}{}
	nothingTable[0XFEC8] = struct{}{}
	nothingTable[0XFEC9] = struct{}{}
	nothingTable[0XFECA] = struct{}{}
	nothingTable[0XFECB] = struct{}{}
	nothingTable[0XFECC] = struct{}{}
	nothingTable[0XFECD] = struct{}{}
	nothingTable[0XFECE] = struct{}{}
	nothingTable[0XFECF] = struct{}{}
	nothingTable[0XFED0] = struct{}{}
	nothingTable[0XFED1] = struct{}{}
	nothingTable[0XFED2] = struct{}{}
	nothingTable[0XFED3] = struct{}{}
	nothingTable[0XFED4] = struct{}{}
	nothingTable[0XFED5] = struct{}{}
	nothingTable[0XFED6] = struct{}{}
	nothingTable[0XFED7] = struct{}{}
	nothingTable[0XFED8] = struct{}{}
	nothingTable[0XFED9] = struct{}{}
	nothingTable[0XFEDA] = struct{}{}
	nothingTable[0XFEDB] = struct{}{}
	nothingTable[0XFEDC] = struct{}{}
	nothingTable[0XFEDD] = struct{}{}
	nothingTable[0XFEDE] = struct{}{}
	nothingTable[0XFEDF] = struct{}{}
	nothingTable[0XFEE0] = struct{}{}
	nothingTable[0XFEE1] = struct{}{}
	nothingTable[0XFEE2] = struct{}{}
	nothingTable[0XFEE3] = struct{}{}
	nothingTable[0XFEE4] = struct{}{}
	nothingTable[0XFEE5] = struct{}{}
	nothingTable[0XFEE6] = struct{}{}
	nothingTable[0XFEE7] = struct{}{}
	nothingTable[0XFEE8] = struct{}{}
	nothingTable[0XFEE9] = struct{}{}
	nothingTable[0XFEEA] = struct{}{}
	nothingTable[0XFEEB] = struct{}{}
	nothingTable[0XFEEC] = struct{}{}
	nothingTable[0XFEED] = struct{}{}
	nothingTable[0XFEEE] = struct{}{}
	nothingTable[0XFEEF] = struct{}{}
	nothingTable[0XFEF0] = struct{}{}
	nothingTable[0XFEF1] = struct{}{}
	nothingTable[0XFEF2] = struct{}{}
	nothingTable[0XFEF3] = struct{}{}
	nothingTable[0XFEF4] = struct{}{}
	nothingTable[0XFEF5] = struct{}{}
	nothingTable[0XFEF6] = struct{}{}
	nothingTable[0XFEF7] = struct{}{}
	nothingTable[0XFEF8] = struct{}{}
	nothingTable[0XFEF9] = struct{}{}
	nothingTable[0XFEFA] = struct{}{}
	nothingTable[0XFEFB] = struct{}{}
	nothingTable[0XFEFC] = struct{}{}
	nothingTable[0XFEFD] = struct{}{}
	nothingTable[0XFEFE] = struct{}{}
	nothingTable[0XFEFF] = struct{}{}
	nothingTable[0XFF00] = struct{}{}
	nothingTable[0XFFFC] = struct{}{}
	nothingTable[0X0000] = struct{}{}
	nothingTable[0X0001] = struct{}{}
	nothingTable[0X0002] = struct{}{}
	nothingTable[0X0003] = struct{}{}
	nothingTable[0X0004] = struct{}{}
	nothingTable[0X0005] = struct{}{}
	nothingTable[0X0006] = struct{}{}
	nothingTable[0X0007] = struct{}{}
	nothingTable[0X0008] = struct{}{}
	nothingTable[0X000E] = struct{}{}
	nothingTable[0X000F] = struct{}{}
	nothingTable[0X0010] = struct{}{}
	nothingTable[0X0011] = struct{}{}
	nothingTable[0X0012] = struct{}{}
	nothingTable[0X0013] = struct{}{}
	nothingTable[0X0014] = struct{}{}
	nothingTable[0X0015] = struct{}{}
	nothingTable[0X0016] = struct{}{}
	nothingTable[0X0017] = struct{}{}
	nothingTable[0X0018] = struct{}{}
	nothingTable[0X0019] = struct{}{}
	nothingTable[0X001A] = struct{}{}
	nothingTable[0X001B] = struct{}{}
	nothingTable[0X001C] = struct{}{}
	nothingTable[0X001D] = struct{}{}
	nothingTable[0X001E] = struct{}{}
	nothingTable[0X001F] = struct{}{}
	nothingTable[0X007F] = struct{}{}
	nothingTable[0X0080] = struct{}{}
	nothingTable[0X0081] = struct{}{}
	nothingTable[0X0082] = struct{}{}
	nothingTable[0X0083] = struct{}{}
	nothingTable[0X0084] = struct{}{}
	nothingTable[0X0086] = struct{}{}
	nothingTable[0X0087] = struct{}{}
	nothingTable[0X0088] = struct{}{}
	nothingTable[0X0089] = struct{}{}
	nothingTable[0X008A] = struct{}{}
	nothingTable[0X008B] = struct{}{}
	nothingTable[0X008C] = struct{}{}
	nothingTable[0X008D] = struct{}{}
	nothingTable[0X008E] = struct{}{}
	nothingTable[0X008F] = struct{}{}
	nothingTable[0X0090] = struct{}{}
	nothingTable[0X0091] = struct{}{}
	nothingTable[0X0092] = struct{}{}
	nothingTable[0X0093] = struct{}{}
	nothingTable[0X0094] = struct{}{}
	nothingTable[0X0095] = struct{}{}
	nothingTable[0X0096] = struct{}{}
	nothingTable[0X0097] = struct{}{}
	nothingTable[0X0098] = struct{}{}
	nothingTable[0X0099] = struct{}{}
	nothingTable[0X009A] = struct{}{}
	nothingTable[0X009B] = struct{}{}
	nothingTable[0X009C] = struct{}{}
	nothingTable[0X009D] = struct{}{}
	nothingTable[0X009E] = struct{}{}
	nothingTable[0X009F] = struct{}{}
	nothingTable[0X06DD] = struct{}{}
	nothingTable[0X070F] = struct{}{}
	nothingTable[0X180E] = struct{}{}
	nothingTable[0X200C] = struct{}{}
	nothingTable[0X200D] = struct{}{}
	nothingTable[0X200E] = struct{}{}
	nothingTable[0X200F] = struct{}{}
	nothingTable[0X202A] = struct{}{}
	nothingTable[0X202B] = struct{}{}
	nothingTable[0X202C] = struct{}{}
	nothingTable[0X202D] = struct{}{}
	nothingTable[0X202E] = struct{}{}
	nothingTable[0X2060] = struct{}{}
	nothingTable[0X2061] = struct{}{}
	nothingTable[0X2062] = struct{}{}
	nothingTable[0X2063] = struct{}{}
	nothingTable[0X206A] = struct{}{}
	nothingTable[0X206B] = struct{}{}
	nothingTable[0X206C] = struct{}{}
	nothingTable[0X206D] = struct{}{}
	nothingTable[0X206E] = struct{}{}
	nothingTable[0X206F] = struct{}{}
	nothingTable[0XFEFF] = struct{}{}
	nothingTable[0XFFF9] = struct{}{}
	nothingTable[0XFFFA] = struct{}{}
	nothingTable[0XFFFB] = struct{}{}
	nothingTable[0X1D173] = struct{}{}
	nothingTable[0X1D174] = struct{}{}
	nothingTable[0X1D175] = struct{}{}
	nothingTable[0X1D176] = struct{}{}
	nothingTable[0X1D177] = struct{}{}
	nothingTable[0X1D178] = struct{}{}
	nothingTable[0X1D179] = struct{}{}
	nothingTable[0X1D17A] = struct{}{}
	nothingTable[0XE0001] = struct{}{}
	nothingTable[0XE0020] = struct{}{}
	nothingTable[0XE0021] = struct{}{}
	nothingTable[0XE0022] = struct{}{}
	nothingTable[0XE0023] = struct{}{}
	nothingTable[0XE0024] = struct{}{}
	nothingTable[0XE0025] = struct{}{}
	nothingTable[0XE0026] = struct{}{}
	nothingTable[0XE0027] = struct{}{}
	nothingTable[0XE0028] = struct{}{}
	nothingTable[0XE0029] = struct{}{}
	nothingTable[0XE002A] = struct{}{}
	nothingTable[0XE002B] = struct{}{}
	nothingTable[0XE002C] = struct{}{}
	nothingTable[0XE002D] = struct{}{}
	nothingTable[0XE002E] = struct{}{}
	nothingTable[0XE002F] = struct{}{}
	nothingTable[0XE0030] = struct{}{}
	nothingTable[0XE0031] = struct{}{}
	nothingTable[0XE0032] = struct{}{}
	nothingTable[0XE0033] = struct{}{}
	nothingTable[0XE0034] = struct{}{}
	nothingTable[0XE0035] = struct{}{}
	nothingTable[0XE0036] = struct{}{}
	nothingTable[0XE0037] = struct{}{}
	nothingTable[0XE0038] = struct{}{}
	nothingTable[0XE0039] = struct{}{}
	nothingTable[0XE003A] = struct{}{}
	nothingTable[0XE003B] = struct{}{}
	nothingTable[0XE003C] = struct{}{}
	nothingTable[0XE003D] = struct{}{}
	nothingTable[0XE003E] = struct{}{}
	nothingTable[0XE003F] = struct{}{}
	nothingTable[0XE0040] = struct{}{}
	nothingTable[0XE0041] = struct{}{}
	nothingTable[0XE0042] = struct{}{}
	nothingTable[0XE0043] = struct{}{}
	nothingTable[0XE0044] = struct{}{}
	nothingTable[0XE0045] = struct{}{}
	nothingTable[0XE0046] = struct{}{}
	nothingTable[0XE0047] = struct{}{}
	nothingTable[0XE0048] = struct{}{}
	nothingTable[0XE0049] = struct{}{}
	nothingTable[0XE004A] = struct{}{}
	nothingTable[0XE004B] = struct{}{}
	nothingTable[0XE004C] = struct{}{}
	nothingTable[0XE004D] = struct{}{}
	nothingTable[0XE004E] = struct{}{}
	nothingTable[0XE004F] = struct{}{}
	nothingTable[0XE0050] = struct{}{}
	nothingTable[0XE0051] = struct{}{}
	nothingTable[0XE0052] = struct{}{}
	nothingTable[0XE0053] = struct{}{}
	nothingTable[0XE0054] = struct{}{}
	nothingTable[0XE0055] = struct{}{}
	nothingTable[0XE0056] = struct{}{}
	nothingTable[0XE0057] = struct{}{}
	nothingTable[0XE0058] = struct{}{}
	nothingTable[0XE0059] = struct{}{}
	nothingTable[0XE005A] = struct{}{}
	nothingTable[0XE005B] = struct{}{}
	nothingTable[0XE005C] = struct{}{}
	nothingTable[0XE005D] = struct{}{}
	nothingTable[0XE005E] = struct{}{}
	nothingTable[0XE005F] = struct{}{}
	nothingTable[0XE0060] = struct{}{}
	nothingTable[0XE0061] = struct{}{}
	nothingTable[0XE0062] = struct{}{}
	nothingTable[0XE0063] = struct{}{}
	nothingTable[0XE0064] = struct{}{}
	nothingTable[0XE0065] = struct{}{}
	nothingTable[0XE0066] = struct{}{}
	nothingTable[0XE0067] = struct{}{}
	nothingTable[0XE0068] = struct{}{}
	nothingTable[0XE0069] = struct{}{}
	nothingTable[0XE006A] = struct{}{}
	nothingTable[0XE006B] = struct{}{}
	nothingTable[0XE006C] = struct{}{}
	nothingTable[0XE006D] = struct{}{}
	nothingTable[0XE006E] = struct{}{}
	nothingTable[0XE006F] = struct{}{}
	nothingTable[0XE0070] = struct{}{}
	nothingTable[0XE0071] = struct{}{}
	nothingTable[0XE0072] = struct{}{}
	nothingTable[0XE0073] = struct{}{}
	nothingTable[0XE0074] = struct{}{}
	nothingTable[0XE0075] = struct{}{}
	nothingTable[0XE0076] = struct{}{}
	nothingTable[0XE0077] = struct{}{}
	nothingTable[0XE0078] = struct{}{}
	nothingTable[0XE0079] = struct{}{}
	nothingTable[0XE007A] = struct{}{}
	nothingTable[0XE007B] = struct{}{}
	nothingTable[0XE007C] = struct{}{}
	nothingTable[0XE007D] = struct{}{}
	nothingTable[0XE007E] = struct{}{}
	nothingTable[0XE007F] = struct{}{}
	nothingTable[0X200B] = struct{}{}

}
