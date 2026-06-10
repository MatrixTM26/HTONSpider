package lib

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ColorReset   = "\033[0m"
	ColorWhite   = "\033[97m"
	ColorBlue    = "\033[34m"
	ColorYellow  = "\033[33m"
	ColorMagenta = "\033[35m"
	ColorRed     = "\033[31m"
	ColorCyan    = "\033[36m"
	ColorGreen   = "\033[32m"
	ColorGray    = "\033[90m"
	ColorBold    = "\033[1m"
)

type WinSize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func TermWidth() int {
	WS := &WinSize{}
	Ret, _, _ := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(os.Stdout.Fd()),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(WS)),
	)
	if Ret != 0 || WS.Col < 40 {
		return 80
	}
	return int(WS.Col)
}

func FrameLine() string {
	return strings.Repeat("-", TermWidth())
}

func LogInfo(Msg string) {
	fmt.Printf("%s[%s%sINFO%s%s]%s  %s\n",
		ColorWhite, ColorReset, ColorBlue+ColorBold, ColorReset, ColorWhite, ColorReset, Msg)
}

func LogWarn(Msg string) {
	fmt.Printf("%s[%s%sWARN%s%s]%s  %s\n",
		ColorWhite, ColorReset, ColorYellow+ColorBold, ColorReset, ColorWhite, ColorReset, Msg)
}

func LogDebug(Msg string) {
	fmt.Printf("%s[%s%sDEBUG%s%s]%s %s\n",
		ColorWhite, ColorReset, ColorMagenta+ColorBold, ColorReset, ColorWhite, ColorReset, Msg)
}

func LogError(Msg string) {
	fmt.Printf("%s[%s%sERROR%s%s]%s %s\n",
		ColorWhite, ColorReset, ColorRed+ColorBold, ColorReset, ColorWhite, ColorReset, Msg)
}

func LogSuccess(Msg string) {
	fmt.Printf("%s[%s%sOK%s%s]%s    %s\n",
		ColorWhite, ColorReset, ColorGreen+ColorBold, ColorReset, ColorWhite, ColorReset, Msg)
}

func PrintFrame() {
	fmt.Printf("%s%s%s\n", ColorGray, FrameLine(), ColorReset)
}

func PrintTitle(Title string) {
	fmt.Println()
	PrintFrame()
	fmt.Printf("%s  %s%s\n", ColorCyan+ColorBold, Title, ColorReset)
	PrintFrame()
}

func Colorize(Color string, Text string) string {
	return Color + Text + ColorReset
}

func TableRow(Cols []string, Widths []int) string {
	var B strings.Builder
	B.WriteString("  ")
	for I, Col := range Cols {
		if I < len(Widths) {
			B.WriteString(fmt.Sprintf("%-*s ", Widths[I], Col))
		} else {
			B.WriteString(Col)
		}
	}
	B.WriteString("\n")
	return B.String()
}

func CalcColWidths(Headers []string, Rows [][]string, TotalWidth int) []int {
	Widths := make([]int, len(Headers))
	for I, H := range Headers {
		Widths[I] = len(H)
	}
	for _, Row := range Rows {
		for I, Cell := range Row {
			if I < len(Widths) && len(Cell) > Widths[I] {
				Widths[I] = len(Cell)
			}
		}
	}
	Used := 2
	for _, W := range Widths {
		Used += W + 1
	}
	Extra := TotalWidth - Used
	if Extra > 0 && len(Widths) > 0 {
		Widths[len(Widths)-1] += Extra
	}
	return Widths
}

var VerboseMode = false

func LogInfoV(Msg string) {
	LogInfo(Msg)
}

func LogDebugV(Msg string) {
	if VerboseMode {
		LogDebug(Msg)
	}
}
