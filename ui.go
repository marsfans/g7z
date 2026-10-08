package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/pterm/pterm"
	"golang.org/x/term"
)

var (
	quiet      bool
	stderrTTY  bool
	stdinTTY   bool
	termOut    *termenv.Output
	styleBar   = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))
	styleEmpty = lipgloss.NewStyle().Foreground(lipgloss.Color("#3C3C3C"))
	styleLabel = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#04B575"))
	styleDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	styleNum   = lipgloss.NewStyle().Foreground(lipgloss.Color("#F2C94C"))
)

func initUI(noColor bool) {
	stderrTTY = term.IsTerminal(int(os.Stderr.Fd()))
	stdinTTY = term.IsTerminal(int(os.Stdin.Fd()))
	termOut = termenv.NewOutput(os.Stderr)
	_, _ = termenv.EnableVirtualTerminalProcessing(termOut)
	profile := termOut.EnvColorProfile()
	if noColor || !stderrTTY {
		profile = termenv.Ascii
	}
	lipgloss.SetColorProfile(profile)
	if profile == termenv.Ascii {
		pterm.DisableColor()
	}
	pterm.SetDefaultOutput(os.Stderr)
	pterm.Info.Prefix.Text = " 信息 "
	pterm.Success.Prefix.Text = " 完成 "
	pterm.Warning.Prefix.Text = " 警告 "
	pterm.Error.Prefix.Text = " 错误 "
}

func logInfo(f string, a ...any) {
	if !quiet {
		clearLine()
		pterm.Info.Printfln(f, a...)
	}
}
func logWarn(f string, a ...any) { clearLine(); pterm.Warning.Printfln(f, a...) }
func logErr(f string, a ...any)  { clearLine(); pterm.Error.Printfln(f, a...) }
func logOK(f string, a ...any) {
	if !quiet {
		clearLine()
		pterm.Success.Printfln(f, a...)
	}
}

var lineMu sync.Mutex
var lineDirty bool

func clearLine() {
	lineMu.Lock()
	defer lineMu.Unlock()
	if lineDirty {
		fmt.Fprint(os.Stderr, "\r\033[K")
		lineDirty = false
	}
}

func humanBytes(n int64) string {
	if n < 0 {
		return "?"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Progress 统计处理过的原始字节，并用 lipgloss 渲染单行进度条
type Progress struct {
	label   string
	total   int64
	done    atomic.Int64
	cur     atomic.Value
	start   time.Time
	enabled bool
	stop    chan struct{}
	wg      sync.WaitGroup
}

func NewProgress(label string, total int64) *Progress {
	p := &Progress{label: label, total: total, start: time.Now(), enabled: stderrTTY && !quiet, stop: make(chan struct{})}
	p.cur.Store("")
	if p.enabled {
		p.wg.Add(1)
		go p.loop()
	}
	return p
}

func (p *Progress) Write(b []byte) (int, error) {
	if p != nil {
		p.done.Add(int64(len(b)))
	}
	return len(b), nil
}

func (p *Progress) Add(n int64) {
	if p != nil {
		p.done.Add(n)
	}
}

func (p *Progress) SetCurrent(name string) {
	if p != nil {
		p.cur.Store(name)
	}
}

func (p *Progress) Done() int64 { return p.done.Load() }

func (p *Progress) Elapsed() time.Duration { return time.Since(p.start) }

func (p *Progress) Finish() {
	if p == nil {
		return
	}
	if p.enabled {
		close(p.stop)
		p.wg.Wait()
		clearLine()
	}
}

func (p *Progress) loop() {
	defer p.wg.Done()
	t := time.NewTicker(120 * time.Millisecond)
	defer t.Stop()
	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			i++
			p.render(spin[i%len(spin)])
		}
	}
}

func (p *Progress) render(spin string) {
	width := 100
	if w, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil && w > 20 {
		width = w
	}
	done := p.done.Load()
	el := time.Since(p.start).Seconds()
	speed := float64(done) / maxf(el, 0.001)
	var b strings.Builder
	b.WriteString(styleLabel.Render(p.label) + " ")
	if p.total > 0 {
		pct := float64(done) / float64(p.total)
		if pct > 1 {
			pct = 1
		}
		barW := 28
		fill := int(pct * float64(barW))
		b.WriteString(styleBar.Render(strings.Repeat("█", fill)) + styleEmpty.Render(strings.Repeat("░", barW-fill)))
		eta := "--"
		if speed > 0 {
			eta = (time.Duration(float64(p.total-done)/speed) * time.Second / time.Second * time.Second).Round(time.Second).String()
		}
		b.WriteString(fmt.Sprintf(" %s %s/%s %s/s ETA %s",
			styleNum.Render(fmt.Sprintf("%5.1f%%", pct*100)), humanBytes(done), humanBytes(p.total), humanBytes(int64(speed)), eta))
	} else {
		b.WriteString(styleBar.Render(spin) + fmt.Sprintf(" %s  %s/s", humanBytes(done), humanBytes(int64(speed))))
	}
	line := b.String()
	cur, _ := p.cur.Load().(string)
	room := width - lipgloss.Width(line) - 3
	if room > 8 && cur != "" {
		r := []rune(cur)
		for lipgloss.Width(string(r)) > room && len(r) > 1 {
			r = r[1:]
		}
		line += "  " + styleDim.Render(string(r))
	}
	lineMu.Lock()
	fmt.Fprint(os.Stderr, "\r\033[K"+line)
	lineDirty = true
	lineMu.Unlock()
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// summary 用 pterm 打印结束汇总
func summary(title string, rows [][]string) {
	if quiet {
		return
	}
	clearLine()
	data := pterm.TableData{{"项目", "值"}}
	data = append(data, rows...)
	pterm.DefaultSection.WithLevel(2).Println(title)
	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(data).Render()
}

func askPassword(prompt string) (string, error) {
	if !stdinTTY {
		return "", fmt.Errorf("需要密码，请使用 -p 指定")
	}
	clearLine()
	return pterm.DefaultInteractiveTextInput.WithMask("*").Show(prompt)
}
