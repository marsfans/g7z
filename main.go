package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var version = "1.0.0"

const sampleConfig = `# g7z 配置文件（命令行参数优先于此文件，环境变量 G7Z_<KEY> 也可覆盖）
# 默认归档格式（输出文件没有可识别扩展名时使用）
type: 7z
# 压缩级别 0-9（0=仅存储）
level: 5
# 线程数，0 表示使用全部 CPU
threads: 0
# 7z 固实块大小，如 16m / 64m / 1g，0 或 off 表示每个文件单独成块
solid: 64m
# 解压遇到同名文件：ask 询问 / a 覆盖 / s 跳过 / u 自动重命名
overwrite: ask
# 压缩时排除的文件（通配符）
exclude:
  - "*.g7ztmp"
# 关闭彩色输出
no-color: false
`

// 7z 风格参数改写：-mx9 -mmt4 -ms=64m -aoa -p
func rewriteArgs(args []string) []string {
	out := make([]string, 0, len(args))
	re := map[*regexp.Regexp]string{
		regexp.MustCompile(`^-mx=?(\d)$`):          "--level=$1",
		regexp.MustCompile(`^-mmt=?(\d+|on|off)$`): "--threads=$1",
		regexp.MustCompile(`^-ms=?([\w]+)$`):       "--solid=$1",
		regexp.MustCompile(`^-ao([asu])$`):         "--overwrite=$1",
		regexp.MustCompile(`^-sccrc(\w+)$`):        "--algo=$1",
		regexp.MustCompile(`^-scrc(\w+)$`):         "--algo=$1",
	}
	afterDD := false
	for _, a := range args {
		if a == "--" {
			afterDD = true
		}
		if !afterDD {
			if a == "-p" {
				out = append(out, "--ask-password")
				continue
			}
			done := false
			for r, rep := range re {
				if r.MatchString(a) {
					v := r.ReplaceAllString(a, rep)
					v = strings.Replace(v, "=on", "=0", 1)
					v = strings.Replace(v, "--threads=off", "--threads=1", 1)
					out = append(out, v)
					done = true
					break
				}
			}
			if done {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

func parseSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "off", "0", "false":
		return 1, nil // 每个文件单独成块
	case "on", "true", "e":
		return 1 << 62, nil
	}
	mul := int64(1)
	switch s[len(s)-1] {
	case 'k':
		mul = 1 << 10
	case 'm':
		mul = 1 << 20
	case 'g':
		mul = 1 << 30
	case 'b':
		mul = 1
	}
	if mul != 1 || s[len(s)-1] == 'b' {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("无效大小: %s", s)
	}
	return n * mul, nil
}

func threads() int {
	n := viper.GetInt("threads")
	if n <= 0 {
		n = runtime.NumCPU()
	}
	return n
}

func getPassword(cmd *cobra.Command, prompt string, confirm bool) (string, error) {
	pw := viper.GetString("password")
	if pw == "" {
		if ask, _ := cmd.Flags().GetBool("ask-password"); ask {
			p, err := askPassword(prompt)
			if err != nil {
				return "", err
			}
			if confirm {
				p2, err := askPassword("再次输入密码")
				if err != nil {
					return "", err
				}
				if p != p2 {
					return "", errors.New("两次输入的密码不一致")
				}
			}
			pw = p
		}
	}
	return pw, nil
}

// openArchiveInteractive 识别格式并在需要时提示密码
func prepareRead(cmd *cobra.Command, archive string) (*Format, string, error) {
	if _, err := os.Stat(archive); err != nil {
		return nil, "", err
	}
	fm, err := sniffFormat(archive)
	if err != nil {
		return nil, "", err
	}
	if t := viper.GetString("type"); t != "" && cmd.Flags().Changed("type") {
		if fm, err = formatByName(t); err != nil {
			return nil, "", err
		}
	}
	pw, err := getPassword(cmd, "输入密码", false)
	if err != nil {
		return nil, "", err
	}
	if pw == "" && needsPassword(archive, fm) {
		if pw, err = askPassword("归档已加密，输入密码"); err != nil {
			return nil, "", err
		}
	}
	return fm, pw, nil
}

func main() {
	var cfgFile string
	var noColor bool
	exitCode := 0

	root := &cobra.Command{
		Use:   "g7z",
		Short: "g7z — 类 7-Zip 的多格式压缩/解压工具",
		Long: `g7z — 类 7-Zip 的多格式压缩/解压工具（Go 实现）

写入: 7z zip tar tar.gz tar.bz2 tar.xz tar.zst tar.lz4 tar.br gz bz2 xz zst lz4 br
读取: 以上全部 + rar(4/5)；7z/zip 支持 AES-256 加密
兼容 7z 风格参数: -mx9  -mmt8  -ms=64m  -aoa/-aos/-aou  -p(交互输入密码)  -pPASS  -oDIR  -tzip`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cmd.Flags().VisitAll(func(f *pflag.Flag) { _ = viper.BindPFlag(f.Name, f) })
			viper.SetEnvPrefix("G7Z")
			viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
			viper.AutomaticEnv()
			viper.SetDefault("level", 5)
			viper.SetDefault("solid", "64m")
			viper.SetDefault("overwrite", "ask")
			if cfgFile == "" {
				cfgFile = os.Getenv("G7Z_CONFIG")
			}
			if cfgFile != "" {
				viper.SetConfigFile(cfgFile)
			} else {
				viper.SetConfigName("g7z")
				viper.SetConfigType("yaml")
				viper.AddConfigPath(".")
				if d, err := os.UserConfigDir(); err == nil {
					viper.AddConfigPath(filepath.Join(d, "g7z"))
				}
				if h, err := os.UserHomeDir(); err == nil {
					viper.AddConfigPath(h)
					viper.AddConfigPath(filepath.Join(h, ".config", "g7z"))
				}
			}
			if err := viper.ReadInConfig(); err != nil {
				var nf viper.ConfigFileNotFoundError
				if !errors.As(err, &nf) && cfgFile != "" {
					return fmt.Errorf("读取配置失败: %w", err)
				}
			}
			initUI(noColor || viper.GetBool("no-color"))
			return nil
		},
	}
	root.PersistentFlags().StringVar(&cfgFile, "config", "", "配置文件路径（默认 ./g7z.yaml 或 ~/.config/g7z/g7z.yaml）")
	root.PersistentFlags().BoolVar(&noColor, "no-color", false, "关闭彩色输出")
	root.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "安静模式，不显示进度")
	root.SetVersionTemplate("g7z {{.Version}}\n")

	// ---------- a ----------
	addCmd := &cobra.Command{
		Use:     "a <归档> <文件/目录...>",
		Aliases: []string{"add"},
		Short:   "压缩：创建归档",
		Example: "  g7z a backup.7z ./docs ./src -mx9 -p\n  g7z a site.tar.zst /var/www -mmt8\n  g7z a pack.zip *.log -pSecret -x '*.tmp'\n  g7z a big.iso.xz big.iso",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := args[0]
			var fm *Format
			var err error
			if cmd.Flags().Changed("type") || formatByExt(out) == nil {
				if fm, err = formatByName(viper.GetString("type")); err != nil {
					return err
				}
				if formatByExt(out) == nil {
					out += fm.Exts[0]
				}
			} else {
				fm = formatByExt(out)
			}
			if !fm.Write {
				return fmt.Errorf("%s 格式只支持读取，不能创建", fm.Name)
			}
			level := viper.GetInt("level")
			if level < 0 || level > 9 {
				return errors.New("压缩级别需在 0-9 之间")
			}
			solid, err := parseSize(viper.GetString("solid"))
			if err != nil {
				return err
			}
			pw, err := getPassword(cmd, "设置密码", true)
			if err != nil {
				return err
			}
			if pw != "" && fm.Name != "7z" && fm.Name != "zip" {
				return fmt.Errorf("%s 不支持加密，请用 7z 或 zip", fm.Name)
			}
			opt := AddOptions{Format: fm, Level: level, Password: pw, Threads: threads(), Solid: solid, Excludes: viper.GetStringSlice("exclude"), Recursive: viper.GetBool("recursive")}
			files, err := collectInputs(args[1:], opt, strings.HasPrefix(fm.Name, "tar"), out)
			if err != nil {
				return err
			}
			total, nf, nd := totalSize(files)
			logInfo("创建 %s [%s]  %d 个文件, %d 个目录, 共 %s  级别 %d  线程 %d", out, fm.Name, nf, nd, humanBytes(total), level, opt.Threads)
			prog := NewProgress("压缩", total)
			err = createArchive(out, files, opt, prog)
			prog.Finish()
			if err != nil {
				return err
			}
			st, _ := os.Stat(out)
			el := prog.Elapsed()
			ratio := "-"
			if total > 0 {
				ratio = fmt.Sprintf("%.1f%%", float64(st.Size())*100/float64(total))
			}
			enc := "无"
			if pw != "" {
				enc = "AES-256"
			}
			summary("压缩完成", [][]string{
				{"归档", out}, {"格式", fm.Name}, {"文件 / 目录", fmt.Sprintf("%d / %d", nf, nd)},
				{"原始大小", humanBytes(total)}, {"压缩后", humanBytes(st.Size())}, {"压缩率", ratio},
				{"加密", enc}, {"耗时", el.Round(time.Millisecond).String()}, {"速度", humanBytes(int64(float64(total)/maxf(el.Seconds(), 0.001))) + "/s"},
			})
			return nil
		},
	}
	addCmd.Flags().StringP("type", "t", "7z", "归档格式（7z zip tar tar.gz tar.bz2 tar.xz tar.zst tar.lz4 tar.br gz bz2 xz zst lz4 br）")
	addCmd.Flags().Int("level", 5, "压缩级别 0-9，等同 -mx9")
	addCmd.Flags().Int("threads", 0, "线程数，0=全部 CPU，等同 -mmt8")
	addCmd.Flags().String("solid", "64m", "7z 固实块大小，off=不固实，等同 -ms=64m")
	addCmd.Flags().StringP("password", "p", "", "加密密码（7z/zip，AES-256）；单独 -p 交互输入")
	addCmd.Flags().Bool("ask-password", false, "交互输入密码")
	addCmd.Flags().StringSliceP("exclude", "x", nil, "排除的文件通配符，可多次使用")
	addCmd.Flags().BoolP("recursive", "r", true, "递归子目录")
	_ = addCmd.Flags().MarkHidden("ask-password")

	// ---------- x / e ----------
	mkExtract := func(use, short string, flat bool, aliases []string) *cobra.Command {
		c := &cobra.Command{
			Use:     use + " <归档> [要解压的文件/通配符...]",
			Aliases: aliases,
			Short:   short,
			Args:    cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				archive := args[0]
				fm, pw, err := prepareRead(cmd, archive)
				if err != nil {
					return err
				}
				ow := viper.GetString("overwrite")
				if y, _ := cmd.Flags().GetBool("yes"); y {
					ow = "a"
				}
				opt := &ExtractOptions{OutDir: viper.GetString("output"), Flat: flat, Overwrite: ow, Filters: args[1:], Password: pw}
				if opt.OutDir == "" {
					opt.OutDir = "."
				}
				if err := os.MkdirAll(opt.OutDir, 0o755); err != nil {
					return err
				}
				logInfo("解压 %s [%s] → %s", archive, fm.Name, opt.OutDir)
				prog := NewProgress("解压", archiveTotal(archive, fm, pw, opt.Filters))
				st, err := runExtract(archive, fm, opt, prog)
				prog.Finish()
				if err != nil {
					if errors.Is(err, errNeedPassword) {
						return errors.New("归档已加密，请用 -p 指定密码")
					}
					return err
				}
				el := prog.Elapsed()
				summary("解压完成", [][]string{
					{"归档", archive}, {"格式", fm.Name}, {"输出目录", opt.OutDir},
					{"文件 / 目录", fmt.Sprintf("%d / %d", st.Files, st.Dirs)}, {"跳过", strconv.Itoa(st.Skipped)}, {"错误", strconv.Itoa(st.Errors)},
					{"大小", humanBytes(st.Bytes)}, {"耗时", el.Round(time.Millisecond).String()}, {"速度", humanBytes(int64(float64(st.Bytes)/maxf(el.Seconds(), 0.001))) + "/s"},
				})
				if st.Errors > 0 {
					exitCode = 2
				}
				return nil
			},
		}
		c.Flags().StringP("output", "o", ".", "输出目录，等同 -oDIR")
		c.Flags().StringP("password", "p", "", "密码；单独 -p 交互输入")
		c.Flags().Bool("ask-password", false, "交互输入密码")
		c.Flags().String("overwrite", "ask", "同名文件处理: ask/a/s/u，等同 -aoa -aos -aou")
		c.Flags().BoolP("yes", "y", false, "全部覆盖，不询问")
		c.Flags().StringP("type", "t", "", "强制指定格式")
		_ = c.Flags().MarkHidden("ask-password")
		return c
	}
	xCmd := mkExtract("x", "解压（保留完整路径）", false, []string{"extract"})
	eCmd := mkExtract("e", "解压到同一目录（不保留路径）", true, nil)

	// ---------- l ----------
	lCmd := &cobra.Command{
		Use:     "l <归档>",
		Aliases: []string{"list"},
		Short:   "列出归档内容",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive := args[0]
			fm, pw, err := prepareRead(cmd, archive)
			if err != nil {
				return err
			}
			data := pterm.TableData{{"修改时间", "属性", "大小", "压缩后", "名称"}}
			var total, packed int64
			nf, nd := 0, 0
			err = walkArchive(archive, fm, pw, func(e *Entry, open func() (io.ReadCloser, error)) error {
				size := e.Size
				if size < 0 && fm.Archive == false {
					// 单文件流需要解压才能知道大小
					if rc, err := open(); err == nil {
						size, _ = io.Copy(io.Discard, rc)
						rc.Close()
					}
				}
				attr := e.Mode.String()
				if e.Encrypted {
					attr += " *"
				}
				ps := "-"
				if e.Packed >= 0 {
					ps = humanBytes(e.Packed)
					packed += e.Packed
				}
				ss := humanBytes(size)
				if e.IsDir {
					ss = "<DIR>"
					nd++
				} else {
					nf++
					if size > 0 {
						total += size
					}
				}
				name := e.Name
				if e.Link != "" {
					name += " -> " + e.Link
				}
				mt := "-"
				if !e.ModTime.IsZero() {
					mt = e.ModTime.Local().Format("2006-01-02 15:04:05")
				}
				data = append(data, []string{mt, attr, ss, ps, name})
				return nil
			})
			if err != nil {
				if errors.Is(err, errNeedPassword) {
					return errors.New("归档已加密，请用 -p 指定密码")
				}
				return err
			}
			st, _ := os.Stat(archive)
			pterm.DefaultSection.WithLevel(2).Printfln("%s  [%s]  %s", archive, fm.Name, humanBytes(st.Size()))
			_ = pterm.DefaultTable.WithHasHeader().WithRightAlignment(false).WithData(data).WithWriter(os.Stdout).Render()
			ps := "-"
			if packed > 0 {
				ps = humanBytes(packed)
			}
			fmt.Printf("\n共 %d 个文件, %d 个目录, 原始 %s, 压缩后 %s\n", nf, nd, humanBytes(total), ps)
			return nil
		},
	}
	lCmd.Flags().StringP("password", "p", "", "密码")
	lCmd.Flags().Bool("ask-password", false, "交互输入密码")
	lCmd.Flags().StringP("type", "t", "", "强制指定格式")
	_ = lCmd.Flags().MarkHidden("ask-password")

	// ---------- t ----------
	tCmd := &cobra.Command{
		Use:     "t <归档> [文件/通配符...]",
		Aliases: []string{"test"},
		Short:   "测试归档完整性（CRC 校验）",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive := args[0]
			fm, pw, err := prepareRead(cmd, archive)
			if err != nil {
				return err
			}
			opt := &ExtractOptions{Test: true, Filters: args[1:], Password: pw}
			prog := NewProgress("测试", archiveTotal(archive, fm, pw, opt.Filters))
			st, err := runExtract(archive, fm, opt, prog)
			prog.Finish()
			if err != nil {
				if errors.Is(err, errNeedPassword) {
					return errors.New("归档已加密，请用 -p 指定密码")
				}
				return err
			}
			if st.Errors > 0 {
				exitCode = 2
				logErr("%s: %d 个文件出错, %d 个正常", archive, st.Errors, st.Files)
				return nil
			}
			logOK("%s: 全部正常（%d 个文件, %s, %s）", archive, st.Files, humanBytes(st.Bytes), prog.Elapsed().Round(time.Millisecond))
			return nil
		},
	}
	tCmd.Flags().StringP("password", "p", "", "密码")
	tCmd.Flags().Bool("ask-password", false, "交互输入密码")
	tCmd.Flags().StringP("type", "t", "", "强制指定格式")
	_ = tCmd.Flags().MarkHidden("ask-password")

	// ---------- i ----------
	iCmd := &cobra.Command{
		Use:     "i",
		Aliases: []string{"info", "formats"},
		Short:   "显示支持的格式",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data := pterm.TableData{{"格式", "扩展名", "压缩", "解压", "加密", "说明"}}
			yn := func(b bool) string {
				if b {
					return pterm.Green("✔")
				}
				return pterm.Gray("—")
			}
			for _, f := range formats {
				pw := f.Password
				if pw == "" {
					pw = "—"
				}
				data = append(data, []string{f.Name, strings.Join(f.Exts, " "), yn(f.Write), yn(f.Read), pw, f.Desc})
			}
			pterm.DefaultSection.WithLevel(2).Println("g7z " + version + " 支持的格式")
			return pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(data).WithWriter(os.Stdout).Render()
		},
	}

	// ---------- h ----------
	hCmd := &cobra.Command{
		Use:     "h <文件...>",
		Aliases: []string{"hash"},
		Short:   "计算文件哈希（crc32 md5 sha1 sha256 sha512）",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			algo := strings.ToLower(viper.GetString("algo"))
			newH := map[string]func() hash.Hash{
				"crc32": func() hash.Hash { return crc32.NewIEEE() }, "md5": md5.New, "sha1": sha1.New, "sha256": sha256.New, "sha512": sha512.New,
			}[algo]
			if newH == nil {
				return fmt.Errorf("不支持的哈希算法 %s", algo)
			}
			var paths []string
			for _, a := range args {
				m, _ := filepath.Glob(a)
				if len(m) == 0 {
					m = []string{a}
				}
				for _, p := range m {
					_ = filepath.Walk(p, func(fp string, info os.FileInfo, err error) error {
						if err == nil && info.Mode().IsRegular() {
							paths = append(paths, fp)
						}
						return err
					})
				}
			}
			sort.Strings(paths)
			var total int64
			for _, p := range paths {
				if st, err := os.Stat(p); err == nil {
					total += st.Size()
				}
			}
			prog := NewProgress(strings.ToUpper(algo), total)
			type res struct{ sum, path string }
			var rs []res
			for _, p := range paths {
				f, err := os.Open(p)
				if err != nil {
					prog.Finish()
					return err
				}
				prog.SetCurrent(p)
				h := newH()
				_, err = io.Copy(io.MultiWriter(h, prog), f)
				f.Close()
				if err != nil {
					prog.Finish()
					return err
				}
				rs = append(rs, res{hex.EncodeToString(h.Sum(nil)), filepath.ToSlash(p)})
			}
			prog.Finish()
			for _, r := range rs {
				fmt.Printf("%s  %s\n", r.sum, r.path)
			}
			return nil
		},
	}
	hCmd.Flags().String("algo", "sha256", "哈希算法: crc32 md5 sha1 sha256 sha512（也可 -scrcSHA256）")

	// ---------- config ----------
	cfgCmd := &cobra.Command{
		Use:   "config",
		Short: "查看当前配置",
		RunE: func(cmd *cobra.Command, args []string) error {
			src := viper.ConfigFileUsed()
			if src == "" {
				src = "（未找到配置文件，使用默认值）"
			}
			data := pterm.TableData{{"键", "值"}}
			for _, k := range []string{"type", "level", "threads", "solid", "overwrite", "exclude", "no-color"} {
				v := fmt.Sprint(viper.Get(k))
				if k == "threads" && viper.GetInt(k) <= 0 {
					v = fmt.Sprintf("0（自动: %d）", runtime.NumCPU())
				}
				if v == "<nil>" || v == "" || v == "[]" {
					v = "-"
				}
				data = append(data, []string{k, v})
			}
			pterm.DefaultSection.WithLevel(2).Println("配置来源: " + src)
			return pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(data).WithWriter(os.Stdout).Render()
		},
	}
	cfgInit := &cobra.Command{
		Use:   "init [路径]",
		Short: "生成示例配置文件",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := "g7z.yaml"
			if len(args) == 1 {
				p = args[0]
			} else if d, err := os.UserConfigDir(); err == nil {
				p = filepath.Join(d, "g7z", "g7z.yaml")
			}
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%s 已存在", p)
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p, []byte(sampleConfig), 0o644); err != nil {
				return err
			}
			logOK("已生成 %s", p)
			return nil
		},
	}
	cfgCmd.AddCommand(cfgInit)

	root.AddCommand(addCmd, xCmd, eCmd, lCmd, tCmd, iCmd, hCmd, cfgCmd)
	root.SetArgs(rewriteArgs(os.Args[1:]))
	if err := root.Execute(); err != nil {
		if stderrTTY || termOut != nil {
			logErr("%v", err)
		} else {
			fmt.Fprintln(os.Stderr, "错误:", err)
		}
		os.Exit(2)
	}
	os.Exit(exitCode)
}
