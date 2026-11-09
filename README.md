# g7z — 类 7-Zip 的多格式压缩工具（Go）

库：cobra + pflag + viper + lipgloss/termenv + pterm；
压缩：ulikunitz/xz（LZMA2）、klauspost/compress（zstd/gzip/deflate）、dsnet/compress（bzip2）、pierrec/lz4、andybalholm/brotli、yeka/zip（AES zip）；
读取：bodgit/sevenzip（7z）、nwaples/rardecode（rar）；RAR5 写入为内置 rarpack 包（固实 / E8E9 过滤 / AES-256 加密 / 头部加密）。

## 命令（与 7z 一致）
| 命令 | 作用 |
|---|---|
| `a` | 压缩 |
| `x` | 解压（保留路径） |
| `e` | 解压到同一目录 |
| `l` | 列出内容 |
| `t` | 测试完整性 |
| `h` | 文件哈希 crc32/md5/sha1/sha256/sha512 |
| `i` | 支持的格式 |
| `config` / `config init` | 查看配置 / 生成配置文件 |

## 示例
```
g7z a backup.7z ./docs ./src -mx9 -p          # 交互输入密码，AES-256
g7z a site.tar.zst /var/www -mmt8
g7z a logs.zip *.log -pSecret -x "*.tmp"
g7z a big.iso.xz big.iso                       # 单文件压缩
g7z x backup.7z -oout -pSecret -aoa            # 覆盖已存在文件
g7z e backup.7z -oflat "*.jpg"                 # 只解压 jpg，不保留目录
g7z l archive.rar
g7z t backup.7z -pSecret
g7z h -scrcSHA256 file.iso
```

## 格式
写入：7z zip rar tar tar.gz tar.bz2 tar.xz tar.zst tar.lz4 tar.br gz bz2 xz zst lz4 br
读取：以上全部 + rar（RAR4/RAR5、加密、分卷）；7z/zip/rar 读写 AES-256，zip 读 ZipCrypto；
格式按文件头魔数识别，不依赖扩展名。

## 7z 风格参数
`-mx0..9` 级别、`-mmtN` 线程、`-ms=64m|off` 固实块、`-md=64m` LZMA2 字典大小（7z/xz，覆盖 -mx 默认值）、`-mhe` 头部加密（7z / rar + 密码）、`-bcj=on|auto` x86 BCJ 过滤器（可执行文件，默认 off）、`-p` / `-pPASS` 密码、`-oDIR` 输出目录、`-tFMT` 格式、`-aoa/-aos/-aou` 覆盖/跳过/重命名、`-y` 全部覆盖、`-x 通配符` 排除。

## 配置
`g7z config init` 生成 `g7z.yaml`（查找顺序：`--config`、`$G7Z_CONFIG`、`./g7z.yaml`、用户配置目录 `g7z/g7z.yaml`、`~/g7z.yaml`）。环境变量 `G7Z_LEVEL`、`G7Z_THREADS` 等同样生效。

## 说明
- 7z 写入为自研：每个固实块一个 LZMA2 folder，多线程并行压缩；固实前按文件类型聚类排序；生成的 7z（含 AES 加密、-mhe 头部加密、BCJ 过滤）已通过官方 7-Zip `t`/`x` 校验。
- RAR5 写入（rarpack）：固实由 `-ms` 控制（off = 不固实，其余为固实），支持 `-p` 加密与 `-mhe` 头部加密，产物经官方 unrar `t`/`x` 校验；不单独存储目录项（路径保留在文件名中），`-mx` / `-md` / `-mmt` 对 rar 不生效。
- 退出码：0 成功，2 出错。

## 压缩基准

```bash
./bench/run.sh [语料目录]   # 缺省生成合成语料；建议传入真实文件目录
```

对比 g7z 与官方 7-Zip 的压缩率/速度，并做解压往返校验。
