# g7z — 类 7-Zip 的多格式压缩工具（Go）

库：cobra + pflag + viper + lipgloss/termenv + pterm；
压缩：ulikunitz/xz（LZMA2）、klauspost/compress（zstd/gzip/deflate）、dsnet/compress（bzip2）、pierrec/lz4、andybalholm/brotli、yeka/zip（AES zip）；
读取：bodgit/sevenzip（7z）、nwaples/rardecode（rar）。

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
写入：7z zip tar tar.gz tar.bz2 tar.xz tar.zst tar.lz4 tar.br gz bz2 xz zst lz4 br
读取：以上全部 + rar（RAR4/RAR5、加密）；7z/zip 读写 AES-256，zip 读 ZipCrypto；
格式按文件头魔数识别，不依赖扩展名。

## 7z 风格参数
`-mx0..9` 级别、`-mmtN` 线程、`-ms=64m|off` 固实块、`-p` / `-pPASS` 密码、`-oDIR` 输出目录、`-tFMT` 格式、`-aoa/-aos/-aou` 覆盖/跳过/重命名、`-y` 全部覆盖、`-x 通配符` 排除。

## 配置
`g7z config init` 生成 `g7z.yaml`（查找顺序：`--config`、`$G7Z_CONFIG`、`./g7z.yaml`、用户配置目录 `g7z/g7z.yaml`、`~/g7z.yaml`）。环境变量 `G7Z_LEVEL`、`G7Z_THREADS` 等同样生效。

## 说明
- 7z 写入为自研：每个固实块一个 LZMA2 folder，多线程并行压缩；生成的 7z（含 AES 加密）已通过官方 7-Zip 25.01 `t`/`x` 校验。
- 7z 写入暂不支持头部加密（-mhe）和向已有归档追加；RAR 只读。
- 退出码：0 成功，2 出错。
