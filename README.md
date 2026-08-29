# SNMP / FTP Audit Scanner

一套用於授權內部網路稽核的 Python 工具，透過 `nmap` 掃描指定 IP 或網段中的 SNMP 與 FTP 服務，並進一步檢查：

* SNMP 是否使用常見 community string
* SNMP community 是否可讀取
* SNMP community 是否可寫入，需手動啟用
* FTP 是否可使用常見帳號密碼登入
* FTP 成功登入後自動列出根目錄檔案清單
* 多主機、多帳密同時並行掃描，加快整體效率
* 掃描完成後自動產生 JSON、CSV、HTML 報告

> 本工具設計用途為內部資安稽核、弱點盤點、設備設定檢查與合規檢測。請只在已取得授權的網路環境中使用。

> **本次優化摘要（詳見文末〈準確度、效能與穩定性優化〉一節）：** 修正 SNMP UDP 埠漏判、SNMP 同時支援 v1/v2c、SNMP 逐台平行測試、FTP 連線錯誤與帳密錯誤分流並自動重試、`--ftp-delay` 序列模式真正生效、字典檔 BOM 自動處理、FTP 目錄列表多編碼容錯（Big5/CP950/GBK/Shift-JIS…）。所有變更皆向後相容，原有指令可照舊使用。

---

## 目錄結構

```text
snmp_ftp_audit/
├── audit_snmp_ftp.py
├── iprange.txt
├── snmplist.txt
├── ftplist.txt
└── reports/
```

| 檔案或目錄               | 說明                                         |
| ------------------- | ------------------------------------------ |
| `audit_snmp_ftp.py` | 主程式                                        |
| `iprange.txt`       | 掃描目標清單，可放單一 IP、CIDR、nmap range 或完整 IP 起訖範圍 |
| `snmplist.txt`      | SNMP community string 字典                   |
| `ftplist.txt`       | FTP 帳號密碼字典                                 |
| `reports/`          | 掃描報告輸出目錄                                   |

---

## 系統需求

建議執行環境：

* Kali Linux
* Python 3
* nmap
* Net-SNMP tools

安裝必要套件：

```bash
sudo apt update
sudo apt install -y nmap snmp python3
```

確認工具是否存在：

```bash
which nmap
which snmpget
which snmpset
python3 --version
```

---

## 建立專案目錄

```bash
mkdir -p snmp_ftp_audit/reports
cd snmp_ftp_audit
```

建立必要檔案：

```bash
touch iprange.txt snmplist.txt ftplist.txt
nano audit_snmp_ftp.py
chmod +x audit_snmp_ftp.py
```

---

## 掃描模式

本工具支援三種掃描模式。

| 模式     | 說明            |
| ------ | ------------- |
| `all`  | 掃描 SNMP 與 FTP |
| `snmp` | 只掃描 SNMP      |
| `ftp`  | 只掃描 FTP       |

預設模式為：

```text
all
```

---

## `iprange.txt` 格式

`iprange.txt` 用來指定掃描範圍，每行一筆目標。

支援格式如下：

```text
# 單一 IP
192.168.1.10

# CIDR 網段
192.168.1.0/24
10.10.10.0/24

# nmap 原生 range
192.168.2.1-50
192.168.3-5.1-254

# 完整 IP 起訖範圍，程式會自動轉換為 CIDR
192.168.0.0-192.168.10.255
10.0.1.20-10.0.3.200
```

例如：

```text
192.168.0.0-192.168.10.255
```

會自動轉成多個 CIDR 後交給 `nmap` 掃描。

注意：完整 IP 起訖範圍可能包含 `.0` 與 `.255` 位址。如果只想掃主機位址，可改用：

```text
192.168.0-10.1-254
```

> **補充（本次優化）：** 三個字典檔（`iprange.txt` / `snmplist.txt` / `ftplist.txt`）皆以「每行一筆資料」讀取，沒有標題列的概念，第一行即為資料；空白行與以 `#` 開頭的註解行會自動略過。程式現在會自動去除檔首 BOM（`\ufeff`），因此用 Windows 記事本另存的字典檔，第一筆資料不會再被 BOM 汙染而比對失敗。

---

## `snmplist.txt` 格式

`snmplist.txt` 每行放一個 SNMP community string。

範例：

```text
public
private
community
manager
admin
default
monitor
cisco
read
write
public_rw
private_rw
```

程式會逐一測試這些字串是否能讀取 SNMP 資訊。

預設讀取 OID：

```text
1.3.6.1.2.1.1.1.0
```

也就是：

```text
sysDescr.0
```

> **補充（本次優化）：** SNMP 測試現在預設同時嘗試 **v2c 與 v1**（可用 `--snmp-versions` 調整），任一版本讀到即算可讀，避免只支援 SNMPv1 的舊型印表機、UPS、工控與監控設備被整批漏掉；同時每台主機會**平行**測試多個 community，並可設定重試次數以降低 UDP 掉包造成的漏報。詳見〈準確度、效能與穩定性優化〉。

---

## `ftplist.txt` 格式

`ftplist.txt` 支援兩種格式。

---

### 格式一：單字交叉模式

每行放一個字串，程式會自動產生帳號與密碼交叉組合。

```text
admin
password
123456
root
guest
administrator
qwerty
12345678
admin123
123123
scan
123
```

會產生類似以下測試組合：

```text
admin:admin
admin:password
admin:123456
root:admin
root:password
root:123456
...
```

若清單有 12 筆，會產生：

```text
12 x 12 = 144
```

組帳密測試。

> **補充（本次優化）：** 單字交叉模式需要「**正確的帳號**」與「**正確的密碼**」兩者都在清單中，該組帳密才會被產生出來測。若某台設備的正確帳號（例如 `ftpuser`）不在字典裡，就算密碼在字典裡也永遠配不出正確組合。若你已知正確帳號，請把它補進清單，或改用下方「指定帳密模式」。另外請留意 `--ftp-max-attempts` 預設為 `150`，超過會截斷；本次優化已在截斷時明確印出「已忽略 N 組」，不再靜默丟棄清單尾端。

---

### 格式二：指定帳密模式

每行使用：

```text
username:password
```

範例：

```text
admin:admin
admin:password
admin:123456
admin:admin123
root:root
root:password
root:123456
guest:guest
administrator:administrator
administrator:password
scan:scan
scan:123
```

正式稽核建議使用指定帳密模式，因為測試範圍較可控，也比較容易解釋稽核證據。

---

## 基本執行方式

### 掃描 SNMP 與 FTP

```bash
sudo python3 audit_snmp_ftp.py --mode all --pn
```

### 只掃描 SNMP

```bash
sudo python3 audit_snmp_ftp.py --mode snmp --pn
```

### 只掃描 FTP

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn
```

---

## 常用參數

| 參數                   | 說明                        | 預設值            |
| -------------------- | ------------------------- | -------------- |
| `--mode`             | 掃描模式：`all`、`snmp`、`ftp`   | `all`          |
| `--iprange-file`     | IP 範圍檔案                   | `iprange.txt`  |
| `--snmp-list`        | SNMP 字典檔案                 | `snmplist.txt` |
| `--ftp-list`         | FTP 字典檔案                  | `ftplist.txt`  |
| `--report-dir`       | 報告輸出目錄                    | `reports`      |
| `--pn`               | 使用 nmap `-Pn`，略過主機發現      | 關閉             |
| `--host-timeout`     | nmap 每台主機逾時               | `45s`          |
| `--max-retries`      | nmap 重試次數                 | `2`            |
| `--snmp-timeout`     | SNMP 逾時秒數                 | `2`            |
| `--snmp-delay`       | 每次 SNMP 測試間隔秒數（僅在 `--snmp-workers 1` 序列模式生效） | `0.1`          |
| `--snmp-write-test`  | 啟用 SNMP 寫入測試              | 關閉             |
| `--ftp-timeout`      | FTP 單次連線逾時秒數（同時作用於控制與資料連線） | `4`            |
| `--ftp-delay`        | 每次 FTP 登入測試間隔秒數（在 `--ftp-workers 1` 序列模式生效）  | `0.2`          |
| `--ftp-max-attempts` | 每台 FTP 主機最多嘗試次數，`0` 代表不限制 | `150`          |
| `--ftp-find-all`     | 找到第一組成功帳密後仍繼續測試           | 關閉             |
| `--no-anonymous`     | 不測試 anonymous FTP         | 關閉             |
| `--ftp-workers`      | 每台主機同時測試的 FTP 帳密執行緒數      | `8`            |
| `--workers`          | 同時稽核的主機數量（主機層級平行）         | `4`            |

---

### 新增與變更參數（本次優化）

以下為本次優化新增、或原本存在但未列於上表的參數：

| 參數                     | 說明                                                                 | 預設值   |
| ---------------------- | ------------------------------------------------------------------ | ----- |
| `--snmp-versions`      | 要嘗試的 SNMP 版本，逗號分隔、依序測試（僅支援 `1`、`2c`），任一成功即算可讀                        | `2c,1` |
| `--snmp-retries`       | SNMP（snmpget/snmpset）重試次數。SNMP 走 UDP 易掉包，`≥1` 可降低偽陰性                 | `1`   |
| `--snmp-workers`       | 每台主機同時測試的 SNMP community 執行緒數；設 `1` 為序列並套用 `--snmp-delay`            | `4`   |
| `--ftp-conn-retries`   | FTP 遇到連線類錯誤（被拒／逾時／限流）時的重試次數；帳密錯誤（如 530）不重試                           | `2`   |
| `--nmap-workers`       | nmap 探索的並行分片數（將目標拆分成多份同時掃描）                                          | `1`   |
| `--nmap-timing`        | nmap 時間樣板（對應 `-T0`～`-T5`）                                            | `4`   |
| `--nmap-min-rate`      | nmap `--min-rate` 最低送包速率（未指定則不加）                                     | 無    |
| `--nmap-stats-interval`| nmap 進度統計輸出間隔                                                        | `10s` |

---

## 建議執行範例

### 第一次盤點

```bash
sudo python3 audit_snmp_ftp.py --mode all --pn
```

---

### 只做 SNMP community 稽核

```bash
sudo python3 audit_snmp_ftp.py --mode snmp --pn
```

---

### 啟用 SNMP 可寫入測試

```bash
sudo python3 audit_snmp_ftp.py --mode snmp --pn --snmp-write-test
```

或在完整掃描時啟用：

```bash
sudo python3 audit_snmp_ftp.py --mode all --pn --snmp-write-test
```

注意：`--snmp-write-test` 會執行 SNMP `SET` 操作。程式採用較保守方式，先讀取 `sysContact.0`，再將相同值寫回原 OID，但仍建議只在授權維護時段或測試環境中使用。

---

### 只做 FTP 弱帳密檢查

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn
```

---

### 降低每台 FTP 主機嘗試次數

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-max-attempts 50
```

---

### 放慢 FTP 測試速度

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-delay 1
```

---

### 調整 FTP 平行執行緒數

減少每台主機同時測試的執行緒，降低對設備的壓力：

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-workers 3
```

增加執行緒加快速度（網路環境允許時）：

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-workers 16
```

---

### 調整主機層級平行數

同時稽核更多主機：

```bash
sudo python3 audit_snmp_ftp.py --mode all --pn --workers 8
```

對慢速環境降低並行數：

```bash
sudo python3 audit_snmp_ftp.py --mode all --pn --workers 2 --ftp-workers 3
```

---

### 找出每台 FTP 所有成功帳密

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-find-all
```

---

### 對應本次優化的實用指令（補充）

第一次盤點時，涵蓋只支援 v1 的舊設備、並抗 UDP 掉包：

```bash
sudo python3 audit_snmp_ftp.py --mode all --pn \
  --snmp-versions 2c,1 --snmp-retries 2 --snmp-workers 6
```

對敏感或老舊設備放慢、降低壓力（SNMP 序列 + 間隔）：

```bash
sudo python3 audit_snmp_ftp.py --mode snmp --pn \
  --snmp-workers 1 --snmp-delay 0.5 --snmp-retries 1
```

FTP 遇到設備限流／防暴力時，改序列並拉開間隔、加重連線重試：

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-find-all \
  --ftp-workers 1 --ftp-delay 0.5 --ftp-conn-retries 3 --ftp-max-attempts 0
```

---

## 報告輸出

掃描完成後，會在 `reports/` 目錄產生三種報告：

```text
reports/snmp_ftp_audit_all_20260615_143000.json
reports/snmp_ftp_audit_all_20260615_143000.csv
reports/snmp_ftp_audit_all_20260615_143000.html
```

不同掃描模式會自動反映在檔名中：

```text
snmp_ftp_audit_all_時間.html
snmp_ftp_audit_snmp_時間.html
snmp_ftp_audit_ftp_時間.html
```

---

## 報告格式說明

| 報告格式 | 用途                     |
| ---- | ---------------------- |
| JSON | 後續自動化分析、串接 SIEM、留存原始結果 |
| CSV  | 匯入 Excel、資產清冊、弱點管理平台（含 `ftp_file_list` 欄位）  |
| HTML | 人工檢視、交付稽核報告、快速瀏覽風險     |

> **補充（本次優化）：** JSON 報告新增兩個欄位（皆為附加欄位，不影響既有解析）：SNMP 結果的 `version`（讀取成功時實際使用的 SNMP 版本），以及 FTP 結果的 `list_error`（登入成功但列目錄失敗時的原因）。

---

## 風險判定邏輯

| 風險等級   | 判定條件                              |
| ------ | --------------------------------- |
| High   | FTP 可使用弱帳密登入，或 SNMP community 可寫入 |
| Medium | SNMP community 可讀取                |
| Low    | FTP 或 SNMP 連接埠開啟，但尚未驗證出弱點         |
| Info   | 僅作紀錄，未發現明顯服務或弱點                   |

---

## HTML 報告欄位

HTML 報告會包含：

* 掃描時間
* 掃描模式
* 掃描目標
* 服務開啟統計
* FTP 開啟主機數
* SNMP 開啟主機數
* FTP 弱帳密主機數
* SNMP 可讀主機數
* SNMP 可寫主機數
* High / Medium / Low 風險統計
* 主機明細
* FTP 成功帳密
* FTP Banner
* FTP 根目錄檔案列表（成功登入後自動列出，依帳密分組顯示；若列目錄失敗會顯示「無法取得列表」與原因）
* SNMP 可讀 community
* SNMP 可寫 community
* SNMP sysDescr

---

## 準確度、效能與穩定性優化（重要變更）

本節整理本次針對「更準確、更快、更穩」所做的變更。**所有變更皆向後相容**，既有指令與報告解析方式不受影響。

### SNMP — 準確度

* **UDP/161 `open|filtered` 不再被丟棄。** SNMP 走 UDP、無交握，`nmap` 對未回應的 UDP 埠常標成 `open|filtered` 而非 `open`。原本只採計嚴格 `open`，會在探索階段就漏掉大量其實有開 SNMP 的設備；現在 `open` 與 `open|filtered` 都會進入後續稽核，交由真正的 `snmpget` 實測作為最終判準（TCP/21 因狀態可信，維持只認 `open`）。
* **同時嘗試 SNMP v2c 與 v1。** 原本只測 `-v2c`，會漏掉只支援 SNMPv1 的舊型印表機、UPS、工控與監控設備；現在預設依序嘗試 `2c,1`（可用 `--snmp-versions` 調整）。
* **可設定重試次數。** 原本重試為 `0`，UDP 只要掉一包就把可讀 community 誤判為不可讀；現在預設 `--snmp-retries 1`。

### SNMP — 效能

* **逐台平行測試 community。** 原本每台主機逐一串列測試；現在以執行緒池平行（`--snmp-workers`，預設 4），對長字典或逾時偏久的設備顯著縮短單台耗時，同時仍完整測試並回報每一個可讀／可寫 community。
* `--snmp-delay` 現在僅在 `--snmp-workers 1` 序列模式下生效，用於對敏感設備維持溫和節奏。

### nmap — 效能

* **關閉反向 DNS（`-n`）。** 稽核以 IP 為對象，省下每台主機的 DNS 等待。
* **UDP 掃描加上 `--defeat-icmp-ratelimit`。** 讓 nmap 不再苦等被目標限速的 ICMP 回應，明顯加速 UDP（`all` / `snmp` 模式）掃描；因只在意「開啟」的埠，對判定準確度無負面影響。

### FTP — 準確度與穩定性

* **區分「帳密錯誤」與「連線問題」並自動重試。** 原本兩者都算失敗、且不重試，導致正確帳密踩到一次暫時性連線失敗（設備限流／防暴力）就被誤判。現在帳密錯誤（如 530）不重試，連線類錯誤（被拒／逾時／421 連線數過多）自動重試（`--ftp-conn-retries`，預設 2）。
* **`--ftp-delay` 真正生效。** 在 `--ftp-workers 1` 序列模式下，每次嘗試之間確實間隔，對限制並行連線或有防暴力機制的嵌入式設備最安全。
* **失敗原因分解。** 某台 FTP 開啟卻零成功登入時，會印出失敗分類（帳密錯誤 / 連線被拒逾時限流 / 其他）與研判提示，讓「密碼真的不對」與「被設備擋掉」一目了然，不必再靠猜。
* **截斷不再靜默。** `--ftp-max-attempts` 截斷清單時會明確印出「已忽略 N 組」。
* **連線逾時處理更乾淨。** 逾時交給 `ftplib` 的 socket timeout（同時作用於控制與資料連線），不再殘留占用 socket 的背景連線。

### FTP — 目錄列表多編碼容錯

* **登入成功卻看不到檔案的常見原因是「解碼」而非「連不上」。** 例如繁體中文 Windows 的 FTP 伺服器，其目錄中文檔名為 Big5／CP950 編碼，`ftplib` 預設以 UTF-8 解碼會直接崩潰。
* 現在改為**抓取原始位元組後自行容錯解碼**，依序嘗試 UTF-8 → CP950 → Big5 → GBK → GB18030 → Shift-JIS → EUC-KR，最後以 `errors="replace"` 保底，**永不因解碼而丟失整份列表**。
* **被動失敗改主動、`LIST` 空再用 `NLST` 交叉確認。** 被動模式（PASV）可能因設備回報不可達 IP 或防火牆擋資料埠而失敗，改試主動模式（PORT）；全部失敗則把原因寫入報告（`list_error`），明確區分「真的空目錄」與「資料連線失敗」。

### 檔案讀取 — BOM 處理

* 三個字典檔改用 `utf-8-sig` 讀取並逐行清除殘留 BOM，修正「用記事本另存的字典檔第一筆資料被 BOM 汙染而比對不到」的問題。

---

## 建議稽核流程

### 1. 確認掃描範圍

先編輯：

```bash
nano iprange.txt
```

確認只包含已授權掃描的 IP 或網段。

---

### 2. 先做低風險盤點

建議第一次執行：

```bash
sudo python3 audit_snmp_ftp.py --mode all --pn --ftp-max-attempts 50 --ftp-delay 0.5
```

---

### 3. 檢查 HTML 報告

```bash
ls -lh reports/
```

用瀏覽器開啟最新的 HTML 報告。

---

### 4. 視需要啟用 SNMP 寫入測試

確認維護時段與授權後，再執行：

```bash
sudo python3 audit_snmp_ftp.py --mode snmp --pn --snmp-write-test
```

---

### 5. 複測修補結果

修補後重新執行同樣指令，保留前後報告作為稽核證據。

---

## 修補建議

### SNMP

若發現 SNMP 使用常見 community string，例如：

```text
public
private
community
admin
```

建議：

1. 停用 SNMPv1 / SNMPv2c。
2. 優先改用 SNMPv3。
3. 若必須使用 SNMPv2c，應使用高強度 community string。
4. 限制可查詢來源 IP。
5. 關閉不必要的 SNMP OID。
6. 禁止使用可寫入 community。
7. 定期檢查網路設備、印表機、NAS、UPS、監控設備的 SNMP 設定。

---

### FTP

若發現 FTP 可使用弱帳密登入，建議：

1. 停用 FTP，改用 SFTP 或 FTPS。
2. 禁止 anonymous login。
3. 停用預設帳號。
4. 強制使用高強度密碼。
5. 啟用登入失敗鎖定機制。
6. 限制來源 IP。
7. 檢查是否仍有明文 FTP 傳輸敏感資料。
8. 移除不必要的 FTP 服務。

---

## 疑難排解

### nmap 執行失敗

請確認是否使用 root 權限：

```bash
sudo python3 audit_snmp_ftp.py --mode all --pn
```

確認 nmap 是否安裝：

```bash
which nmap
```

---

### SNMP 掃不到設備

可能原因：

1. UDP/161 被防火牆阻擋。
2. 設備只允許特定來源 IP 查詢。
3. community string 不在 `snmplist.txt` 中。
4. 設備使用 SNMPv3。
5. 目標網段禁止 ICMP，需使用 `--pn`。

建議：

```bash
sudo python3 audit_snmp_ftp.py --mode snmp --pn --max-retries 3 --snmp-timeout 3
```

若懷疑是只支援 v1 的舊設備或 UDP 掉包，可再加上（本次優化）：

```bash
sudo python3 audit_snmp_ftp.py --mode snmp --pn \
  --snmp-versions 2c,1 --snmp-retries 2
```

---

### FTP 掃描太慢

使用 `--ftp-workers` 增加每台主機同時測試的執行緒數（預設 8）：

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-workers 16
```

使用 `--workers` 增加同時稽核的主機數量（預設 4）：

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --workers 8
```

也可以降低每台主機嘗試次數：

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-max-attempts 50
```

或調整字典，改用指定帳密模式。

---

### FTP 探索到的主機數量偏少（本次優化補充）

若「掃到的 FTP 主機數」明顯少於實際，多半是 nmap 探索階段被 `--host-timeout`（預設 45s）砍掉慢速主機，或大網段封包遺失所致。可放寬逾時、加重試：

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn \
  --host-timeout 0 --max-retries 3 --nmap-timing 3
```

先觀察 `nmap 探索完成，共 N 台主機需要稽核` 的 `N`：若 `N` 偏小，代表問題在探索階段（逾時／掉包）；若 `N` 很大卻只稽核到少數，才是稽核階段的問題。

---

### FTP 明明有正確帳密卻登入失敗（本次優化補充）

程式會在某台「FTP 開啟卻零成功登入」時印出失敗分解，據此判斷：

* **全部為「帳密錯誤」** → 密碼配不出來。單字交叉模式需要「正確帳號」也在字典中；若正確帳號不在 `ftplist.txt`，任何密碼都配不出正確組合。請補上正確帳號，或改用 `帳號:密碼` 指定帳密格式。
* **「連線被拒／逾時／限流」偏多** → 設備限制並行連線或觸發防暴力鎖定。改序列並拉開間隔：

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-find-all \
  --ftp-workers 1 --ftp-delay 0.5 --ftp-conn-retries 3 --ftp-max-attempts 0
```

---

### FTP 登入成功但看不到根目錄檔案列表（本次優化補充）

多數情況是「解碼」問題而非「連不上」。例如繁中 Windows 的 FTP 伺服器，其中文檔名為 Big5／CP950 編碼。本次優化已改為抓原始位元組並多編碼容錯解碼，一般可直接正常顯示中文檔名。若報告仍顯示「無法取得列表」，請看括號內的原因：

* `PASV:... ; PORT:timed out` 且 PASV 顯示解碼類錯誤 → 屬編碼問題，已由多編碼容錯處理；若仍為亂碼，代表該設備使用了目前嘗試順序未先命中的編碼。
* `PASV` 與 `PORT` 皆為連線類錯誤 → 資料連線被防火牆阻擋，或設備回報了不可達的被動模式 IP。

---

### 字典檔第一筆資料比對不到（BOM）（本次優化補充）

若字典檔以 Windows 記事本另存為 UTF-8，檔首可能含 BOM。本次優化已改用 `utf-8-sig` 讀取並逐行清除殘留 BOM，第一筆資料不會再被汙染。若仍有疑慮，可用以下指令確認檔首位元組是否為 `ef bb bf`：

```bash
head -c 3 snmplist.txt | od -An -tx1
```

---

### 大網段掃描時間過長

可分批放入 `iprange.txt`，例如：

```text
192.168.0.0/24
192.168.1.0/24
192.168.2.0/24
```

也可以分別執行：

```bash
sudo python3 audit_snmp_ftp.py --mode snmp --pn
sudo python3 audit_snmp_ftp.py --mode ftp --pn
```

---

## 使用注意事項

1. 僅限授權環境使用。
2. 大型網段建議分批掃描。
3. 老舊設備、工控設備、醫療設備、印表機與 UPS 可能對掃描較敏感。
4. 啟用 `--snmp-write-test` 前應確認維護時段與設備風險。
5. FTP 帳密測試應控制嘗試次數，避免觸發帳號鎖定或設備異常。
6. 報告中可能包含有效帳密或敏感設備資訊，應妥善保護。

---

## 範例完整流程

```bash
sudo apt update
sudo apt install -y nmap snmp python3

mkdir -p snmp_ftp_audit/reports
cd snmp_ftp_audit

nano audit_snmp_ftp.py
chmod +x audit_snmp_ftp.py

cat > iprange.txt << EOF
192.168.1.0/24
192.168.2.1-50
192.168.0.0-192.168.10.255
EOF

cat > snmplist.txt << EOF
public
private
community
manager
admin
default
monitor
cisco
read
write
public_rw
private_rw
EOF

cat > ftplist.txt << EOF
admin:admin
admin:password
admin:123456
admin:admin123
root:root
root:password
root:123456
guest:guest
administrator:administrator
administrator:password
scan:scan
scan:123
EOF

sudo python3 audit_snmp_ftp.py --mode all --pn --ftp-max-attempts 50 --ftp-delay 0.5
```

查看報告：

```bash
ls -lh reports/
```

---

## 版本建議

目前版本功能：

* 多 IP / 多網段掃描
* 跨網段 IP 起訖範圍轉 CIDR
* SNMP community 檢查
* SNMP 可讀檢查
* SNMP 可寫入檢查
* FTP 常見帳密檢查
* 三種掃描模式
* JSON / CSV / HTML 報告輸出

本次優化新增：

* SNMP UDP 埠 `open|filtered` 納入稽核（修正漏判）
* SNMP 同時支援 v1 / v2c 與可設定重試
* SNMP 逐台平行測試 community
* nmap `-n` 與 UDP `--defeat-icmp-ratelimit` 加速
* FTP 連線錯誤與帳密錯誤分流、連線錯誤自動重試
* FTP 失敗原因分解與研判提示
* FTP 目錄列表多編碼容錯（Big5/CP950/GBK/Shift-JIS…）
* FTP 被動／主動與 `LIST`／`NLST` 列目錄退路
* 字典檔 BOM 自動處理

後續可擴充：

* `--exclude-file` 排除清單
* SNMPv3 檢查
* FTP 是否支援 FTPS
* FTP 目錄列表改用 `FEAT` / `OPTS UTF8 ON` 與 `MLSD`，並提供 `--ftp-encoding` 手動指定編碼（規劃中，目前尚未實作）
* CVSS 風險評分
* Excel 報告
* SQLite 結果資料庫
* 歷史掃描差異比對
* 修補建議欄位
* 與 Wazuh / Graylog / SIEM 串接

---

## 授權與責任聲明

本工具僅供合法授權之資安稽核、內部資產盤點與弱點檢測使用。使用者應自行確認掃描範圍、授權邊界、維護時段與相關法規要求。任何未經授權的掃描、登入測試或設備設定測試，皆不屬於本工具建議用途。
