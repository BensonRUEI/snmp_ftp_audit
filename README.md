# SNMP / FTP Audit Scanner

一套用於授權內部網路稽核的 Python 工具，透過 `nmap` 掃描指定 IP 或網段中的 SNMP 與 FTP 服務，並進一步檢查：

* SNMP 是否使用常見 community string
* SNMP community 是否可讀取
* SNMP community 是否可寫入，需手動啟用
* FTP 是否可使用常見帳號密碼登入
* 掃描完成後自動產生 JSON、CSV、HTML 報告

> 本工具設計用途為內部資安稽核、弱點盤點、設備設定檢查與合規檢測。請只在已取得授權的網路環境中使用。

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
| `--snmp-delay`       | 每次 SNMP 測試間隔秒數            | `0.1`          |
| `--snmp-write-test`  | 啟用 SNMP 寫入測試              | 關閉             |
| `--ftp-timeout`      | FTP 連線逾時秒數                | `4`            |
| `--ftp-delay`        | 每次 FTP 登入測試間隔秒數           | `0.2`          |
| `--ftp-max-attempts` | 每台 FTP 主機最多嘗試次數，`0` 代表不限制 | `150`          |
| `--ftp-find-all`     | 找到第一組成功帳密後仍繼續測試           | 關閉             |
| `--no-anonymous`     | 不測試 anonymous FTP         | 關閉             |

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
sudo .python3 audit_snmp_ftp.py --mode all --pn --snmp-write-test
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

### 找出每台 FTP 所有成功帳密

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-find-all
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
| CSV  | 匯入 Excel、資產清冊、弱點管理平台   |
| HTML | 人工檢視、交付稽核報告、快速瀏覽風險     |

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
* FTP banner
* SNMP 可讀 community
* SNMP 可寫 community
* SNMP sysDescr

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

---

### FTP 掃描太慢

可降低每台主機嘗試次數：

```bash
sudo python3 audit_snmp_ftp.py --mode ftp --pn --ftp-max-attempts 50
```

或調整字典，改用指定帳密模式。

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

後續可擴充：

* `--exclude-file` 排除清單
* 平行掃描與併發控制
* SNMPv3 檢查
* FTP 是否支援 FTPS
* CVSS 風險評分
* Excel 報告
* SQLite 結果資料庫
* 歷史掃描差異比對
* 修補建議欄位
* 與 Wazuh / Graylog / SIEM 串接

---

## 授權與責任聲明

本工具僅供合法授權之資安稽核、內部資產盤點與弱點檢測使用。使用者應自行確認掃描範圍、授權邊界、維護時段與相關法規要求。任何未經授權的掃描、登入測試或設備設定測試，皆不屬於本工具建議用途。
