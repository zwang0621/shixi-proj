# DB Vulnerability Scanner (Go + MySQL)

一个可扩展的数据库漏洞扫描器骨架：采集（CVE API / CNVD / 阿里云）、标准化存储（MySQL）、匹配引擎（厂商/产品/版本）、扫描器（版本识别，支持 dry-run）、结果导出（JSON/CSV）。

## 快速开始

```bash
# 1) 准备 MySQL
mysql -uroot -p -e "CREATE DATABASE scanner DEFAULT CHARACTER SET utf8mb4;"

# 2) 配置 DSN（可用 env 覆盖）
export STORE_DSN='root:Pai3.1415926@tcp(127.0.0.1:3306)/shixi_gpt?parseTime=true'

# 3) 初始化
go mod tidy

# 4) 采集（CVE + 本地 CNVD/阿里云模拟）
go run ./cmd --mode collect --source cve --since 2025-01-01
go run ./cmd --mode collect --source cnvd
go run ./cmd --mode collect --source aliyun

# 5) 扫描（dry-run，不连真实数据库）
go run ./cmd --mode scan --db mysql --addr 127.0.0.1:3306 --user root --password 123456 --dry-run

# 6) 导出结果
go run ./cmd --mode export --format json --out scan_result.json