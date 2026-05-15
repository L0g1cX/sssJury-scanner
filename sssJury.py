import os
import re
import csv
import json
import math
import time
import shutil
import subprocess
import ipaddress
import html
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init

init(autoreset=True)  # 自动恢复颜色，不用手动重置

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    class _DummyColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
        LIGHTBLACK_EX = LIGHTRED_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = LIGHTBLUE_EX = LIGHTMAGENTA_EX = LIGHTCYAN_EX = LIGHTWHITE_EX = ""
    class _DummyStyle:
        RESET_ALL = ""
    Fore = _DummyColor()
    Style = _DummyStyle()

# ================= 评分规则配置 =================
RULES = {
    "url_keywords": {
        "keywords": ['test', 'dev', 'uat', 'backup', 'bak', 'oa', 'git', 'svn', 'jenkins', 'api', 'admin', 'swagger', 'actuator'],
        "score": 8,
        "desc": "URL含敏感环境或组件词"
    },
    "vuln_frameworks": {
        "keywords": ['struts', 'thinkphp', 'shiro', 'fastjson', 'weblogic', 'jboss', 'spring', 'ruoyi', 'laravel', 'drupal'],
        "score": 12,
        "desc": "命中历史高危框架"
    },
    "title_keywords": {
        "keywords": ['登录', '管理', '后台', '系统', 'login', 'admin', 'dashboard', 'platform', '中心', '入口', '门户'],
        "score": 8,
        "desc": "高价值系统入口(后台/登录)"
    },
    "weak_configs": {
        "keywords": ['welcome to nginx', 'apache tomcat', 'iis windows', 'directory listing', 'index of'],
        "score": 6,
        "desc": "默认页面或中间件探针"
    },
    "sensitive_paths": {
        "keywords": ['/api', '/admin', '/actuator', '/swagger', '/manage', '/console', '/backend', '/system'],
        "score": 5,
        "desc": "敏感路径上下文"
    }
}

# ================= 扫描性能配置 =================
HTTPX_CONFIG = {
    "batch_size": 200,      # 每批目标数
    "concurrency": 4,       # 并发运行 httpx 的批次数
    "rate_limit": 300,      # 每个 httpx 进程的速率限制
    "threads": 100,         # 每个 httpx 进程内部线程数
    "timeout": 8,           # 超时秒数
    "retries": 1            # 重试次数
}


class AssetHunter:
    def __init__(self):
        self.targets = set()
        self.results = []
        self.temp_dir = "httpx_temp"
        self.final_httpx_output = "httpx_output.json"
        self.skipped_targets = []
        self.input_files = []

    def get_input_files(self):
        """输入文件：支持手动输入或自动匹配 res-X.txt/csv"""
        files = []
        user_input = input("[*] 请输入资产文件路径 (多个文件用逗号分隔)，直接回车将自动匹配当前目录下文件名格式为 R<N>.txt/csv 的文件:\n>>> ").strip()

        if user_input:
            files = [f.strip() for f in user_input.split(',')]
        else:
            idx = 1
            print("[*] 自动匹配当前目录文件...")
            while True:
                txt_file = f"R{idx}.txt"
                csv_file = f"R{idx}.csv"
                found = False
                if os.path.exists(txt_file):
                    files.append(txt_file)
                    found = True
                if os.path.exists(csv_file):
                    files.append(csv_file)
                    found = True
                if not found:
                    break
                idx += 1

        if not files:
            print("[-] 未找到任何输入文件，请检查路径或文件名。")
            exit(1)

        self.input_files = files
        print(f"[+] 成功读取文件: {Fore.GREEN}{', '.join(files)}")
        return files

    def _is_ip(self, value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _is_valid_hostname(self, host):
        """
        判断是否为合理的域名/IP
        - 允许 IPv4
        - 允许常规域名
        - 过滤普通标题、状态文本等
        """
        if not host:
            return False

        host = host.strip().lower().rstrip('.')
        if not host:
            return False

        if self._is_ip(host):
            return True

        if len(host) > 253:
            return False

        labels = host.split('.')
        if len(labels) < 2:
            return False

        tld = labels[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False

        label_pattern = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
        for label in labels:
            if not label or len(label) > 63:
                return False
            if not label_pattern.match(label):
                return False

        return True

    def _normalize_candidate_url(self, candidate):
        """
        规范化候选 URL：
        - 支持 http/https 完整 URL
        - 支持裸域名/IP[:port][/path]
        - 非法内容返回 None
        """
        if not candidate:
            return None

        candidate = candidate.strip().strip('"\'')
        if not candidate:
            return None

        if candidate.startswith(("http://", "https://")):
            parsed = urlparse(candidate)
            if not parsed.netloc:
                return None
            host = parsed.hostname
            if not host or not self._is_valid_hostname(host):
                return None
            return candidate

        parsed = urlparse("http://" + candidate)
        host = parsed.hostname
        if not host or not self._is_valid_hostname(host):
            return None

        return "http://" + candidate

    def _split_line_fields(self, line):
        """
        尽量按 CSV/常见分隔符拆字段，避免把整行标题文本识别成 URL。
        优先使用 csv.reader 处理逗号引号，再回退到其他分隔方式。
        """
        if not line:
            return []

        fields = []
        try:
            row = next(csv.reader([line]))
            fields.extend(row)
        except Exception:
            fields.append(line)

        normalized_fields = []
        for field in fields:
            if field is None:
                continue
            sub_fields = re.split(r'[\t|]', field)
            for sub in sub_fields:
                sub = sub.strip()
                if sub:
                    normalized_fields.append(sub)

        return normalized_fields

    def _extract_status_from_fields(self, fields, url_field_index):
        """
        从 URL 字段之后的字段中提取状态码。
        仅识别独立字段或字段中的独立 token，避免误伤 URL 本身。
        """
        if not fields or url_field_index is None:
            return None

        tail_fields = fields[url_field_index + 1:]

        for field in tail_fields:
            field = field.strip().strip('"\'')
            if not field:
                continue

            if re.fullmatch(r'(404|502|503)', field):
                return int(field)

            token_match = re.search(r'(?<!\d)(404|502|503)(?!\d)', field)
            if token_match:
                return int(token_match.group(1))

        return None

    def _extract_url_and_status(self, line):
        """
        从一行原始数据中提取 URL 和其后附带的状态码。
        修复点：
        1. 不再用宽松正则把标题列/状态列识别成 URL
        2. 优先识别显式 http(s) URL
        3. 其次识别裸域名/IP[:port][/path]
        4. 状态码仅从 URL 后续字段中提取
        """
        if not line:
            return None, None

        fields = self._split_line_fields(line)
        if not fields:
            return None, None

        explicit_url_pattern = re.compile(r'https?://[^\s,"\']+')
        host_like_pattern = re.compile(
            r'^(?:'
            r'(?:\d{1,3}(?:\.\d{1,3}){3})'
            r'|'
            r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
            r')'
            r'(?::\d{1,5})?'
            r'(?:/[^\s,"\']*)?$'
        )

        for idx, field in enumerate(fields):
            field = field.strip().strip('"\'')
            if not field:
                continue

            explicit_match = explicit_url_pattern.search(field)
            if explicit_match:
                raw_url = explicit_match.group(0)
                normalized_url = self._normalize_candidate_url(raw_url)
                if normalized_url:
                    status_code = self._extract_status_from_fields(fields, idx)
                    return normalized_url, status_code

            if host_like_pattern.fullmatch(field):
                normalized_url = self._normalize_candidate_url(field)
                if normalized_url:
                    status_code = self._extract_status_from_fields(fields, idx)
                    return normalized_url, status_code

        return None, None

    def extract_and_dedup(self, files):
        """读取异构文件，提取 URL 并去重；若原始记录带有 404/502/503 状态码则跳过 httpx"""
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        clean_line = line.strip().strip('"\'')
                        if not clean_line:
                            continue

                        url, skip_status = self._extract_url_and_status(clean_line)
                        if not url:
                            continue

                        if skip_status in [404, 502, 503]:
                            self.skipped_targets.append({
                                "url": url,
                                "status_code": skip_status
                            })
                        else:
                            self.targets.add(url)

            except Exception as e:
                print(f"[-] 读取文件 {Fore.RED}{file}{Style.RESET_ALL} 报错: {e}")

        print(f"[+] 读取并去重完毕，共发现 {Fore.LIGHTYELLOW_EX}{len(self.targets)}{Style.RESET_ALL} 个独立目标。")
        if self.skipped_targets:
            print(f"[+] 识别到 {Fore.LIGHTYELLOW_EX}{len(self.skipped_targets)}{Style.RESET_ALL} 条带 404/502/503 状态码的记录，将跳过 httpx 探测并置于结果末尾。")

    def _prepare_temp_dir(self):
        """准备临时目录"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        os.makedirs(self.temp_dir, exist_ok=True)

    def _chunk_targets(self, targets, batch_size):
        """将目标分批"""
        for i in range(0, len(targets), batch_size):
            yield targets[i:i + batch_size]

    def _write_batch_file(self, batch_targets, batch_index):
        """写入批次目标文件"""
        input_file = os.path.join(self.temp_dir, f"targets_batch_{batch_index}.txt")
        with open(input_file, 'w', encoding='utf-8') as f:
            for target in batch_targets:
                f.write(target + '\n')
        return input_file

    def _run_httpx_batch(self, batch_targets, batch_index, start_seq):
        """执行单个批次的 httpx 扫描"""
        input_file = self._write_batch_file(batch_targets, batch_index)
        output_file = os.path.join(self.temp_dir, f"httpx_output_batch_{batch_index}.json")

        cmd = [
            "httpx",
            "-l", input_file,
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-server",
            "-json",
            "-rl", str(HTTPX_CONFIG["rate_limit"]),
            "-threads", str(HTTPX_CONFIG["threads"]),
            "-timeout", str(HTTPX_CONFIG["timeout"]),
            "-retries", str(HTTPX_CONFIG["retries"]),
            "-o", output_file
        ]

        batch_start = time.perf_counter()
        try:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as e:
            print(f"[-] 批次 {batch_index} 扫描失败: {e}")
        batch_end = time.perf_counter()

        batch_elapsed_ms = (batch_end - batch_start) * 1000
        avg_target_ms = batch_elapsed_ms / len(batch_targets) if batch_targets else 0

        for offset, url in enumerate(batch_targets):
            seq = start_seq + offset
            print(
                f"[~] 序号 {Fore.LIGHTYELLOW_EX}{seq}{Style.RESET_ALL}，扫描 {Fore.LIGHTBLUE_EX}{url}{Style.RESET_ALL} 完成，扫描用时 {Fore.LIGHTYELLOW_EX}{avg_target_ms:.2f}ms{Style.RESET_ALL}"
            )

        return output_file

    def _merge_httpx_outputs(self, output_files):
        """合并多个批次结果"""
        with open(self.final_httpx_output, 'w', encoding='utf-8') as outfile:
            for file in output_files:
                if not os.path.exists(file):
                    continue
                try:
                    with open(file, 'r', encoding='utf-8', errors='ignore') as infile:
                        for line in infile:
                            line = line.strip()
                            if line:
                                outfile.write(line + '\n')
                except Exception as e:
                    print(f"[-] 合并结果文件 {file} 时报错: {e}")

    def run_httpx(self):
        """调用 Httpx 工具进行分批并发存活检测与指纹识别"""
        if not self.targets:
            return

        if shutil.which("httpx") is None:
            print("[-] 错误: 系统未安装 httpx 或未加入环境变量。")
            exit(1)

        print("[*] 正在调用 Httpx 进行指纹识别与存活探测...")
        print(
            f"[*] 扫描参数: batch_size={HTTPX_CONFIG['batch_size']}, "
            f"concurrency={HTTPX_CONFIG['concurrency']}, "
            f"rate_limit={HTTPX_CONFIG['rate_limit']}, "
            f"threads={HTTPX_CONFIG['threads']}, "
            f"timeout={HTTPX_CONFIG['timeout']}, "
            f"retries={HTTPX_CONFIG['retries']}"
        )

        self._prepare_temp_dir()

        target_list = sorted(self.targets)
        batches = list(self._chunk_targets(target_list, HTTPX_CONFIG["batch_size"]))
        total_batches = len(batches)

        if total_batches == 0:
            print("[-] 没有可供扫描的目标。")
            return

        print(f"[*] 共拆分为 {Fore.GREEN}{total_batches}{Style.RESET_ALL} 个批次，并发执行中...")

        output_files = []
        future_map = {}

        with ThreadPoolExecutor(max_workers=HTTPX_CONFIG["concurrency"]) as executor:
            for batch_index, batch_targets in enumerate(batches, start=1):
                start_seq = (batch_index - 1) * HTTPX_CONFIG["batch_size"] + 1
                future = executor.submit(self._run_httpx_batch, batch_targets, batch_index, start_seq)
                future_map[future] = batch_index

            for future in as_completed(future_map):
                batch_index = future_map[future]
                try:
                    output_file = future.result()
                    output_files.append(output_file)
                    print(f"[+] 批次 {Fore.GREEN}{batch_index}/{total_batches}{Style.RESET_ALL} 扫描完成")
                except Exception as e:
                    print(f"[-] 批次 {batch_index} 执行异常: {e}")

        self._merge_httpx_outputs(sorted(output_files))

        print("[+] Httpx 探测完成！")

        # 清理临时目录
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def calculate_score(self, item):
        """核心评分算法"""
        score = 0
        reasons = []

        url = item.get('url', '')
        title = item.get('title', '')
        tech = item.get('tech', [])
        status = item.get('status_code', 0)

        tech_str = ' '.join(tech).lower() if isinstance(tech, list) else str(tech).lower()
        search_context = f"{title.lower()} | {tech_str}"
        url_lower = url.lower()

        for kw in RULES["url_keywords"]["keywords"]:
            if kw in url_lower:
                score += RULES["url_keywords"]["score"]
                reasons.append(f"{RULES['url_keywords']['desc']}({kw})")
                break

        for kw in RULES["vuln_frameworks"]["keywords"]:
            if kw in search_context:
                score += RULES["vuln_frameworks"]["score"]
                reasons.append(f"{RULES['vuln_frameworks']['desc']}({kw})")
                break

        for kw in RULES["title_keywords"]["keywords"]:
            if kw in title.lower():
                score += RULES["title_keywords"]["score"]
                reasons.append(f"{RULES['title_keywords']['desc']}({kw})")
                break

        for kw in RULES["weak_configs"]["keywords"]:
            if kw in search_context:
                score += RULES["weak_configs"]["score"]
                reasons.append(f"{RULES['weak_configs']['desc']}({kw})")
                break

        sensitive_path_hit = None
        for kw in RULES["sensitive_paths"]["keywords"]:
            if kw in url_lower:
                sensitive_path_hit = kw
                break

        if sensitive_path_hit:
            score += RULES["sensitive_paths"]["score"]
            reasons.append(f"{RULES['sensitive_paths']['desc']}({sensitive_path_hit})")

        parsed = urlparse(url)
        port = parsed.port
        if port and port not in [80, 443]:
            score += 5
            reasons.append(f"非标准端口({port})")

        if status == 200:
            score += 2
        elif status in [401, 403] and sensitive_path_hit:
            score += 5
            reasons.append(f"敏感路径上的未授权/禁止访问({status}状态码，可能存在规避的接口或后台)")
        elif status in [401, 403]:
            reasons.append(f"未授权/禁止访问({status}状态码，缺少敏感路径)")

        return score, " ; ".join(reasons)

    def process_results(self):
        """解析 Httpx 结果并打分排序"""
        if not os.path.exists(self.final_httpx_output):
            print("[-] 未找到 httpx 输出文件，可能所有目标均不存活。")
            self.results.extend(
                {
                    "URL": item["url"],
                    "Title": "N/A",
                    "Status": item["status_code"],
                    "Technologies": "",
                    "Score": -1,
                    "Reasons": f"原始数据状态码为 {item['status_code']}，跳过 httpx 探测"
                }
                for item in self.skipped_targets
            )
            self.results.sort(key=lambda x: x["Score"], reverse=True)
            return

        with open(self.final_httpx_output, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    score, reason = self.calculate_score(data)
                    self.results.append({
                        "URL": data.get('url', ''),
                        "Title": data.get('title', 'N/A'),
                        "Status": data.get('status_code', 'N/A'),
                        "Technologies": ", ".join(data.get('tech', [])),
                        "Score": score,
                        "Reasons": reason if reason else "常规"
                    })
                except json.JSONDecodeError:
                    continue

        for item in self.skipped_targets:
            self.results.append({
                "URL": item["url"],
                "Title": "N/A",
                "Status": item["status_code"],
                "Technologies": "",
                "Score": -1,
                "Reasons": f"原始数据状态码为 {item['status_code']}，跳过 httpx 探测"
            })

        self.results.sort(key=lambda x: x["Score"], reverse=True)

    def export_csv(self):
        """导出最终优先级的 CSV 文件"""
        if not self.results:
            return None

        output_file = f"{Fore.GREEN}Prioritized_Targets_Report.csv{Style.RESET_ALL}"
        output_file_real = "Prioritized_Targets_Report.csv"
        headers = ["Score", "URL", "Title", "Status", "Technologies", "Reasons"]

        with open(output_file_real, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for row in self.results:
                writer.writerow({
                    "Score": row["Score"],
                    "URL": row["URL"],
                    "Title": row["Title"],
                    "Status": row["Status"],
                    "Technologies": row["Technologies"],
                    "Reasons": row["Reasons"]
                })

        print(f"\n[↓] 资产整理与评分完毕，结果导出至: {output_file}")

        # print("\n" + "=" * 20 + " Top 5 高优先攻击目标 " + "=" * 20)
        # for i, row in enumerate(self.results[:5]):
        #     print(f"[{i + 1}] 分数: {row['Score']} | 目标: {row['URL']}")
        #     print(f"    标题: {row['Title']}")
        #     print(f"    加分项: {row['Reasons']}\n")

        return output_file_real

    def _html_escape(self, value):
        if value is None:
            return ""
        return html.escape(str(value), quote=True)

    def export_html(self, csv_file):
        """导出与 CSV 同名的 HTML 可视化报告"""
        if not self.results or not csv_file:
            return

        html_file = os.path.splitext(csv_file)[0] + ".html"
        headers = ["序号", "得分", "URL", "标题", "状态", "Technologies", "匹配因子"]

        rows_html = []
        for index, row in enumerate(self.results, start=1):
            rows_html.append(
                "<tr>"
                f"<td>{self._html_escape(index)}</td>"
                f"<td>{self._html_escape(row['Score'])}</td>"
                f"<td class=\"url-cell\"><a href=\"{self._html_escape(row['URL'])}\" target=\"_blank\">{self._html_escape(row['URL'])}</a></td>"
                f"<td>{self._html_escape(row['Title'])}</td>"
                f"<td>{self._html_escape(row['Status'])}</td>"
                f"<td>{self._html_escape(row['Technologies'])}</td>"
                f"<td>{self._html_escape(row['Reasons'])}</td>"
                "</tr>"
            )

        header_html = "".join(
            f"<th><div class=\"th-inner\"><span>{self._html_escape(col)}</span><div class=\"col-resizer\"></div></div></th>"
            for col in headers
        )

        page = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Prioritized Targets Report</title>
    <style>
        :root {{
            --bg: #ffecd6;
            --panel: #fff5ea;
            --panel-2: #fecca0;
            --line: #facf58;
            --line-dark: #efc355;
            --text: #512a00;
            --text-soft: #432817;
            --accent: #ba6000;
            --accent-dark: #964e00;
            --header: #e6d6cf;
            --row-alt: #f7f2ed;
            --shadow: #ba6d1b;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 24px;
            background: var(--bg);
            color: var(--text);
            font-family: Tahoma, Verdana, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.4;
        }}

        .app {{
            width: 100%;
            max-width: 1600px;
            margin: 0 auto;
            border: 1px solid var(--line-dark);
            background: var(--panel);
            box-shadow: 4px 4px 0 var(--shadow);
        }}

        .topbar {{
            background: linear-gradient(to bottom, var(--header), #dac0bd);
            border-bottom: 1px solid var(--line-dark);
            padding: 14px 18px;
        }}

        .title {{
            margin: 0;
            font-size: 22px;
            font-weight: bold;
            letter-spacing: 0.5px;
        }}

        .subtitle {{
            margin-top: 6px;
            color: var(--text-soft);
            font-size: 12px;
        }}

        .meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            padding: 12px 18px;
            border-bottom: 1px solid var(--line);
            background: var(--panel-2);
        }}

        .meta-box {{
            min-width: 180px;
            padding: 10px 12px;
            border: 1px solid var(--line);
            background: var(--panel);
        }}

        .meta-label {{
            font-size: 12px;
            color: var(--text-soft);
            margin-bottom: 4px;
        }}

        .meta-value {{
            font-size: 18px;
            font-weight: bold;
            color: var(--accent-dark);
        }}

        .tips {{
            padding: 10px 18px;
            border-bottom: 1px solid var(--line);
            background: #f8f5ee;
            color: var(--text-soft);
            font-size: 12px;
        }}

        .table-wrap {{
            overflow: auto;
            width: 100%;
            background: #fcfaf7;
        }}

        table {{
            width: 100%;
            min-width: 1300px;
            border-collapse: collapse;
            table-layout: fixed;
        }}

        colgroup col:nth-child(1) {{ width: 80px; }}
        colgroup col:nth-child(2) {{ width: 90px; }}
        colgroup col:nth-child(3) {{ width: 300px; }}
        colgroup col:nth-child(4) {{ width: 260px; }}
        colgroup col:nth-child(5) {{ width: 100px; }}
        colgroup col:nth-child(6) {{ width: 220px; }}
        colgroup col:nth-child(7) {{ width: 520px; }}

        thead th {{
            position: sticky;
            top: 0;
            z-index: 2;
            background: var(--header);
            color: var(--text);
            border: 1px solid var(--line-dark);
            padding: 0;
            text-align: left;
            font-weight: bold;
        }}

        .th-inner {{
            position: relative;
            padding: 10px 12px;
            user-select: none;
        }}

        .col-resizer {{
            position: absolute;
            top: 0;
            right: 0;
            width: 8px;
            height: 100%;
            cursor: col-resize;
            background: transparent;
        }}

        .col-resizer:hover {{
            background: rgba(93, 127, 93, 0.18);
        }}

        tbody td {{
            border: 1px solid var(--line);
            padding: 10px 12px;
            vertical-align: top;
            word-break: break-word;
            background: #fdfcf8;
        }}

        tbody tr:nth-child(even) td {{
            background: var(--row-alt);
        }}

        tbody tr:hover td {{
            background: #f0ede0;
        }}

        .url-cell a {{
            color: #5c3a24;
            text-decoration: none;
        }}

        .url-cell a:hover {{
            text-decoration: underline;
        }}

        .footer {{
            border-top: 1px solid var(--line);
            background: var(--panel-2);
            padding: 10px 18px;
            color: var(--text-soft);
            font-size: 12px;
        }}

        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border: 1px solid var(--line-dark);
            background: #f4f3e7;
            color: var(--accent-dark);
            margin-right: 6px;
        }}
    </style>
</head>
<body>
    <div class="app">
        <div class="topbar">
            <h1 class="title">资产价值评估报告</h1>
        </div>

        <div class="meta">
            <div class="meta-box">
                <div class="meta-label">结果总数</div>
                <div class="meta-value" style="font-size:14px;">{len(self.results)}</div>
            </div>
            <div class="meta-box">
                <div class="meta-label">结果文件</div>
                <div class="meta-value" style="font-size:14px;">{self._html_escape(os.path.basename(csv_file))}</div>
            </div>
            <div class="meta-box">
                <div class="meta-label">来源总数</div>
                <div class="meta-value" style="font-size:14px;">{len(self.targets)}</div>
            </div>
            <div class="meta-box">
                <div class="meta-label">来源文件</div>
                <div class="meta-value" style="font-size:14px;">{self._html_escape(', '.join(self.input_files))}</div>
            </div>
        </div>

        <div class="table-wrap">
            <table id="reportTable">
                <colgroup>
                    <col>
                    <col>
                    <col>
                    <col>
                    <col>
                    <col>
                    <col>
                </colgroup>
                <thead>
                    <tr>
                        {header_html}
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows_html)}
                </tbody>
            </table>
        </div>

        <div class="footer" style="display: flex; justify-content: space-between; align-items: center; padding: 10px 0; font-size: 14px; color: #666;">
            <span>  本报告由 sssJury.py 自动生成。</span>
            <span>Github: https://github.com/L0g1cX/sssJury-scanner/  </span>
        </div>
    </div>

    <script>
        (function () {{
            const table = document.getElementById('reportTable');
            const cols = table.querySelectorAll('colgroup col');
            const resizers = table.querySelectorAll('.col-resizer');

            resizers.forEach((resizer, index) => {{
                let startX = 0;
                let startWidth = 0;
                let active = false;

                const onMouseMove = (e) => {{
                    if (!active) return;
                    const dx = e.clientX - startX;
                    const newWidth = Math.max(60, startWidth + dx);
                    cols[index].style.width = newWidth + 'px';
                }};

                const onMouseUp = () => {{
                    active = false;
                    document.body.style.cursor = '';
                    document.body.style.userSelect = '';
                    window.removeEventListener('mousemove', onMouseMove);
                    window.removeEventListener('mouseup', onMouseUp);
                }};

                resizer.addEventListener('mousedown', (e) => {{
                    e.preventDefault();
                    active = true;
                    startX = e.clientX;
                    startWidth = cols[index].getBoundingClientRect().width;
                    document.body.style.cursor = 'col-resize';
                    document.body.style.userSelect = 'none';
                    window.addEventListener('mousemove', onMouseMove);
                    window.addEventListener('mouseup', onMouseUp);
                }});
            }});
        }})();
    </script>
</body>
</html>
"""

        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(page)

        print(f"[↓] HTML 可视化报告已导出至: {Fore.GREEN}{html_file}{Style.RESET_ALL}")


if __name__ == "__main__":
    print("""
                               `..                                       
                               `..                                       
 `....  `....  `....           `..  `..  `..  `. `...  `..   `..
`..    `..    `..              `..  `..  `..   `..      `.. `.. 
  `...   `...   `...           `..  `..  `..   `..        `...  
    `..    `..    `..     `.   `..  `..  `..   `..         `..  
`.. `..`.. `..`.. `..       `....     `..`..  `...        `..   
                                                        `..    
                      资产价值评估安全工具
    
    """)
    hunter = AssetHunter()
    files = hunter.get_input_files()
    hunter.extract_and_dedup(files)
    hunter.run_httpx()
    hunter.process_results()
    csv_file = hunter.export_csv()
    hunter.export_html(csv_file)
