import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import requests
from urllib.parse import urlparse

# 优化1：新增全局变量，记录最优扫描协议（避免双协议重复请求，大幅提速）
best_protocol = "http"


def clean_domain(domain_input):
    """
    清洗输入的域名，去除 http/https、末尾斜杠等无效内容
    """
    if not domain_input:
        return None
    domain_input = domain_input.strip()
    if domain_input.startswith(('http://', 'https://')):
        domain_input = urlparse(domain_input).netloc
    if domain_input.endswith('/'):
        domain_input = domain_input[:-1]
    return domain_input


BANNER = r"""
  _____             _     _                       
 |  __ \           | |   | |                      
 | |  | | __ _ _ __| | __| | __ _ _ __ _   _      
 | |  | |/ _` | '__| |/ _` |/ _` | '__| | | |     
 | |__| | (_| | |  | | (_| | (_| | |  | |_| |     
 |_____/ \__,_|_|  |_|\__,_|\__,_|_|   \__, |     
                                        __/ |     
  Subdomain Scanner v1.0               |___/      
  Status: Broken Heart 💔 | Mode: Crying...       

  [ 别扫了，字典再大也扫不回她的心... :( ]
  [ 使用教程 ]：
  1. 请将你的字典文件重命名为 'dic.txt'。
  2. 将 'dic.txt' 放入本脚本所在的当前文件夹内。
  3. 脚本会自动读取并开始“碎心爆破”。
--------------------------------------------------
"""
print(BANNER)

# 初始化 requests Session
session = requests.Session()
# 优化2：适度提高并发池（60，兼顾速度和资源占用，比50快且不易卡顿）
adapter = requests.adapters.HTTPAdapter(pool_connections=60, pool_maxsize=60)
session.mount('http://', adapter)
session.mount('https://', adapter)

# 输入提示 + 域名清洗
domain_input = input("请输入根域名（示例：baidu.com）：")
domain_root = clean_domain(domain_input)
if not domain_root:
    print("[!] 输入的域名无效，请重新运行脚本并输入正确格式的根域名")
    exit(1)

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}


def get_wildacrd_fingerprint(root_domain):
    """
    检测目标域名是否存在泛解析，同时记录最优扫描协议（大幅减少后续无用请求）
    优化：检测成功后锁定协议，不再双协议尝试
    """
    global best_protocol
    random_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    test_urls = [
        f"https://{random_prefix}.{root_domain}",  # 优先检测https（现在大部分域名支持）
        f"http://{random_prefix}.{root_domain}"
    ]

    for test_url in test_urls:
        current_proto = test_url.split('://')[0]
        print(f"[*] 正在检测泛解析：{test_url}")
        try:
            # 优化3：缩短超时时间到2秒（减少无效等待，大幅提速，漏扫概率极低）
            res = session.get(test_url, headers=headers, timeout=2, allow_redirects=False)
            wc_code = res.status_code
            wc_len = len(res.content)
            best_protocol = current_proto  # 锁定成功的协议，后续仅用该协议扫描
            print(f"[*] 存在泛解析! 状态码: {wc_code}，页面长度: {wc_len}")
            print(f"[*] 后续将使用 {best_protocol} 协议扫描，过滤无效条目")
            return True, wc_code, wc_len
        except requests.exceptions.RequestException:
            continue

    # 无泛解析时，锁定第一个可用协议（优先https）
    for test_url in test_urls:
        current_proto = test_url.split('://')[0]
        try:
            session.get(test_url, headers=headers, timeout=2, allow_redirects=False)
            best_protocol = current_proto
            break
        except:
            continue
    print(f"[*] 不存在泛解析，将使用 {best_protocol} 协议开始子域名爆破")
    return False, None, None


is_wildcard, wc_code, wc_len = get_wildacrd_fingerprint(domain_root)
print("-" * 50)

# 读取字典文件
try:
    with open('dic.txt', 'r', encoding='utf-8') as f:
        # 优化4：有序去重（比set更省内存，且不打乱字典顺序）
        subdomains = list(dict.fromkeys([line.strip() for line in f if line.strip()]))
    print(f"[*] 成功读取字典文件，共加载 {len(subdomains)} 个不重复子域名条目")
except FileNotFoundError:
    print("[!] 错误：当前目录下未找到 dic.txt 字典文件，请按照教程放置字典文件后重新运行")
    exit(1)
except Exception as e:
    print(f"[!] 读取字典文件失败：{str(e)}")
    exit(1)

# 优化5：边扫描边写入文件（避免内存堆积，缓解卡顿，无需等待全部扫描完成）
result_file = open('subdomain.txt', 'w', encoding='utf-8')
found_count = 0  # 统计有效子域名数量


def check_subdomain(sub):
    """
    检查单个子域名是否有效（仅用锁定的协议，大幅提速，减少资源占用）
    """
    global found_count
    url = f"{best_protocol}://{sub}.{domain_root}"
    try:
        res = session.get(url, headers=headers, timeout=2, allow_redirects=False)
        current_code = res.status_code
        current_len = len(res.content)

        # 泛解析过滤逻辑
        if is_wildcard:
            if current_code == wc_code and abs(current_len - wc_len) < 200:
                return

        # 记录有效子域名
        if current_code in [200, 301, 302, 403, 401]:
            result_line = f"{sub}.{domain_root}   {current_code}   {url}\n"
            # 优化6：关闭频繁控制台打印（改为仅写入文件，缓解卡顿，大幅提速）
            result_file.write(result_line)
            found_count += 1
    except requests.exceptions.RequestException:
        return


# 优化7：适度提高并发数到60（IO密集型任务，略提高并发不卡顿且更快）
max_workers = 60
print(f"[*] 启动 {max_workers} 个并发线程，开始子域名爆破...")
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    future_results = [executor.submit(check_subdomain, sub) for sub in subdomains]
    # tqdm进度条保持（简化刷新，减少CPU占用）
    for future in tqdm(as_completed(future_results), total=len(subdomains), desc="爆破进度"):
        future.result()

# 关闭文件
result_file.close()
print(f"\n[*] 完成！共发现 {found_count} 个不重复有效子域名，结果已写入 subdomain.txt")