import threading
import uuid
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

from Common.client import client_main
from Common.logger import setup_logger, get_logger
from Common.reptile import get_soap

is_first_stop = True
vul_lists = []


def ts():
    n = datetime.datetime.now()
    return n.strftime("%Y%m%d") + str(n.hour * 3600 + n.minute * 60 + n.second) + '_' + str(uuid.uuid4())[:4]


def parse_http_request(raw_data):
    """解析HTTP请求数据包"""

    class HTTPRequest(BaseHTTPRequestHandler):
        def __init__(self, request_text):
            self.rfile = BytesIO(request_text.encode())
            self.raw_requestline = self.rfile.readline()
            self.error_code = self.error_message = None
            self.parse_request()

        def send_error(self, code, message):
            self.error_code = code
            self.error_message = message

    # 创建请求对象

    request = HTTPRequest(raw_data)

    # 提取body（在空行之后的内容）
    body = ''
    if '\r\n\r\n' in raw_data:
        body = raw_data.split('\r\n\r\n', 1)[1]
    elif '\n\n' in raw_data:
        body = raw_data.split('\n\n', 1)[1]

    parse_http = {
        'method': getattr(request, 'command', ''),
        'path': getattr(request, 'path', ''),
        'version': getattr(request, 'request_version', ''),
        'headers': dict(getattr(request, 'headers', {})),
        'body': body
    }
    return parse_http


logger = get_logger(__name__)

lock = threading.Lock()


def go(api_url, wsdl_target_url, proxy, soap_example):
    with lock:
        if is_first_stop and wsdl_target_url in vul_lists:
            return
    # 解析soap数据包
    parse_http = parse_http_request(soap_example)
    if len(parse_http) == 0:
        logger.debug("未解析到数据包")
        exit(0)
    # 开始扫描
    api_url = api_url
    req_type = parse_http.get("method", None)
    target_url = f"{urlparse(wsdl_target_url).scheme}://{parse_http.get('headers').get('Host')}{parse_http.get('path')}"
    target_headers = '\n'.join([f'{k}: {v}' for k, v in parse_http.get('headers').items()])
    target_body = parse_http.get('body', None)

    b, log_data = client_main(api_url, req_type, target_url, target_headers, target_body, proxy)
    result = {
        'info': b,
        'wsdl_target_url': wsdl_target_url,
        'target_url': target_url,
        'soap_example': soap_example,
        'log_data': log_data,
    }
    return result


def run_check_wsdl_sql(api_url, wsdl_target_url, proxy, thread):
    # 爬虫
    soap_examples = get_soap(wsdl_target_url, proxy)
    if not soap_examples:
        logger.warning(f"未获取到SOAP示例: {wsdl_target_url}")
        return

    run_data_list = []
    for _, soap_example in enumerate(soap_examples):
        run_data_list.append((api_url, wsdl_target_url, proxy, soap_example))
    # 用线程池执行
    with ThreadPoolExecutor(max_workers=thread) as executor:
        for params in run_data_list:
            futures = [executor.submit(go, *params)]
            # 实时获取结果
            for future in as_completed(futures):
                result = future.result()
                if result is not None and result['info']:
                    with lock:
                        if result['wsdl_target_url'] in vul_lists:
                            continue
                        t = ts()
                        vul_lists.append(result['wsdl_target_url'])
                        logger.info(f"存在SQL注入:{result['wsdl_target_url']}")
                        path = Path(f"output/{urlparse(result['wsdl_target_url']).hostname}")
                        path.mkdir(parents=True, exist_ok=True)
                        path_url = path / f"{t}_url.txt"
                        path_row_http = path / f"{t}_row_http.txt"
                        path_log_data = path / f"{t}_log.txt"
                        path_url.write_text(result['target_url'])
                        path_row_http.write_text(result['soap_example'].replace('\r\n', '\n'))
                        path_log_data.write_text(result['log_data'])

