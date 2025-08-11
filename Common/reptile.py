import re
import warnings
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

from Common.logger import get_logger

logger = get_logger(__name__)

warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)


def http_request(url, http_type, headers=None, data=None, proxy=None, try_agent=3):
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    proxies = {
        'http': proxy,
        'https': proxy
    }
    if headers is None:
        headers = {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/7.0.12(0x17000c2f) NetType/4G Language/zh_CN wechatdevtools qcloudcdn-xinan  uacq"
        }

    def request():
        if http_type == 'GET':
            response = requests.get(url, headers=headers, proxies=proxies, verify=False)
            return True, response
        if http_type == 'POST':
            response = requests.post(url, headers=headers, data=data, proxies=proxies, verify=False)
            return True, response

    for i in range(try_agent):
        try:
            b, data = request()
            if b:
                return data
        except Exception as e:
            logger.error(f"请求出错:{e}")
    return None


def extract_hrefs_with_beautifulsoup(html_content):
    """使用BeautifulSoup提取所有href值"""
    soup = BeautifulSoup(html_content, 'html.parser')

    # 找到所有包含href属性的<a>标签
    links = soup.find_all('a', href=True)

    # 提取href值
    filter_keywords = ['www.w3.org', 'www.ietf.org']
    hrefs = []
    for link in links:
        href = link['href']
        # 检查是否包含任何过滤关键词
        if not any(keyword in href for keyword in filter_keywords):
            hrefs.append(href)

    return hrefs


def process_xml_content(xml_content, host_port):
    """处理XML内容"""
    # 这里使用半年前的时间
    half_year_ago = datetime.now() - timedelta(days=183)
    current_time = half_year_ago.strftime("%Y-%m-%dT%H:%M:%S")

    new_request = re.sub(r'Host: [^\r\n]+', f'Host: {host_port}', xml_content)
    # 移除Content-Length行
    new_request = re.sub(r'Content-Length: [^\r\n]+\r\n', '', new_request)
    # 使用正则表达式替换 <tag>int</tag> 和 <tag>string</tag> 为 <tag>123456</tag>
    new_request = re.sub(r'<(\w+)>(int|string)</(\w+)>', r'<\1>123456</\3>', new_request)
    new_request = re.sub(r'<(\w+)>dateTime</(\w+)>', rf'<\1>{current_time}</\2>', new_request)
    return new_request


def extract_clean_soap_requests(html_content):
    """提取干净的SOAP请求包内容"""
    warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)
    soup = BeautifulSoup(html_content, "html.parser")
    pre_tags = soup.find_all('pre')

    soap_requests = []

    for pre in pre_tags:
        content = pre.get_text()

        if content.startswith('POST'):
            # 清理内容，移除HTML实体和多余空白
            clean_content = content.replace('&lt;', '<').replace('&gt;', '>')

            # 判断是SOAP 1.1还是1.2
            # if 'text/xml' in clean_content:
            #     soap_version = 'SOAP 1.1'
            # elif 'application/soap+xml' in clean_content:
            #     soap_version = 'SOAP 1.2'
            # else:
            #     soap_version = 'Unknown'

            soap_requests.append({
                # 'version': soap_version,
                'content': clean_content
            })

    return soap_requests


def get_soap(target_url, proxy=None):
    response = http_request(url=target_url, http_type="GET", proxy=proxy)
    if response is None:
        return None
    if response.status_code != 200:
        logger.debug(f"响应错误{response.status_code}")
        return None

    soap_examples = []
    hrefs_urls = extract_hrefs_with_beautifulsoup(response.text)
    for href in hrefs_urls:
        if "://" in href:
            continue
        response_1 = http_request(url=f"{target_url}/{href}", http_type="GET", proxy=proxy)
        soap_requests = extract_clean_soap_requests(response_1.text)
        if len(soap_requests) > 0:
            for soap_request in soap_requests:
                if soap_request['content']:
                    if urlparse(target_url).port is not None:
                        soap_example = process_xml_content(soap_request.get('content'),
                                                           f"{urlparse(target_url).hostname}:{urlparse(target_url).port}")
                    else:
                        soap_example = process_xml_content(soap_request.get('content'),
                                                           f"{urlparse(target_url).hostname}")
                    soap_examples.append(soap_example)
    return soap_examples


if __name__ == '__main__':
    soap_examples = get_soap("http://220.179.244.131:8088/")
    if soap_examples == None:
        print("未获取到soap数据包")
        exit(0)
