import argparse
import os

import Common.config
from Common.config import run_check_wsdl_sql, vul_lists
from Common.logger import setup_logger, get_logger


def read_file_to_array(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file]


banner = """
  ___        _           _ __        ______  ____  _     
 |_ _|_ __  (_) ___  ___| |\ \      / / ___||  _ \| |    
  | || '_ \ | |/ _ \/ __| __\ \ /\ / /\___ \| | | | |    
  | || | | || |  __/ (__| |_ \ V  V /  ___) | |_| | |___ 
 |___|_| |_|/ |\___|\___|\__| \_/\_/  |____/|____/|_____|
          |__/                                           
 @xbfding
"""

if __name__ == "__main__":
    print(banner)
    # 创建参数解析器
    parser = argparse.ArgumentParser(description='WSDL注入检查工具')

    # 添加参数
    parser.add_argument('-t', '--target', default=None, help='输入URL')
    parser.add_argument('-tf', '--target_file', default=None, help='输入文件目录,URL一行一个')
    parser.add_argument('--is_first_stop', type=bool, default=True,
                        help='当前URL发现漏洞后立即停止扫描,输入True,False.默认:True')
    parser.add_argument('-api', '--sqlmap_api', default="http://127.0.0.1:8775",
                        help='输入sqlmapApi地址,默认http://127.0.0.1:8775')
    parser.add_argument('-T', '--thread', type=int, default=3, help='同时进行sql注入的数据包，默认是3')
    parser.add_argument('-p', '--proxy', default=None, help='代理地址,http://127.0.0.1:7890')
    parser.add_argument('-log', '--loglevel', default="info", help='日志显示等级info,error,debug')
    parser.add_argument('-v', '--version', action='version', version=f'version:V1.1-20250811')

    # 解析参数
    args = parser.parse_args()

    # 根据命令行参数配置日志
    setup_logger(args.loglevel)  # 这里才真正设置日志级别

    # 获取日志器并使用
    logger = get_logger(__name__)
    Common.config.is_first_stop = args.is_first_stop

    wsdl_target_urls = []
    if args.target_file is not None:
        wsdl_target_urls.extend(read_file_to_array(args.target_file))

    if args.target is not None:
        wsdl_target_urls.append(args.target)

    # 启动sqlmap api服务
    # start(host, port)
    try:
        # 准备数据
        for _, wsdl_target_url in enumerate(wsdl_target_urls):
            logger.info(f"开始扫描{wsdl_target_url}:")
            run_check_wsdl_sql(args.sqlmap_api, wsdl_target_url, args.proxy, args.thread)

        for _, t in enumerate(wsdl_target_urls):
            if t not in vul_lists:
                logger.info(f"未检测出SQL注入漏洞:{t}")
        logger.info("检查结束!")
    except KeyboardInterrupt:
        print("\nCurl+C Exit...")
        os._exit(0)