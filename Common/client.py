import json
import logging
import os
import time

import requests
from Common.logger import get_logger

logger = get_logger(__name__)


def get_version(api_url):
    """获取 sqlmap 版本信息"""
    try:
        response = requests.get(f"{api_url}/version", verify=False)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        logger.debug(f"获取版本信息失败: {e}")
        return None


def is_server_running(api_url):
    """检查服务器是否运行"""
    try:
        response = requests.get(f"{api_url}/version", timeout=5, verify=False)
        return response.status_code == 200
    except:
        return False


def create_new_task(api_url):
    """创建任务ID"""
    try:
        response = requests.get(f"{api_url}/task/new", verify=False)
        if response.status_code == 200:
            task_id = response.json()['taskid']
            logger.debug(f"创建新任务ID成功，任务ID: {task_id}")
            return task_id
        else:
            logger.error(f"创建任务ID失败: {response.text}")
            return None
    except Exception as e:
        logger.error(f"创建任务ID异常: {e}")
        return None


def delete_task(api_url, task_id):
    """删除任务"""
    try:
        response = requests.get(f"{api_url}/task/{task_id}/delete", verify=False)
        if response.status_code == 200:
            logger.debug(f"任务 {task_id} 删除成功")
            return True
        else:
            logger.error(f"删除任务失败: {response.text}")
            return False
    except Exception as e:
        logger.error(f"删除任务异常: {e}")
        return False


def init_database(target_url, req_type, target_headers, target_body, proxy):
    if req_type == "POST":
        data = {
            "url": target_url,
            "method": req_type,
            "headers": target_headers,
            "data": target_body,
            "level": 1,
            "risk": 1,
            "technique": "BEUSTQ",
            "batch": True,
            "randomAgent": True,
            "proxy": proxy,
            "ignoreProxy": False
        }
    if req_type == "GET":
        data = {
            "url": target_url,
            "method": req_type,
            "level": 1,
            "risk": 1,
            "technique": "BEUSTQ",
            "batch": True,
            "randomAgent": True,
            "proxy": proxy,
            "ignoreProxy": False
        }
    return json.dumps(data)


def start_scan(api_url, task_id, req_type, target_url, target_headers, target_body, proxy):
    """启动扫描任务"""
    try:

        response = requests.post(
            url=f"{api_url}/scan/{task_id}/start",
            headers={'Content-Type': 'application/json'},
            data=init_database(target_url, req_type, target_headers, target_body, proxy),
            # proxies={
            #     "http": "http://127.0.0.1:8083",
            #     "https": "http://127.0.0.1:8083",
            # }
            verify=False
        )
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                logger.debug(f"扫描任务 {task_id} 启动成功")
                return True
            else:
                logger.error(f"启动扫描失败: {result}")
                return False
        else:
            logger.error(f"启动扫描失败: {response.text}")
            return False

    except KeyboardInterrupt:
        print("\nCurl+C Exit...")
        os._exit(0)
    except Exception as e:
        logger.error(f"启动扫描异常: {e}")
        return False


def get_scan_status(api_url, task_id):
    """获取扫描状态"""
    try:
        response = requests.get(f"{api_url}/scan/{task_id}/status", verify=False)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        return None


def get_scan_data(api_url, task_id):
    """获取扫描数据"""
    try:
        response = requests.get(f"{api_url}/scan/{task_id}/data", verify=False)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        return None


def get_scan_log(api_url, task_id):
    """获取扫描日志"""
    try:
        response = requests.get(f"{api_url}/scan/{task_id}/log", verify=False)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        return None


def get_final_results(api_url, task_id):
    """获取最终扫描结果"""
    try:
        data = get_scan_data(api_url, task_id)
        if data and 'data' in data:
            results = data['data']

            if results:
                data_log = ""
                data_log += f"发现 {len(results) // 2} 个潜在的SQL注入点:\r\n"
                data_log += f'{"=" * 60}\r\n'

                for _, result in enumerate(results, 1):
                    if 'value' in result:
                        if isinstance(result['value'], list):
                            # 遍历 data_structure['data'] 提取 title 和 payload
                            for values in result['value']:
                                data_log += f"请求方式: {values.get('place', 'N/A')}\r\n"
                                data_log += f'{"=" * 40}\r\n'
                                data = values.get("data", {})
                                for key, value in data.items():
                                    data_log += f"参数ID: {key}\r\n"
                                    data_log += f"标题: {value.get('title', 'N/A')}\r\n"
                                    data_log += f"载荷: {value.get('payload', 'N/A')}\r\n"
                                    data_log += f'{"=" * 40}\r\n'
                        else:
                            data_log += f"网站地址: {result['value'].get('url', 'N/A')}\r\n"
                            data_log += f"利用参数: {result['value'].get('query', 'N/A')}\r\n"
                logger.debug(data_log)
                return True, data_log

            else:
                logger.debug("未发现SQL注入漏洞")
                return False, None
        else:
            logger.error("无法获取扫描结果")
            return False, None

    except Exception as e:
        logger.error(f"获取最终结果异常: {e}")


def stop_scan(api_url, task_id):
    """停止扫描"""
    try:
        response = requests.get(f"{api_url}/scan/{task_id}/stop", verify=False)
        if response.status_code == 200:
            logger.debug(f"扫描任务 {task_id} 已停止")
            return True
        return False
    except Exception as e:
        return False


def monitor_scan_progress(api_url, task_id, check_interval=5):
    """监控扫描进度并实时返回结果"""
    logger.debug(f"开始监控任务 {task_id} 的进度...")
    logger.debug("=" * 60)

    last_log_count = 0

    while True:
        try:
            # 获取任务状态
            status = get_scan_status(api_url, task_id)
            if not status:
                break

            current_status = status.get('status', 'unknown')
            # print(f"\r当前状态: {current_status}", end='', flush=True)

            # 获取日志
            log_data = get_scan_log(api_url, task_id)
            if log_data and 'log' in log_data:
                logs = log_data['log']
                new_logs = logs[last_log_count:]

                if new_logs:
                    for log_entry in new_logs:
                        timestamp = log_entry.get('time', '')
                        level = log_entry.get('level', 'INFO')
                        message = log_entry.get('message', '')
                        logger.debug(f"[{timestamp}] [{level}] {message}")

                    last_log_count = len(logs)

            # 检查是否完成
            if current_status in ['terminated', 'finished']:
                logger.debug(f"任务 {task_id} 已完成，状态: {current_status}")
                break

            time.sleep(check_interval)

        except KeyboardInterrupt:
            logger.error(f"用户中断，停止监控任务 {task_id}")
            stop_scan(api_url, task_id)
            break
        except Exception as e:
            logger.error(f"监控异常: {e}")
            break

    # 获取最终结果
    logger.debug("\n" + "=" * 60)
    logger.debug("获取最终扫描结果...")
    b, data = get_final_results(api_url, task_id)
    if b:
        return True, data
    return False, None


def client_main(api_url, req_type, target_url, target_headers=None, target_body=None, proxy=None):

    task_id = create_new_task(api_url)
    if len(task_id) > 0:
        if not start_scan(api_url, task_id, req_type, target_url, target_headers, target_body, proxy):
            logging.error("扫描出错")
            exit(1)
        b, log_data = monitor_scan_progress(api_url, task_id, check_interval=5)
        if b:
            return True, log_data
        return False, None
