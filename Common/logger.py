import logging
import sys


class ColorFormatter(logging.Formatter):
    """自定义日志格式化类，支持颜色输出"""
    COLORS = {
        "DEBUG": "\033[34m",  # 蓝色
        "INFO": "\033[32m",  # 绿色
        "WARNING": "\033[33m",  # 黄色
        "ERROR": "\033[31m",  # 红色
        "CRITICAL": "\033[41m",  # 红色背景
        "RESET": "\033[0m",  # 重置颜色
        "TIME": "\033[36m",  # 青色
    }

    def format(self, record):
        level_color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        time_color = self.COLORS["TIME"]
        reset_color = self.COLORS["RESET"]

        # 格式化时间，添加颜色
        formatted_time = self.formatTime(record, self.datefmt)
        colored_time = f"{time_color}{formatted_time}{reset_color}"

        # 格式化日志等级，添加颜色
        colored_level = f"{level_color}{record.levelname}{reset_color}"

        # 手动构建最终的日志消息
        log_message = f"[{colored_time}] [{colored_level}] {record.getMessage()}"

        return log_message


class LoggerConfig:
    _instance = None
    _configured = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def setup(self, log_level="info", log_file=None):
        """配置日志系统"""
        if self._configured:
            return

        level_map = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL
        }
        level = level_map.get(log_level.lower(), logging.INFO)

        # 清除现有的处理器
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # 创建控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColorFormatter(datefmt='%Y-%m-%d %H:%M:%S'))

        # 创建文件处理器（如果需要）
        handlers = [console_handler]
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            # 文件处理器使用无颜色格式
            file_handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s",
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            handlers.append(file_handler)

        # 配置根日志器
        logging.basicConfig(
            level=level,
            handlers=handlers,
            force=True
        )

        self._configured = True

    def get_logger(self, name=None):
        """获取日志器"""
        return logging.getLogger(name)


# 创建全局实例
logger_config = LoggerConfig()


# 提供便捷函数
def setup_logger(log_level="info", log_file=None):
    logger_config.setup(log_level, log_file)


def get_logger(name=None):
    return logger_config.get_logger(name)


# 使用示例
if __name__ == "__main__":
    # 设置日志级别和输出文件（可选）
    setup_logger(log_level="debug", log_file="app.log")

    # 获取日志器
    logger = get_logger("MyApp")

    # 记录不同级别的日志
    logger.debug("这是 DEBUG 信息")
    logger.info("这是 INFO 信息")
    logger.warning("这是 WARNING 信息")
    logger.error("这是 ERROR 信息")
    logger.critical("这是 CRITICAL 信息")