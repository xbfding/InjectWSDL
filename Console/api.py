import threading

# from sqlmapapi import server


# def start(host="127.0.0.1", port=8775):
#     try:
#         # 创建并启动后台线程
#         thread = threading.Thread(target=server, args=(host, port))
#         thread.daemon = True  # 设置为守护线程，主程序结束时自动结束
#         thread.start()
#     except Exception as e:
#         print(f"启动错误: {e}")
