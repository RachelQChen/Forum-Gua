import time

def log(*args):
    t = time.time()
    formated_time = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(t))
    print(formated_time, *args)

