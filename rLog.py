import time

def log(*args):
    t = time.time()
    formated_time = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(t))
    # time_str_list = []
    # for t in formated_time:
    #     time_str_list.append(str(t))
    # time_str = ''.join(time_str_list)
    # arg_list = []
    # for arg in args:
    #     arg_list.append(str(arg))
    # arg_str = '|'.join(arg_list)
    # with open('log.txt', 'w') as f:
    #     f.write(time_str + ' ' + arg_str + '\r\n')
    print(formated_time, *args)
    # print(time_str + ' ' + arg_str + '\r\n')


