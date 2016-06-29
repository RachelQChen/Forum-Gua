import time


def formatted_time(timestamp):
    now = int(time.time())
    n = time.localtime(now)
    t = time.localtime(timestamp)
    this_year = time.strftime('%Y', n)
    timestamp_year = time.strftime('%Y', t)
    if this_year != timestamp_year:
        time_format = '%y/%m/%d %H:%M'
    else:
        time_format = '%m/%d %H:%M'
    ft = time.strftime(time_format, t)
    return ft


def short_time(timestamp):
    time_format = '%m/%d %H:%M'
    t = time.localtime(timestamp)
    ft = time.strftime(time_format, t)
    return ft


def from_now(timestamp):
    now = int(time.time())
    from_now = now - timestamp
    a_minute = 60
    an_hour = 60 * 60
    a_day = 60 * 60 * 24
    a_week = 60 * 60 * 24 * 7
    a_month = 60 * 60 * 24 * 30
    a_year = 60 * 60 * 24 * 365
    if from_now < an_hour:
        from_now_int = int(from_now / a_minute)
        from_now_str = '{} 分钟前'.format(from_now_int)
    elif from_now < a_day:
        from_now_int = int(from_now / an_hour)
        from_now_str = '{} 小时前'.format(from_now_int)
    elif from_now < a_week:
        from_now_int = int(from_now / a_day)
        from_now_str = '{} 天前'.format(from_now_int)
    elif from_now < a_month:
        from_now_int = int(from_now / a_week)
        from_now_str = '{} 周前'.format(from_now_int)
    elif from_now < a_year:
        from_now_int = int(from_now / a_month)
        from_now_str = '{} 月前'.format(from_now_int)
    else:
        from_now_int = int(from_now / a_year)
        from_now_str = '{} 年前'.format(from_now_int)
    return from_now_str