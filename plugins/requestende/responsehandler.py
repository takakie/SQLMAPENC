# 启用开关
# 响应包解密开关,1开,0关
dr_flag = 0


def decrypt_response(page):
    print("response:")
    print(page)
    if not dr_flag:
        return page
    return page
