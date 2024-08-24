from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from lib.core.common import urldecode
from plugins.requestende.encryptfunc import sm2_encrypt, sm2_decrypt, sm3_digest
from datetime import datetime

get_param1 = 'key'


def decrypt_request_handler(req_content):
    req_content_list = list(req_content)
    url = req_content_list[0]
    parsed_url = urlparse(url)
    # 使用parse_qs从查询字符串中解析参数
    query_params = parse_qs(parsed_url.query)
    value = query_params.get(get_param1, [None])[0]
    plain = sm2_decrypt(value)
    query_params[get_param1] = plain
    # 重新构建查询字符串
    # 构建新的查询参数字符串
    new_query_string = urlencode(query_params, doseq=True)
    # new_query_string = "&".join([f"{key}={value}" for key, value in query_params.items()])
    new_url = urlunparse(
        (
            parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query_string,
            parsed_url.fragment)
    )
    print("dec-----------------------:" + new_url)
    req_content_list[0] = new_url
    req_content_tuple = tuple(req_content_list)
    return req_content_tuple


def encrypt_request_handler(url, post, headers):
    parsed_url = urlparse(url)

    # 签名
    now = datetime.now()
    time_stamp = str(int(datetime.timestamp(now) * 1000))
    headers['Timestamp'] = time_stamp
    plain = parsed_url.path + '?' + urldecode(parsed_url.query) + '@' + time_stamp
    headers['Sign'] = sm3_digest(plain)

    # 使用parse_qs从查询字符串中解析参数进行加密
    query_params = parse_qs(parsed_url.query)
    value = query_params.get(get_param1, [None])[0]
    cipher = sm2_encrypt(value)
    query_params[get_param1] = cipher
    # 构建新的查询参数字符串
    new_query_string = urlencode(query_params, doseq=True)
    new_url = urlunparse(
        (
            parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query_string,
            parsed_url.fragment)
    )


    return new_url, post, headers


if __name__ == '__main__':
    # url1 = 'http://localhost:5000/login?key={"username":"admin","password":"pswd001","code":"1154"}&iv=xa$xa'
    # post1 = None
    # headers1 = None
    # url11, post11, headers11 = encrypt_request_handler(url1, post1, headers1)
    tp = ('http://localhost:5000/login?key=secret&iv=administrator', 'POST',
          '{"username":"admin","password":"pswd001","code":"1154"}', None, (
              ('Host', 'localhost:5000'), ('Content-Type', 'application/json'), ('User-Agent', 'PostmanRuntime/7.37.3'),
              ('Accept', '*/*'), ('Postman-Token', '52e74626-8806-4d31-bac5-69d3936e93a7'),
              ('Accept-Encoding', 'gzip, deflate, br')))
    print(decrypt_request_handler(tp))
