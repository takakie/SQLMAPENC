import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from lib.core.common import urldecode
from plugins.requestende.encryptfunc import sm2_encrypt, sm2_decrypt, sm3_digest, sm4_en_enc, sm4_de_enc

# 请求包解密开关
drh_flag = 0
# 请求包get参数加密开关
get_erh_flag = 1
# 请求包post参数加密开关
post_erh_flag = 1
# 请求头变更操纵开关
header_handler_flag = 1

# 加密后缀
ENC = "@@@ENC@@@"
SM4_KEY_ENC = "042a834ad848c5035f2c48ba8a873f9b711cfb41f41a01c28ec92a6839a9e0076e67c90f985a38e44f06889c069378049fb28427f6e7a0ae395173d260d15a6bdbfc0d9249abf494281dad330890f1ff71c560acfff88057c279467930e41aae22b12cbc2f7d4710ce68cd6bb64b9077b78909ec280849e3faf6f33f9093ef290e"
SIGN = ",AAAAAAAAAAAAAAAA89e4cc7cf482a9de96eb290982b8841e6b81113e8fe0448843e421ff42e9f3d9"
POST_KEY = "ENC_PARAM_FLG="
GET_KEY = 'ENC_GET_PARAM_FLG'


def decrypt_request_handler(req_content):
    if not drh_flag:
        return req_content
    req_content_list = list(req_content)
    url = req_content_list[0]
    parsed_url = urlparse(url)
    # 使用parse_qs从查询字符串中解析参数
    query_params = parse_qs(parsed_url.query)
    value = query_params.get(GET_KEY, [None])[0]
    # 解密get参数
    if value is not None:
        value_list = value.split(ENC)
        sm4_key = sm2_decrypt(value_list[1])
        plain = sm4_de_enc(value_list[0], sm4_key)
        index = plain.find('},')
        if index != -1:
            json_str = plain[:index+1]
            json_dict = json.loads(json_str)
            for key, value in json_dict.items():
                if isinstance(value, str):
                    json_dict[key] = value + '*'
            json_str = json.dumps(json_dict)
        else:
            print("jsonStr-------------------error:" + "json_str")
        query_params[GET_KEY] = json_str
        # 重新构建查询字符串
        # 构建新的查询参数字符串
        new_query_string = urlencode(query_params, doseq=True)
        # new_query_string = "&".join([f"{key}={value}" for key, value in query_params.items()])
        new_url = urlunparse(
            (
                parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query_string,
                parsed_url.fragment)
        )
        print("decrypt_url: -----------------------:" + new_url)
        req_content_list[0] = new_url
    # 解密post
    post = req_content_list[2]
    if post:
        post = urldecode(post)
        post_list = post.split(POST_KEY)
        value_list = post_list[1].split(ENC)
        sm4_key = sm2_decrypt(value_list[1])
        plain = sm4_de_enc(value_list[0], sm4_key)
        index = plain.find('},')
        if index != -1:
            json_str_post = plain[:index + 1]
            req_content_list[2] = json_str_post
            print("decrypt_post----------: " + json_str_post)
    return tuple(req_content_list)


def encrypt_request_handler(url, post, headers):
    print("payload request:")
    print(url)
    print(post)
    parsed_url = urlparse(url)
    new_url = url
    # 请求头操纵
    if header_handler_flag:
        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'.encode()
    if get_erh_flag:
        # 使用parse_qs从查询字符串中解析参数进行加密
        query_params = parse_qs(parsed_url.query)
        value = query_params.get(GET_KEY, [None])[0]
        # 加密get参数
        if value is not None:
            cipher = sm4_en_enc(value + SIGN) + ENC + SM4_KEY_ENC
            query_params[GET_KEY] = cipher
            # 构建新的查询参数字符串
            new_query_string = urlencode(query_params, doseq=True)
            new_url = urlunparse(
                (
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query_string,
                    parsed_url.fragment)
            )
    if post_erh_flag:
        post = POST_KEY + sm4_en_enc(post + SIGN) + ENC + SM4_KEY_ENC

    print("encrypt request:")
    print(new_url)
    print(post)
    return new_url, post, headers


if __name__ == '__main__':
    pass
    # url1 = 'http://localhost:5000/login?key={"username":"admin","password":"pswd001","code":"1154"}&iv=xa$xa'
    # post1 = None
    # headers1 = None
    # url11, post11, headers11 = encrypt_request_handler(url1, post1, headers1)

    # tp = ('http://localhost:5000/login?key=secret&iv=administrator', 'POST',
    #       '{"username":"admin","password":"pswd001","code":"1154"}', None, (
    #           ('Host', 'localhost:5000'), ('Content-Type', 'application/json'), ('User-Agent', 'PostmanRuntime/7.37.3'),
    #           ('Accept', '*/*'), ('Postman-Token', '52e74626-8806-4d31-bac5-69d3936e93a7'),
    #           ('Accept-Encoding', 'gzip, deflate, br')))
    # print(decrypt_request_handler(tp))
    # print('{"order":"asc","limit":10,"offset":0},If1amtZOtftH1QT89eedba997263d345854e92f53fbe0b8c5fe3464885166e8b470397e724df4082'[:-81])
