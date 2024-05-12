import requests
import csv
import random  # 导入random模块

# 列出多个API密钥
API_KEYS = [
    '填写自己微步api 最好多几个',
    '',
    '',
    '',
    '',
    '',
    ''
]

# 随机选择一个API密钥
def get_random_api_key():
    return random.choice(API_KEYS)

# 全局变量，API参数
API_URL = 'https://api.threatbook.cn/v3/file/report'
SANDBOX_TYPE = 'win7_sp1_enx86_office2013'

# 调用微步API获取MD5信息函数
def get_md5_info(md5_value):
    api_key = get_random_api_key()  # 随机选择一个API密钥
    params = {
        'apikey': api_key,
        'sandbox_type': SANDBOX_TYPE,
        'md5': md5_value
    }
    list_data = []
    try:
        response = requests.get(API_URL, params=params)
        response_json = response.json()
        print(response_json)

        if response_json['response_code'] == 0:
            # 解析API响应
            data = response_json['data']['summary'] #概括
            multi_engines = "'"+ data['multi_engines']   #检测引擎数
            is_whitelist = data['is_whitelist']     #是否白名单
            malware_type = data['malware_type']     #恶意软件类型
            malware_family = data['malware_family']    #恶意软件家族
            threat_level = data['threat_level']     #告警等级 suspicious(可疑的)    malicious(恶意的)   clean(干净的)
            list_datas = multi_engines, is_whitelist, malware_type, malware_family, threat_level
            list_data.extend(list_datas)

            return list_data
        else:
            return None
    except Exception as e:
        print(f'MD5获取错误：{str(e)}')
        return None

# 读取CSV文件
with open('command_hashes.csv', 'r', encoding="GBK",newline='') as f:
    reader = csv.reader(f)
    rows = list(reader)
# 添加列标题到CSV数据的末尾的单独列中
for row in rows[1:]:  # 跳过第一行，从第二行开始
    md5_value = row[1]  # 获取第三列数据
    if md5_value:
        result = get_md5_info(md5_value)  # 获取MD5信息
        if result is not None:
            row.extend(result)


#
# 更新后的数据保存
with open('command_hashes_update.csv', 'w', newline='', encoding='utf-8-sig') as f:
    writer = csv.writer(f)
    writer.writerow(['文件名','MD5','检测引擎数', '是否白名单', '恶意软件类型', '恶意软件家族','告警等级'])
    for row in rows[1:]:  # 写入处理过的所有行
        writer.writerow(row)
        print(row)

print("CSV文件已成功更新.")
