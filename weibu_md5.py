# # -*- coding: utf-8 -*-
#
import requests
import csv
#调用微步APi获取MD5信息函数

def get_md5_info(md5_value):
    url = 'https://api.threatbook.cn/v3/file/report'
    params = {
        'apikey': '填写api',
        'sandbox_type': 'win7_sp1_enx86_office2013',
        'md5': md5_value
    }
    try:
        response = requests.get(url,params=params)
        response_json = response.json()
        if response_json['response_code'] == 0:
            return response_json['data']['summary']['multi_engines']
        else:
            return None
    except Exception as e:
        print(f'md5获取错误：{str(e)}')
        return None


#读取csv文件
with open('1.csv','r',encoding='utf-8') as f:
    reader = csv.reader(f)
    rows = list(reader)
#遍历CSV中的每一行
for row in rows:
    md5_value = row[1] #获取第二列数据
    if md5_value:
        result = get_md5_info(md5_value)  #获取MD5信息
        if result is not None:
            row.append(result) #将结果添加到行的末尾

#更新后的数据保存
with open('1_update.csv','w',newline='',encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerows(rows)

print("CSV文件已成功更新。")
