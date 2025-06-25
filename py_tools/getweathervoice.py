import requests
import time
# import http.cookiejar
# import json
import sys


from selenium import webdriver
from selenium.webdriver.common.by import By 

forecast_str = '预计，'

def get_text_speech(weather_text,city_code="shanghai"):
    seeeion = requests.session()
    vioce_resp = seeeion.post(
            "https://www.text-to-speech.cn/getSpeek.php",
            data={
                "language":"中文（普通话，简体）",
                "voice":"zh-CN-XiaoxiaoNeural",
                "text": weather_text,
                "role": 0,
                "style": "customerservice",
                "rate": 45,
                "pitch":0,
                "kbitrate": "audio-16khz-32kbitrate-mono-mp3",
                "silence":"",
                "styledegree":1,
                "volume":75,
                "predict":0,
                "user_id":"",
                "yzm":"202410170001",
                "replice":1,
                "token": "045c570669d8b3f739feb6ea191ab4f1",
                "toke2":"045c570669d8b3f739feb6ea191ab4f1"
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Origin": "https://www.text-to-speech.cn",
                "Referer": "https://www.text-to-speech.cn/",
            },
        )
    if vioce_resp.status_code == 200:
        vioce_data = vioce_resp.json()
        print(vioce_data)
        if vioce_data.get("code") == 200:
            wav_url = vioce_data.get("download")
            wav_response = seeeion.get(wav_url)
            if wav_response.status_code == 200:
                mday= time.strftime("%m-%d", time.localtime())
                filename = f"weather_{city_code}_{mday}.mp3"
                with open(filename, "wb") as f:
                    f.write(wav_response.content)
                print(f"Audio file saved as {filename}")
            else:
                print("Failed to download audio file.")
        else:
            print("Error in response:", vioce_data.get("msg"))
    else:
        print("Failed to get voice data.")
    pass

# 101010100 北京
# 101190101 南京
# 101020100 上海
# 101210101 杭州
# 101180101 郑州
# 101180601 信阳

city_code_dict = {
    "beijing": "101010100",
    "nanjing": "101190101",
    "shanghai": "101020100",
    "hangzhou": "101210101",
    "zhengzhou": "101180101",
    "xinyang": "101180601"
}

def get_weather_text(city_code="shanghai"):
    # 创建Chrome浏览器对象
    driver = webdriver.Chrome()
    city_id = city_code_dict.get(city_code.lower(), "101020100")  # 默认上海
    driver.get(f"https://e.weather.com.cn/e_index/sudutianqi.html?aid={city_id}")

    driver.implicitly_wait(5)

    element = driver.find_element(By.CLASS_NAME, "contentDiv")
    # print(element.text)
    content_str = element.text
    forecast_str_index = content_str.find(forecast_str)+len(forecast_str)
    forecast_str_index_end = content_str.find('\n', forecast_str_index)
    if forecast_str_index != -1:
        if forecast_str_index_end != -1:
            content_str = content_str[forecast_str_index:forecast_str_index_end]
        else:
            content_str = content_str[forecast_str_index:]
        pass
        print(content_str)
        get_text_speech(content_str,city_code)
    pass
    driver.quit()

# seeeion = requests.session()
# # response = seeeion.get("https://www.text-to-speech.cn//")

# content_div_str = '<div class="contentDiv">'

# # https://e.weather.com.cn/e_index/sudutianqi.html?aid=101020100
# w_resp = requests.get('https://e.weather.com.cn/mweather/101020100.shtml',headers={'User-Agent': 'Mozilla/5.0'})

# if(w_resp.status_code == 200):
#     w_resp.render(timeout=10)
#     w_resp.encoding = 'utf-8'
#     with open("resp.html", "wb") as f:
#         f.write(w_resp.content)
#     w_resp_text = w_resp.text
#     start_index = w_resp_text.find(content_div_str) + len(content_div_str)
#     end_index = w_resp_text.find('</div>', start_index)
#     if start_index != -1 and end_index != -1:
#         content_str = w_resp_text[start_index:end_index]
#         forecast_str_index = content_str.find(forecast_str)+len(forecast_str)
#         forecast_str_index_end = content_str.find('</p>', forecast_str_index)
#         if forecast_str_index != -1:
#             if forecast_str_index_end != -1:
#                 content_str = content_str[forecast_str_index:forecast_str_index_end]
#             else:
#                 content_str = content_str[forecast_str_index:]
#             pass
#             print(content_str)
#         pass
#     pass

# if response.status_code == 200:
    # print(response.text)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        city_code = sys.argv[1].lower()
        get_weather_text(city_code)
    else:
        print("Usage: python getweathervoice.py <city_code>")
        print("Available city codes: beijing, nanjing, shanghai, hangzhou, zhengzhou, xinyang")
        # 默认获取上海天气
    # get_weather_text('shanghai')
#    get_text_speech('天白天小雨，最高气温32.5℃，南风3-4级，今天夜间小雨，最低气温25.4℃，微风。')
