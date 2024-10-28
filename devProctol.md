
# 基本规则

分为请求包和应答包报文
设备端可以发起请求包报文,并接收服务端应答.
服务端可以发起请求报文,设备端进行应答.
对于部分报文类型，采用AES-128对报文包体数据进行加密处理,AES加密的报文数据如需填充，以00填充，根据设备Id对应的密钥。
服务端存储有所有设备的当前有效密钥，并提供机制对设备进行密钥更换。


# 报文包格式简介

**报文中各字段取值均同一采用Intel字节序**

## 请求包

### 包头
- MsgId         2Byte
- TypeFlag      1Byte
- SeqNum        2Byte
- MsgBodyLen    4Byte
- CryptFlag     1Byte
- Reserved      3Byte
- Crc16         2Byte
- DevId         4Byte
- SessionId     4Byte

### 包体
由包头中MsgBodyLen指定的报文长度，具体含义根据报文MsgId进行单独说明
CryptFlag 如为1，则包体内容是做过AES ECB处理的

## 应答包

### 包头
- MsgId         2Byte
- TypeFlag      1Byte
- SeqNum        2Byte
- MsgBodyLen    4Byte
- CryptFlag     1Byte
- Reserved      3Byte
- Crc16         2Byte
- RespCode      4Byte
### 包体
由包头中MsgBodyLen指定的报文长度，具体含义根据报文MsgId进行单独说明
CryptFlag 如为1，则包体内容是做过AES ECB处理的

**应答包必须与请求包的SeqNum一致**


...
unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
unsigned int plainLen = 16 * sizeof(unsigned char);  //bytes in plaintext

AES aes(AESKeyLength::AES_128);  ////128 - key length, can be 128, 192 or 256
c = aes.EncryptECB(plain, plainLen, key);
//now variable c contains plainLen bytes - ciphertext
...

# 具体报文说明

## --------------   dev -> svr 

## 设备注册
tcp长连接情况下设备上电重启等条件下，设备连接服务端，发送的首条报文
tcp短连接情况下设备连接服务端，发送的首条报文
- MsgId  1001
### 包体部分
- Devtime  localtime
    - year         2Byte
    - month        1Byte
    - day          1Byte
    - hour         1Byte
    - min          1Byte
    - second       1Byte
- DevHwVersion      4Byte
- DevSoftVersion    4Byte
- motorCtrlHWVer    4Byte
- motorCtrlSoftVer  4Byte
- dashboardHWVer    4Byte
- dashboardSoftVer  4Byte

### 应答包
服务端根据具体情况回复，
RespCode 
    - 0  正常
            应答报文体
            - SessinId   4Byte 设备需在后续请求报文中按此填入
    - 1  重定向其他服务端口
            应答报文体
            - svrIplen   1Byte 设备需重连的服务端Ip的字符串（以'\0'结束）长度
            - svrIp      nByte utf-8编码
            - svrPort    2Byte
    - 2  拒绝
    - 其他值  暂未定义的错误



## 设备状态
- MsgId  1002
包体部分
- DevType  设备类型 1Byte
    - 1   国标电动自行车
    - 2   E-Motor

    - 4   电动三轮
    - 6   电动四轮

    - 8   换电柜
    - 9   充电柜

以下针对E-bike和E-Motor

- ProtocolFlag  应对后续协议升级用的标识
    - 1   目前对应的版本
- lngPos    lng位置  double  8Byte
- latPos    lat位置  double  8Byte
- mileage   行驶总里程  U32  以10m 为单位,四舍五入
- bDriving  行驶状态  bool   1Byte
- speed     行驶速度  U16    速度 整数 mm/s
- status    工作状态  6Byte
    - lockStuats    1Byte  bit0 电气锁  bit1 座桶锁 bit2 手套箱锁 bit3 头盔锁 bit4 电驱锁  bit取值1 为锁打开
    - lightStatus   2Byte  灯光状态
        - bit0~1   照明大灯  0b01 开启 0b00 关闭  0b11 故障
        - bit2~3   示廓灯    0b01 开启 0b00 关闭  0b11 故障
        - bit4~5   转向灯    0b01 开启左转向灯  0b10 开启右转向灯 0b00 关闭  0b11 故障
        - bit6~7   双闪灯    0b01 开启 0b00 关闭  0b11 故障
        - bit8~9   刹车灯    0b01 开启 0b00 关闭  0b11 故障
    - sensorStatus  1Byte  传感器状态  
        - bit0 座位传感器  
        - bit1 脚撑传感器 
        - bit2 儿童座位传感器
        - bit4 车辆倾倒状态
    - brakeStatus   1Byte  刹车系统状态
        - bit0 后轮刹车
        - bit1 前轮刹车
        - bit4 ABS工作
        - bit5 TCS工作
    - reserved      1Byte
- miniBatteryExist  1Byte  当小电池不存在时，后续字段无效
- miniBatteryId     30Byte  字符串
- miniiBatteryStatus  中控小电池状态
    - socPercent    1Byte           u8   0~100
    - voltage       2Byte           u16  电压值*100
    - temp          2Byte           i16  温度值*100
- batteryExist      1Byte          
    - 1 存在        
    - 0 不存在, 当动力电池不存在时，后续字段无效
- chargeFlag        1Byte  是否在充电过程中  1 充电 0 非充电
- batteryId         32Byte           动力电池编号 string
- batteryStatus     动力电池状态
    - socPercent    1Byte           u8   0~100   
    - voltage       2Byte           u16  电压值*100
    - temp          2Byte           i16  温度值*100
    - chargeCycle   2Byte           u16  充放电循环次数
    - soH           1Byte           u8   0~100
    - currentFlag   1Byte           U8   1  放电  2 充电
    - current       2Byte           u16  电流值*100
    - seriesCount       1Byte           u8   多少串
    - seriesData        4 * s_count Byte   每串的数据
        - voltage       2Byte           u16  每串电压值*100  
        - temp          2Byte           i16  每串温度值*100, 如无温度传感器，填0xFFFF  

设备位置未发生明显变化（距离<1m）时，每5min上传一次设备状态信息
当设备位置发生明显变化时，每1min(待实测评估)上传一次设备状态信息


## 车辆行程  
在每次行程结束时，车辆发送该报文到svr，行程由车辆计算得出，单位m
- MsgId  1008
- CryptFlag 1
### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- st_time localtim
    - year         2Byte
    - month        1Byte
    - day          1Byte
    - hour         1Byte
    - min          1Byte
    - second       1Byte   //以上数据在数据库中存为8字节 timestamp
- st_lngPos    lng位置  float8  8Byte
- st_latPos    lat位置  float8  8Byte  
- end_time     localtime
    - year         2Byte
    - month        1Byte
    - day          1Byte
    - hour         1Byte
    - min          1Byte
    - second       1Byte   //以上数据在数据库中存为8字节 timestamp
- end_lngPos   lng位置  float8  8Byte
- end_latPos   lat位置  float8  8Byte  
- ltinerary    行程  以10m记  int
- maxSpeed     最高速度
- aveSpeed     平均速度
- maxCurrent   最大供电电流



### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 车辆充电完成  
在每次充电结束时，车辆发送该报文到svr，为过滤因充电器接触不良，每次充电时长需大于30min，以30min内soc不再增长作为结束或者以电池反馈已充电完成作为结束
- MsgId  1010
- CryptFlag 1
### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- st_time localtim
    - year         2Byte
    - month        1Byte
    - day          1Byte
    - hour         1Byte
    - min          1Byte
    - second       1Byte   //以上数据在数据库中存为8字节 timestamp
- lngPos    lng位置  float8  8Byte
- latPos    lat位置  float8  8Byte  
- end_time     localtime
    - year         2Byte
    - month        1Byte
    - day          1Byte
    - hour         1Byte
    - min          1Byte
    - second       1Byte   //以上数据在数据库中存为8字节 timestamp
- maxCurrent   最大充电电流
- socBegin     开始时的SOC
- socEnd       结束时的SOC
- volBegin     开始时的电压
- volEnd       结束时的电压



### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 设备事件上报
- MsgId  1010
- CryptFlag 1
### 包体部分
**注意：包体部分是AES之后的数据，需解密后处理**
- eventCount  事件数量
- evTime localtime
    - year         2Byte
    - month        1Byte
    - day          1Byte
    - hour         1Byte
    - min          1Byte
    - second       1Byte   //以上数据在数据库中存为8字节 timestamp
    - microsecond  2Byte   //另外字段存储，便于查找比较
- eventType        1Byte
    - 1      用户使用Key开锁
    - 2      网络开锁
    - 3      自动锁车
    - 4      用户锁车
    - 5      在车充电
    - 6      车辆电池被取出
    - 7      车辆电池被放入
    - 8      车辆倾倒
    - 9      车辆未解锁被移动



## --------------   svr -> dev

## 授权开锁  
- MsgId  2001
- CryptFlag 1
### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- svrtime         8Byte timestamp  localtime 
- devSessionId    4Byte
- allowTime       2Byte  允许使用的时长， 以min计
- lowestSocP      1Byte  允许使用到的最低电量  0~100
- farthestDist    4Byte  允许的最远距离，以m计
### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 授权解锁设备 
- MsgId  2002
- CryptFlag 1
### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- svrtime         8Byte timestamp  localtime  
- devSessionId    4Byte
- KeyType         1Byte  解锁设备类型
    - 1   蓝牙
    - 2   UWB
    - 3   NFC
- KeyIdLen        1Byte  解锁设备Id长度
- KeyId           nByte  解锁设备的Id
### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 禁用某一解锁设备
- MsgId  2003
- CryptFlag 1
### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- svrtime         8Byte timestamp  localtime 
- devSessionId    4Byte
- KeyType         1Byte  解锁设备类型
    - 1   蓝牙
    - 2   UWB
    - 3   NFC
- KeyIdLen        1Byte  解锁设备Id长度
- KeyId           nByte  解锁设备的Id
### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 网络锁车
- MsgId  2009
- CryptFlag 1
### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- svrtime         8Byte timestamp  localtime 
- devSessionId    4Byte
- voice           1Byte  关锁音效
### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 限制使用
- MsgId  2010
- CryptFlag 1
### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- svrtime         8Byte timestamp  localtime 
- devSessionId    4Byte
- shutdownMotor   1Byte  是否关闭电驱
- maxSpeed        2Byte  限制的最高速度, 以m/s*100
- warningVoice    1Byte  报警音效
### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 文件下发
- MsgId  2020
- CryptFlag 1
### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- svrtime         8Byte timestamp  localtime 
- devSessionId    4Byte
- FileType        1Byte 
- FileName        32Byte  char utf-8 
- FileLen         4Byte  
- FileMD5         16Byte
- FileData        
### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


