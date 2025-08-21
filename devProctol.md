
# 基本规则

分为请求包和应答包报文
设备端可以发起请求包报文,并接收服务端应答.
服务端可以发起请求报文,设备端进行应答.
对于部分报文类型，采用AES-128-CBC 对报文包体数据进行加密处理,AES加密的报文数据如需填充，根据设备Id对应的密钥。
服务端存储有所有设备的当前有效密钥，并提供机制对设备进行密钥更换。

MCU的序列号 12Byte ，由生产工具叠加时间戳信息4Byte，然后AES 出16字节的对应该MCU的密钥Key：16Byte，
由生产工具写入MCU或者PCBA的某个存储区域，服务器保存有所有MCU的序列号和Key信息，后续服务端下发的加密报文，利用该MCU的Key来做AES加密，
MCU收到后利用自己的key来解密获得原始报文体数据，报文体包含基于原始数据的报文长度和CRC，解密后验证不匹配的报文丢弃

svrMgr 对应管理不同的svrInstance
svrInstance 对应处理一定范围Id的device
dev出厂时设定的svrIp/Port，如后台规则调整，DevReg应答时返回dev应该连接的ip/port

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
由包头中MsgBodyLen指定的报文长度，具体含义根据报文MsgId进行单独说明，针对加密的数据报文，MsgBodyLen是加密后的报文数据长度
CryptFlag 如为1，则包体内容是做过AES 处理的

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
CryptFlag 如为1，则包体内容是做过AES 处理的，

**应答包必须与请求包的SeqNum一致**




# 具体报文说明

# --------------   dev -----> svrInstace 

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
- RespCode 
    - 0  正常
            
            应答报文体
    - 1  重定向其他服务端口   暂时不实现
            应答报文体
            - svrIplen   1Byte 设备需重连的服务端Ip的字符串（以'\0'结束）长度
            - svrIp      nByte utf-8编码
            - svrPort    2Byte 
    - 2  拒绝
    - 其他值  暂未定义的错误
包体部分
respcode为0时： 
- SessinId   4Byte     设备需在后续请求报文中按此填入
- IV         16Byte    AES用的IV向量



## 设备状态
- MsgId  1002

**车辆电气锁开关状态变化以及车辆充电状态变化时，即刻上传新的状态**

设备位置未发生明显变化（距离<1m）时，每5min上传一次设备状态信息
当设备位置发生明显变化时，每1min(待实测评估)上传一次设备状态信息

### 包体部分
- DevType  设备类型 1Byte
    - 1   国标电动自行车
    - 2   E-Motor

    - 4   电动三轮
    - 6   电动四轮

    - 8   换电柜
    - 9   充电柜

以下针对E-bike和E-Motor

- ProtocolFlag  应对后续协议升级用的标识   1Byte
    - 1   目前对应的版本
- lngPos    lng位置  double  8Byte
- latPos    lat位置  double  8Byte
- mileage   行驶总里程  U32  以10m 为单位,四舍五入
- bDriving  行驶状态  bool   1Byte
- speed     行驶速度  U16    速度 整数 mm/s
- status    工作状态  6Byte
    - lockStuats    1Byte  bit0 电气锁  bit1 座桶锁 bit2 手套箱锁 bit3 头盔锁 bit4 电驱锁  bit取值1 为锁打开
    - lightStatus   2Byte  灯光状态
        - bit0~1     照明大灯    0b01 开启 0b00 关闭  0b11 故障
        - bit2~3     照明远光灯  0b01 开启 0b00 关闭  0b11 故障
        - bit4~5     示廓灯      0b01 开启 0b00 关闭  0b11 故障
        - bit6~7     转向灯      0b01 开启左转向灯  0b10 开启右转向灯 0b00 关闭  0b11 故障
        - bit8~9     双闪灯      0b01 开启 0b00 关闭  0b11 故障
        - bit10~11   刹车灯      0b01 开启 0b00 关闭  0b11 故障
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



### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 设备流量上报      
- MsgId  1004
- CryptFlag 0

设备每8h向Svr上报当月已使用流量数据


### 包体部分
- DevType              1Byte   设备类型
- ProtocolFlag         1Byte   应对后续协议升级用的标识
    - 1   目前对应的版本
- usedTraffic          4Byte   以 K Byte为单位，当月的流量，每个月从0开始，

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝



## 设备查询电池续航能力
- MsgId  1005
- CryptFlag 0

设备向Svr查询电池的当前续航能力
因不同电池不同阶段SOC值对应的续航里程会变化，故设备在电池新插入后、充电完成、或者每日定时向Svr查询
设备在仪表上显示的可续航里程，可基于从svr获取的值来做计算预估，（根据上次获取的可续航里程，按当前soc-socMinVal平均计算）


### 包体部分
- DevType              1Byte           设备类型
- batteryId            32Byte          动力电池编号 string
- socPercent           1Byte           u8   0~100   
- voltage              2Byte           u16  电压值*100

### 应答包
- RespCode
    - 0   Ok
    - 1   发生错误
- maxRange             4Byte    U32  以m为单位
- chargeNotifySoc      1Byte    u8   0~100
- socMinVal            1Byte    u8   0~100， 已无法驱动车辆的soc下限值，此值仅用作预估计算用，设备不根据此值来判断是否停止驱动行驶  



## 车辆行程  
在每次行程结束时，车辆发送该报文到svr，行程由车辆计算得出，单位m
- MsgId  1008
- CryptFlag 1

### 包体部分 

**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- 加密部分报文
    - st_time      localtim
        - year         2Byte
        - month        1Byte
        - day          1Byte
        - hour         1Byte
        - min          1Byte
        - second       1Byte   //以上数据在数据库中存为8字节 timestamp
    - st_lngPos    8Byte   lng位置  float8  
    - st_latPos    8Byte   lat位置  float8   
    - end_time     localtime
        - year         2Byte
        - month        1Byte
        - day          1Byte
        - hour         1Byte
        - min          1Byte
        - second       1Byte   //以上数据在数据库中存为8字节 timestamp
    - end_lngPos    8Byte   lng位置  float8 
    - end_latPos    8Byte   lat位置  float8  8Byte  
    - ltinerary     4Byte    行程      U32 以m计
    - socBegin      1Byte    开始时的SOC
    - socEnd        1Byte    结束时的SOC
    - maxSpeed      2Byte    最高速度   整数 mm/s 
    - aveSpeed      2Byte    平均速度   整数 mm/s 
    - maxCurrent    2Byte    最大供电电流     u16  电流值*100
    - batteryId     32Byte   动力电池编号 string          //如更换电池，上一行程结束，新行程重新开始
    - nPointCount   4Byte   GPS坐标点数量
    - Points    不包含起始和结束位置的位置点数据
        - lngPos    lng位置  double  8Byte
        - latPos    lat位置  double  8Byte
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16



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
- 加密部分报文
    - st_time localtime
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
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16



### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 设备事件上报
- MsgId  1012
- CryptFlag 1
### 包体部分
**注意：包体部分是AES之后的数据，需解密后处理**
- 加密部分报文
    - eventCount  事件数量
    - events     []
        - evTime localtime
            - year         2Byte
            - month        1Byte
            - day          1Byte
            - hour         1Byte
            - min          1Byte
            - second       1Byte   //以上数据在数据库中存为8字节 timestamp
            - microsecond  2Byte   //另外字段存储，便于查找比较
        - eventType        1Byte
            - 1      用户手机蓝牙靠近自动开锁
            - 2      用户网络开锁
            - 3      自动锁车
            - 4      用户网络锁车
            - 5      在车充电
            - 6      车辆电池被取出
            - 7      车辆电池被放入
            - 8      车辆倾倒
            - 9      车辆未解锁被移动
            - 10     车辆骑行过程中倾倒
            - 11     用户使用车辆钥匙开锁
            - 12     用户使用车辆钥匙锁车
            - 13     用户开始骑行
        - eventData 
            - usrId   4Byte    //未有用户开锁状态下，全填0
            - speed     行驶速度  U16    速度 整数 mm/s
        - lngPos    lng位置  float8  8Byte
        - latPos    lat位置  float8  8Byte  
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16




## 设备接收文件完成  
在每次接收文件2020/2021，或者设备通过1022接收文件，全部完成后，设备发送该报文到svr
- MsgId  1020
- CryptFlag 0
### 包体部分 
- Devtime  localtime
    - year         2Byte
    - month        1Byte
    - day          1Byte
    - hour         1Byte
    - min          1Byte
    - second       1Byte   timestamp
- devtype         1Byte
- recvFlag        1Byte
    - 0       2020/2021接收文件
    - 1       1022接收文件
- FileType        1Byte 
    - 1                 固件版本等系统文件
    - 2                 媒体文件
- FileName        32Byte  char utf-8  || 需要对文件名的规则进行约定，以实现固件OTA升级以及媒体文件等更新下发
    - "bms"            对应BMS固件
    - "motorcontrol"    对应电机控制器
    - "maincontrol"     对应主控
    - "dashboard"       对应仪表盘
    - "weather.mp3"     对应天气提示
- FileLen         4Byte  
- FileMD5         16Byte

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 文件更新下载
- MsgId  1022
- CryptFlag 0

### 包体部分 
- DevType         1Byte 设备类型 
- FileType        1Byte 
    - 1                 固件版本等系统文件
    - 2                 媒体文件
- FileName        32Byte  char utf-8  || 需要对文件名的规则进行约定，以实现固件OTA升级以及媒体文件等更新下发
    - "bms"            对应BMS固件
    - "motorcontrol"    对应电机控制器
    - "maincontrol"     对应主控
    - "dashboard"       对应仪表盘
    - "weather.mp3"     对应天气提示
- FileURL_KEY     16Byte  
- FileDataPos     4Byte   请求文件数据的起始位置
- nDataLen        2Byte   数据的长度  每包支持最大64k,由设备端指定  


### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝   
- FileDataPos     4Byte   本包数据在文件数据的起始位置
- nDataLen        2Byte   数据的长度  每包不超过20k 
- FileHData          
- crc16           2Byte    包体部分从FileDataPos到FileData的crc16


# --------------   svrInstance -----> dev

## 授权开锁  
- MsgId  2001
- CryptFlag 1

### 包体部分 

**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- 加密部分报文
    - svrtime         8Byte timestamp  localtime 
    - devSessionId    4Byte
    - usrId           4Byte  开锁用户id
    - allowTime       2Byte  允许使用的时长， 以min计
    - lowestSocP      1Byte  允许使用到的最低电量  0~100
    - farthestDist    4Byte  允许的最远距离，以m计
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝



## 网络锁车
- MsgId  2002
- CryptFlag 1

### 包体部分 

**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- 加密部分报文
    - svrtime         8Byte timestamp  localtime 
    - devSessionId    4Byte
    - voice           1Byte  关锁音效
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 限制使用
- MsgId  2003
- CryptFlag 1

### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- 加密部分报文
    - svrtime          8Byte timestamp  localtime 
    - devSessionId     4Byte
    - MotorPowerFlag   1Byte  
        - 0     关闭电机输出
        - 1     限制功率在100W
        - 2     限制功率输出在200W
        - 0xFF  不限制功率
    - maxSpeed         2Byte  限制的最高速度, 以m/s*100
    - warningVoice     1Byte  报警音效
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 打开车辆电控锁

- MsgId  2004
- CryptFlag 1
### 包体部分 

**注意：包体部分是AES之后的数据**
- 加密部分报文
    - svrtime          8Byte timestamp  localtime 
    - devSessionId     4Byte
    - lockFlag         1Byte   
        - 0x02             座桶锁
        - 0x04             手套箱锁
        - 0x08             头盔锁
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝

## 灯光控制

- MsgId  2005
- CryptFlag 1
### 包体部分 

**注意：包体部分是AES之后的数据**
- 加密部分报文
    - svrtime          8Byte timestamp  localtime 
    - devSessionId     4Byte
    - lightFlag        1Byte  
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝



## 文件头部数据下发
- MsgId  2020
- CryptFlag 1

### 包体部分 

**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- 加密部分报文
    - svrtime         8Byte timestamp  localtime 
    - devSessionId    4Byte
    - FileType        1Byte 
        - 1                 固件版本等系统文件
        - 2                 媒体文件, **对2020下发的媒体文件，设备端接收成功完毕后即进行播放**
    - FileName        32Byte  char utf-8  || 需要对文件名的规则进行约定，以实现固件OTA升级以及媒体文件等更新下发
        - "bms"            对应BMS固件
        - "motorcontrol"    对应电机控制器
        - "maincontrol"     对应主控
        - "dashboard"       对应仪表盘
        - "weather.mp3"     对应天气提示
    - FileLen         4Byte  
    - FileMD5         16Byte
    - FileHeadData    小于4k的数据，当文件数据大于4k时，仅填入4k长度数据，剩余数据由2021报文依次下发    
- nDataLen     4Byte  //原始数据的长度
- crc16        2Byte  //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝   //当MCU存储空间不足等情况，回复拒绝


## 文件数据下发
- MsgId  2021
- CryptFlag 0

**设备接收到全部文件数据后，校验md5, 完成本次文件数据下发**

### 包体部分 
- devSessionId    4Byte
- FileType        1Byte 
- FileName        32Byte  char utf-8 
- FileDataPos     4Byte   本包数据在文件数据的起始位置
- nDataLen        2Byte   数据的长度  每包不超过20k 
- FileData          
- crc16           2Byte    包体部分从FileDataPos到FileData的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 文件更新下载通知
- MsgId  2022
- CryptFlag 1

### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- 加密部分报文
    - svrtime         8Byte timestamp  localtime 
    - devSessionId    4Byte
    - FileType        1Byte 
        - 1                 固件版本等系统文件
        - 2                 媒体文件
    - FileName        32Byte  char utf-8  || 需要对文件名的规则进行约定，以实现固件OTA升级以及媒体文件等更新下发
        - "bms"            对应BMS固件
        - "motorcontrol"    对应电机控制器
        - "maincontrol"     对应主控
        - "dashboard"       对应仪表盘
        - "weather.mp3"     对应天气提示
    - FileLen         4Byte  
    - FileMD5         16Byte
    - FileURL_KEY     16Byte    
- nDataLen     4Byte  //原始数据的长度
- crc16        2Byte  //原始数据的crc16


### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝   //当MCU存储空间不足等情况，回复拒绝



## 授权解锁设备

**这里再思考一下**
钥匙类型：
1. 车辆出厂 配对好的1把蓝牙钥匙
2. 用户实名手机号对应绑定的蓝牙
3. 智能头盔配置里的蓝牙
4. 家人通过用户家庭共享的实名手机对应绑定的蓝牙

- MsgId  2031
- CryptFlag 1

### 包体部分 

**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- 加密部分报文
    - svrtime         8Byte timestamp  localtime  
    - devSessionId    4Byte
    - KeyType         1Byte  解锁设备类型
        - 1   NFC      //暂时可能只支持NFC一种，蓝牙等无法通过该方法??
    - KeyIdLen        1Byte  解锁设备Id长度
    - KeyId           nByte  解锁设备的Id
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 禁用某一解锁设备
- MsgId  2032
- CryptFlag 1

### 包体部分 

**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- 加密部分报文
    - svrtime         8Byte timestamp  localtime 
    - devSessionId    4Byte
    - KeyType         1Byte  解锁设备类型
        - 1   NFC
        - 2   BLE
    - KeyIdLen        1Byte  解锁设备Id长度
    - KeyId           nByte  解锁设备的Id
- nDataLen  4Byte    //原始数据的长度
- crc16     2Byte    //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 设置dev日志记录level

此对应服务端控制台，设置通信报文日志记录标识

- MsgId 2041
- CryptFlag 0
### 包体部分 
- devSessionId    4Byte
- logSendFlag     1Byte
  - 1 打开日志记录
  - 0 关闭日志记录
- logRecvFlag     1Byte
  - 1 打开日志记录
  - 0 关闭日志记录
- logLevel        1Byte
  - bit0  error
  - bit1  waring
  - bit2  info
  - bit3  debug
        

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝
    - 0xFF  发生错误

