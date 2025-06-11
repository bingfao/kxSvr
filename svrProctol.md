
# 基本规则


wx小程序通过https，调用webSvr接口，查看dev的状态、事件等信息
通过App对设备进行控制操作，由webSvr与svrMgr通信来实现。

# wxApp  <--->  WebSvr

## 用户登录
/usrLogin

httpRequest
  - type          
    - 1 wx小程序
    - 2 独立App 
  - usrOpenid   可选   wx小程序已获取到openid后，优先填入此，
  - usrCode     可选
    - 对wx小程序  是wx登录返回的code , 系统后台数据库记录openid,uuid、phoneNum,这3个字段关联匹配，均可作为用户唯一标识
- timestamp


HttpResponse采用json形式返回
  成功时
  - usrId
  - usrSessionId
  - nickname
  - devList
    - devId
    - devType
    - ownerFlag   所有权说明，1 拥有  2 家人共享  3 朋友临时分享
  - errCode 0
  失败时
  - errCode
    - 0xff  参数错误
    - 10000 对应未完成手机号关联的用户
    - 10001 调用微信服务接口失败
  - errMsg
  - openid  
  - unionid


## 用户注册
/usrRegister

httpRequest
  - type
    - 1 wx小程序
    - 2 独立App
  - usrOpenid
    - 仅对wx小程序，系统此时不需要再次查询用户openid
  - usrUUid
    - 可选，仅对wx小程序
  - mobilePhone   用户手机号，用户输入的
  - authCode      对于调用微信的手机号快速验证组件，提供的code
    - 对wx小程序  是wx小程序点击获取用户手机号返回的code , 系统基于此来查找该用户手机号等信息
  - nickname
  - timestamp

HttpResponse采用json形式返回
  - usrId
  - usrSessionId
  - errCode
    - 0xff    参数错误
    - 10001   调用微信服务接口获取手机号失败 
  - errMsg






**重要说明**
  **仅usrLogin和usrRegister 返回usrSessionId,usrSessionId的有效时长24h,之后需重新login获取**
  **后续其他报文req中，仅包含usrId,但crc部分有usrSessionId参与计算得出，svr基于此校验报文**

## 获取用户可使用的车辆
/getUsrDevs

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App   
  - usrId
  - timestamp
  - hash

HttpResponse采用json形式返回
  成功时
  - devList
    - devId
    - devType
    - ownerFlag   所有权说明，1 拥有  2 家人共享  3 朋友临时分享
    - nickname
    - devPhotoUrl   
  - devStatus
    - position
      - lngPos
      - latPos
    - mileage
    - bdriving
    - speed
    - status
    - bMiniBatExist
    - MiniBatteryid
    - MiniiBatteryStatus
    - batteryExist
    - chargeFlag
    - batteryId
    - batteryStatus 
      - socpercent
      - voltage
      - temp
      - currentflag
      - current
      - seriescount
      - seriesdata  //[]
    - sttime  //string形式的
  - errCode 0
  失败时
  - errCode
    - 0xFF 请求的参数存在错误
  - errMsg



## 绑定车辆
/bindDevWithUsr
   
httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App   
  - usrId
  - devId
  - devType
  - timestamp
  - hash

HttpResponse采用json形式返回
  成功时
    - errCode 0
  失败时
  - errCode
  - errMsg


## 解绑车辆
/unbindDev

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App   
  - usrId
  - devId
  - devType
  - timestamp
  - hash

HttpResponse采用json形式返回
  成功时
    - errCode 0
  失败时
  - errCode
  - errMsg

## 共享车辆给家人
/shareDevWithFamily

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App   
  - usrId
  - devId
  - devType
  - fmPhone           // 字符串
  - shareTracks       // bool
  - shareLtinerary    // bool
  - timestamp
  - hash

HttpResponse采用json形式返回
  成功时
    - errCode 0
  失败时
  - errCode
    - 200 该手机号码需要注册
    - 300 超出最大允许共享人数
  - errMsg


## 取消车辆家人共享
/unshareDevWithFamily

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App   
  - usrId
  - devId
  - devType
  - fmPhone           // 字符串
  - timestamp
  - hash

HttpResponse采用json形式返回
  成功时
    - errCode 0
  失败时
  - errCode
    - 200 该手机号码未注册
  - errMsg

## 临时分享车辆
/tmpShareDevTo

## 取消临时分享
/cancelTmpShare



## 车辆授权情况查询
/devSharedStatus

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App   
  - usrId
  - devId
  - devType
  - timestamp
  - hash

HttpResponse采用json形式返回
  - devOwnerStatus  
    []
    - usrId
    - ownerFlag
  - errCode
  - errMsg


## 设备当前状态查询
/devStatus

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App   
  - usrId
  - devId
  - devType
  - timestamp
  - hash

HttpResponse采用json形式返回
  - devStatus
    - position
      - lngPos
      - latPos
    - mileage
    - bdriving
    - speed
    - status
    - bMiniBatExist
    - MiniBatteryid
    - MiniiBatteryStatus
    - batteryExist
    - chargeFlag
    - batteryId
    - batteryStatus 
      - socpercent
      - voltage
      - temp
      - currentflag
      - current
      - seriescount
      - seriesdata  //[]
    - sttime
  - errCode
  - errMsg


## 设备状态历史查询
/devStatusHistory

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App  
  - usrId 
  - devId
  - devType
  - timeStart
  - timeEnd
  - hash

HttpResponse采用json形式返回
  - devStatusArray
    - TimeStart
    - TimeEnd
    - devStatus
  - errCode
  - errMsg


## 设备位置信息查询
/devPosInfo

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App   
  - usrId
  - devId
  - devType
  - timestamp
  - hash

HttpResponse采用json形式返回
  -devPosInfo
    - cur_lngPos   8Byte   lng位置  float8
    - cur_latPos   8Byte   lat位置  float8   
    - sttime
    - bdriving
    以下字段仅在 bdriving 为1 时存在
    - st_lngPos    8Byte   lng位置  float8  
    - st_latPos    8Byte   lat位置  float8  
    - Points    不包含起始和当前位置的位置点数据
        - lngPos    lng位置  double  8Byte
        - latPos    lat位置  double  8Byte
    - speed
  - errCode
  - errMsg


## 设备事件历史查询
/getDevEvent

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App   
  - usrId
  - devId
  - devType
  - timeStart
  - timeEnd
  - hash

HttpResponse采用json形式返回
  - devEventArray
    - eventTime
    - eventType
    - eventDesc
  - errCode
  - errMsg


## 车辆最近行程查询
/devLtinerary

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App  
  - usrId 
  - devId
  - devType
  - hash

HttpResponse采用json形式返回
  - TimeStart
  - TimeEnd
  - st_lngPos    lng位置  float8  8Byte
  - st_latPos    lat位置  float8  8Byte  
  - end_lngPos   lng位置  float8  8Byte
  - end_latPos   lat位置  float8  8Byte  
  - ltinerary    行程  以10m记  int
  - maxSpeed     最高速度
  - aveSpeed     平均速度
  - maxCurrent   最大供电电流
  - batteryId    电池编号 

  - errCode
  - errMsg


## 车辆历史行程查询
/devLtineraryHistory

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App  
  - usrId 
  - devId
  - devType
  - timeStart
  - timeEnd
  - hash

HttpResponse采用json形式返回
  - LtineraryArray    []
    - TimeStart
    - TimeEnd
    - st_lngPos    lng位置  float8  8Byte
    - st_latPos    lat位置  float8  8Byte  
    - end_lngPos   lng位置  float8  8Byte
    - end_latPos   lat位置  float8  8Byte  
    - ltinerary    行程  以10m记  int
    - maxSpeed     最高速度
    - aveSpeed     平均速度
    - maxCurrent   最大供电电流
    - batteryId    电池编号 
  - errCode
  - errMsg



## 电池状态历史查询


## 电池事件历史查询



## 车辆开锁
/devOpenLock

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App  
  - usrId 
  - devId
  - devType
  **以下3项不参与计算hash**
  - allowTime       允许使用的时长， 以min计
  - lowestSocP      允许使用到的最低电量  0~100
  - farthestDist    允许的最远距离，以m计
  - hash

HttpResponse采用json形式返回
  - errCode
  - errMsg


## 车辆锁定
/lockDev

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App  
  - usrId 
  - devId
  - devType
  **以下项不参与计算hash**
  - voice           关锁音效  number
  - hash

HttpResponse采用json形式返回
  - errCode
  - errMsg

## 防盗锁定
/devGuard

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App  
  - usrId 
  - devId
  - devType
  **以下项不参与计算hash**
  - MotorPowerFlag  电驱控制
  - maxSpeed        限制的最高速度, 以m/s*100
  - warningVoice    报警音效
  - hash

HttpResponse采用json形式返回
  - errCode
  - errMsg


## 打开车辆电控锁
/devOpenElecLock

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App  
  - usrId 
  - devId
  - devType
  **以下项不参与计算hash**
  - lockFlag        
    - 0x02             座桶锁
    - 0x04             手套箱锁
    - 0x08             头盔锁
  - voice              音效  number
  - hash

HttpResponse采用json形式返回
  - errCode
  - errMsg

## 灯光控制
/devLightCtrl

## 声响控制
/devVoiceCtrl


## 文件下发--测试
/devFileDeliver

httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App  
  - usrId 
  - devId
  - devType
  **以下项不参与计算hash**
  - FileType
  - FileName
  - FileUrl
  - hash

HttpResponse采用json形式返回
  - errCode
  - errMsg





## 查找附近可借用的车辆
/searchUseableVechicles
httpRequest
  - type          //type不参与计算hash
    - 1 wx小程序
    - 2 独立App  
  - usrId 
  - devType
  - postion
  - time
  **以下项不参与计算hash**
  - hoursToUse
  - distance
  - PositionScope   //四个点限定的区域
    - topLeft
    - topRight
    - bottomLeft
    - bottomRight
  - hash


HttpResponse采用json形式返回
  - errCode
  - errMsg
  - vehicles  []
    - devId
    - devType
    - devPostion
    - devSOCPercent
    - availableMiles
    - returnTime
    - price



#######################################################################################################################
# WebSvr <--->  svrInstance

此部分报文格式参见devProctol的包头和包体部分
devId 填 0

## 连接验证
- MsgId 9001
- CryptFlag 1    

### 包体部分 
**注意：包体部分是AES之后的数据**
- 加密部分报文           用初始密钥加密  AES-128-CBC, KEY,IV 均用初始值
  - timestamp    8Byte
  - svrHost      
- nDataLen   4Byte    //原始数据的长度      
- crc16      2Byte    //原始数据的crc16    



### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝
**注意：包体部分是AES之后的数据**
- 加密部分报文
  - sessionId    4Byte
  - newIV        16Byte 
  - timestamp    8Byte
- nDataLen   4Byte    //原始数据的长度      
- crc16      2Byte    //原始数据的crc16    

webSvr收到后，后续报文，使用该IV来做AES计算


## 服务器心跳通信包

- MsgId 9002
- CryptFlag 0    

### 包体部分 
  - timestamp    8Byte
  - svrHost      32Byte 当前仅允许  kingxun.site 



### 应答包
- RespCode
    - 0   Ok
- totalDevCount        4Byte   
- svrStartTime         8Byte   svr启动的时间点值  




## 设备控制命令

### 远程开锁
- MsgId  4001
- CryptFlag 1
#### 包体部分 

**注意：包体部分是AES之后的数据**
- 加密部分报文
  - devId           4Byte
  - devtype         1Byte  
  - timestamp       8Byte
  - usrId           4Byte
  - allowTime       2Byte  允许使用的时长， 以min计
  - lowestSocP      1Byte  允许使用到的最低电量  0~100
  - farthestDist    4Byte  允许的最远距离，以m计
- nDataLen  //原始数据的长度
- crc16     //原始数据的crc16

#### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝



### 远程锁定
- MsgId  4002
- CryptFlag 1
#### 包体部分 

**注意：包体部分是AES之后的数据**
- 加密部分报文
  - devId           4Byte
  - devtype         1Byte  
  - timestamp       8Byte
  - usrId           4Byte
  - voice           1Byte  关锁音效
- nDataLen  //原始数据的长度
- crc16     //原始数据的crc16

#### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝



### 远程防盗锁定
- MsgId  4003
- CryptFlag 1
#### 包体部分 

**注意：包体部分是AES之后的数据**
- 加密部分报文
  - devId            4Byte
  - devtype          1Byte  
  - timestamp        8Byte
  - usrId            4Byte
  - MotorPowerFlag   1Byte  
    - 0     关闭电机输出
    - 1     限制功率在100W
    - 2     限制功率输出在200W
    - 0xFF  不限制功率
  - maxSpeed         2Byte  限制的最高速度, 以m/s*100
  - warningVoice     1Byte  报警音效
- nDataLen  //原始数据的长度
- crc16     //原始数据的crc16

#### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝





### 打开车辆电控锁

- MsgId  4004
- CryptFlag 1
#### 包体部分 

**注意：包体部分是AES之后的数据**
- 加密部分报文
  - devId           4Byte
  - devtype         1Byte  
  - timestamp       8Byte
  - usrId           4Byte
  - lockFlag        1Byte   
    - 0x02             座桶锁
    - 0x04             手套箱锁
    - 0x08             头盔锁
  - warningVoice     1Byte  报警音效
- nDataLen  //原始数据的长度
- crc16     //原始数据的crc16

#### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝



### 灯光控制

- MsgId  4005
- CryptFlag 1
#### 包体部分 
**注意：包体部分是AES之后的数据**
- 加密部分报文
  - devId           4Byte
  - devtype         1Byte  
  - timestamp       8Byte
  - usrId           4Byte
  - lightFlag       2Byte  
    - 0x01     照明大灯 
    - 0x04     照明远光灯
    - 0x10     示廓灯    
    - 0x40     开启左转向灯  
    - 0x80     开启右转向灯 
    - 0x0100   双闪灯    
    - 0x0400   刹车灯    
- nDataLen  //原始数据的长度
- crc16     //原始数据的crc16

#### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝

### 声响控制

### 自定义提示音

### 自定义灯光

### 开启整车测试

车辆在接收到该命令后，开启测试模式，按规定顺序逐一控制各部件，并反馈每次控制的状态情况

此命令仅为检测使用，不开放给App日常操作


### 下发文件

此对应服务端控制台，文件已copy到svr端，有url路径可访问到

- MsgId 4020
- CryptFlag 0
#### 包体部分 
- devId           4Byte
- devtype         1Byte  
- timestamp       8Byte
- sysUsrId        4Byte
- FileType        1Byte 
  - 1                  固件版本等系统文件
  - 2                  媒体文件
- FileName        32Byte  char utf-8  || 需要对文件名的规则进行约定，以实现固件OTA升级以及媒体文件等更新下发
  - "bms"              对应BMS固件
  - "motorcontrol"     对应电机控制器
  - "maincontrol"      对应主控
  - "dashboard"        对应仪表盘
  - "weather.mp3"      对应天气提示
- FileDataLen     4Byte
- FileMD5         16Byte
- FileData        NBytes         

#### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝
    - 0xFF  发生错误


### 设置SVR记录socket报文日志

此对应服务端控制台，设置通信报文日志记录标识

- MsgId 4040
- CryptFlag 0
#### 包体部分 
- devId           4Byte
- devtype         1Byte  
- timestamp       8Byte
- sysUsrId        4Byte
- logSendFlag     1Byte
  - 1 打开日志记录
  - 0 关闭日志记录
- logRecvFlag     1Byte
  - 1 打开日志记录
  - 0 关闭日志记录
        

#### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝
    - 0xFF  发生错误


### 设置dev日志记录level

此对应服务端控制台，设置通信报文日志记录标识

- MsgId 4041
- CryptFlag 0
#### 包体部分 
- devId           4Byte
- devtype         1Byte  
- timestamp       8Byte
- sysUsrId        4Byte
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
        

#### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝
    - 0xFF  发生错误




