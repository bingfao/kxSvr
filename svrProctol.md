
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
  - usrCode   
    - 对wx小程序  是wx登录返回的code , 系统后台数据库记录openid,uuid、phoneNum,这3个字段关联匹配，均可作为用户唯一标识
  - timestamp

HttpResponse采用json形式返回
  成功时
  - usrId
  - usrSessionId
  - devList
    - devId
    - devType
    - ownerFlag   所有权说明，1 拥有  2 家人共享  3 朋友临时分享
  - errCode 0
  失败时
  - errCode
    - 0xff  对应未完成手机号关联的用户
    - 10001 调用微信服务接口失败
  - errMsg
  - openid  
  - unionid


## 获取用户手机号注册
/usrRegister

httpRequest
  - type
    - 1 wx小程序
    - 2 独立App
  - usrCode
    - 对wx小程序  是wx登录返回的code,系统基于此查询用户的openid
  - usrOpenid
    - 仅对wx小程序，系统此时不需要再次查询用户openid
  - usrUUid
    - 可选，仅对wx小程序
  - authCode   
    - 对wx小程序  是wx小程序点击获取用户手机号返回的code , 系统基于此来查找该用户手机号等信息
  - timestamp

HttpResponse采用json形式返回
  - usrId
  - usrSessionId
  - errCode
    - 0xff  对应未完成手机号关联的用户
  - errMsg


**重要说明**
  **仅usrLogin和usrRegister返回usrSessionId,usrSessionId的有效时长24h,之后需重新login获取**
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






#######################################################################################################################
# WebSvr <--->  svrInstance

此部分报文格式参见devProctol的包头和包体部分

## 连接验证
- MsgId 9001
- CryptFlag 1    

### 包体部分 
**注意：包体部分是AES之后的数据**
- svrIp
- svrHost
- timestamp    8Byte

以上数据用初始密钥加密  AES-256-CBC, KEY,IV 均用初始值

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝
**注意：包体部分是AES之后的数据**
- 加密部分报文
  - newIV        16Byte     
  - timestamp    8Byte
- nDataLen  //原始数据的长度
- crc16     //原始数据的crc16

webSvr收到后，后续报文，使用该IV来做AES计算

# 设备控制命令

## 远程开锁
- MsgId  4001
- CryptFlag 1
### 包体部分 

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

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝



## 远程锁定
- MsgId  4002
- CryptFlag 1
### 包体部分 

**注意：包体部分是AES之后的数据**
- 加密部分报文
  - devId           4Byte
  - devtype         1Byte  
  - timestamp       8Byte
  - usrId           4Byte
  - voice           1Byte  关锁音效
- nDataLen  //原始数据的长度
- crc16     //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝



## 远程防盗锁定
- MsgId  4003
- CryptFlag 1
### 包体部分 

**注意：包体部分是AES之后的数据**
- 加密部分报文
  - devId           4Byte
  - devtype         1Byte  
  - timestamp       8Byte
  - usrId           4Byte
  - shutdownMotor   1Byte  是否关闭电驱
  - maxSpeed        2Byte  限制的最高速度, 以m/s*100
  - warningVoice    1Byte  报警音效
- nDataLen  //原始数据的长度
- crc16     //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝


## 灯光控制

- MsgId  4004
- CryptFlag 1
### 包体部分 

**注意：包体部分是AES之后的数据**
- 加密部分报文
  - devId           4Byte
  - devtype         1Byte  
  - timestamp       8Byte
  - usrId           4Byte
  - lightFlag       1Byte  
- nDataLen  //原始数据的长度
- crc16     //原始数据的crc16

### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝

## 声响控制

## 自定义提示音

## 自定义灯光

## 开启整车测试

车辆在接收到该命令后，开启测试模式，按规定顺序逐一控制各部件，并反馈每次控制的状态情况

此命令仅为检测使用，不开放给App日常操作


