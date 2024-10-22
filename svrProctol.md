
# 基本规则

svrMgr 对应管理不同的svrInstance
svrInstance 对应处理一定范围Id的device
dev出厂时设定的svrIp/Port，如后台规则调整，DevReg应答时返回dev应该连接的ip/port
wx小程序内，查看dev的状态、事件等信息，由svrMgr提供一定时间的动态缓存数据，
  控制dev的指令交互，tcp连接对应的svrInstance，svrInstance再发给对应的dev


为方便App获取设备的当前状态以及历史数据信息，svrMgr提供https接口
通过App对设备进行控制操作，由svrMgr的另外tcp接口，通信采用加密方式,AES-128,基于用户ID和登录设备ID，唯一分配的 AES  key。

# MgrHttpsSvr

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
  - type
    - 1 wx小程序
    - 2 独立App
  - usrId
  - usrSessionId   
  - timestamp
  - hash

HttpResponse采用json形式返回
  成功时
  - devList
    - devId
    - devType
    - ownerFlag   所有权说明，1 拥有  2 家人共享  3 朋友临时分享
    - dev
  - devStatus   //仅返回第一个dev的状态数据，其他另外查询，参见devProcotol文件
    - position
      - lngPos
      - latPos
    - status
    - miniiBatteryStatus
    - batteryExist
    - batteryId
    - batteryStatus 
    - seriesDataList  //[]

  - errCode 0
  失败时
  - errCode
    - 0xFF 请求的参数存在错误
  - errMsg



## 绑定车辆
/bindDevWithUsr
   
httpRequest
  - type
    - 1 wx小程序
    - 2 独立App
  - usrId
  - usrSessionId   
  - devId
  - devType
  - timestamp
  - crc

HttpResponse采用json形式返回
  成功时
    - errCode 0
  失败时
  - errCode
  - errMsg


## 解绑车辆
/unbindDev

httpRequest
  - type
    - 1 wx小程序
    - 2 独立App
  - usrId
  - usrSessionId   
  - devId
  - devType
  - timestamp
  - crc

HttpResponse采用json形式返回
  成功时
    - errCode 0
  失败时
  - errCode
  - errMsg

## 共享车辆给家人
/shareDevWithFamily

## 取消车辆家人共享
/unshareDevWithFamily

## 临时分享车辆
/tmpShareDevTo

## 取消临时分享
/cancelTmpShare



## 车辆授权情况查询
/devSharedStatus

httpRequest
  - usrSessionId
  - devId
  - timestamp
  - crc

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
  - userSessionId
  - devId
  - timestamp
  - crc

HttpResponse采用json形式返回
  - devStatus
    - position
      - lngPos
      - latPos
    - status
    - miniiBatteryStatus
    - batteryExist
    - batteryId
    - batteryStatus 
    - seriesDataList  //[]
  - errCode
  - errMsg


## 设备状态历史查询
/devStatusHistory

httpRequest
  - userSessionId
  - devId
  - timeStart
  - timeEnd
  - crc

HttpResponse采用json形式返回
  - devStatusArray
    - statusTimeStart
    - statusTimeEnd
    - devStatus
  - errCode
  - errMsg


## 设备事件历史查询
/getDevEvent

httpRequest
  - userSessionId
  - devId
  - timeStart
  - timeEnd
  - crc

HttpResponse采用json形式返回
  - devEventArray
    - eventTime
    - eventType
    - eventDesc
  - errCode
  - errMsg


## 电池状态历史查询


## 电池事件历史查询



#######################################################################################################################
# 以下为待定，临时测试用


# App发送设备控制命令

App通过连接Tcp Socket 发起控制命令

## 远程开锁
- MsgId  4001
- CryptFlag 1
### 包体部分 
**注意：包体部分是AES之后的数据，设备端需解密后验证时间和SessionId后处理**
- devId           4Byte
- allowTime       2Byte  允许使用的时长， 以min计
- lowestSocP      1Byte  允许使用到的最低电量  0~100
- farthestDist    4Byte  允许的最远距离，以m计
### 应答包
- RespCode
    - 0   Ok
    - 1   拒绝

## 添加分享手机号

## 远程锁定

## 远程防盗锁定

## 灯光控制

## 声响控制

## 自定义提示音

## 自定义灯光

## 开启整车测试

车辆在接收到该命令后，开启测试模式，按规定顺序逐一控制各部件，并反馈每次控制的状态情况

此命令仅为检测使用，不开放给App日常操作


