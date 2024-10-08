# 部署环境

腾讯云 轻量应用服务器 	Ubuntu Server 24.04 LTS 64bit
g++ 13.2

# 开发环境

docker kasmweb-ubuntu image采用kasmweb/ubuntu-jammy-dind:1.14.0-rolling
- 启动命令：
    docker run --name kasmweb-ubuntu -p 6901:6901 -p 5433:5432 -e VNC_PW=bingfao -v D:/workspace:/home/workspace -id kasmweb/ubuntu-jammy-dind:1.14.0-rolling
- 安装配置
    1. g++/gcc版本升级到13.1 （参考https://www.cnblogs.com/DHJ151250/p/17990879）
    - 添加ppa源
        sudo add-apt-repository ppa:ubuntu-toolchain-r/test
    - 安装gcc-13和g++-13
        sudo apt install gcc-13
        sudo apt install g++-13
    - 设定优先级
        sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 11
        sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 13
        sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 11
        sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 13
    - 检查gcc/g++版本
        gcc -v
        g++ -v
    2. Install PostgreSQL on Ubuntu （参考https://www.postgresqltutorial.com/postgresql-getting-started/install-postgresql-linux/）
    - Add PostgreSQL Repository
        sudo apt update
        sudo apt install gnupg2 wget
        sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
        curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg
        sudo apt update
    - Install PostgreSQL 16
        sudo apt install postgresql-16 postgresql-contrib-16
        sudo systemctl start postgresql  // docker里ubuntu不支持，采用sudo service postgresql start
        sudo systemctl enable postgresql 
    - Configure PostgreSQL server
        sudo nano /etc/postgresql/16/main/postgresql.conf
        listen_addresses = '*'
        Configure PostgreSQL to use md5 password authentication in the pg_hba.conf file
            sudo sed -i '/^host/s/ident/md5/' /etc/postgresql/16/main/pg_hba.conf
            sudo sed -i '/^local/s/peer/trust/' /etc/postgresql/16/main/pg_hba.conf
            echo "host all all 0.0.0.0/0 md5" | sudo tee -a /etc/postgresql/16/main/pg_hba.conf
        sudo service postgresql restart
        sudo ufw allow 5432/tcp
    - Connect to the PostgreSQL database server
        sudo -u postgres psql
        ALTER USER postgres PASSWORD '<password>';  //这里修改为想要的psw
        \q
    docker_pgsql 5433    psw: bingfao
    3. asio等代码通过docker的/home/workspace共享
    安装openssl的开发环境 参考（https://www.cnblogs.com/Yogile/p/12914741.html）
        sudo apt update
        sudo apt install openssl
        sudo apt install libssl-dev

# 微信小程序测试号

AppID(小程序ID)    wxc17827c5a40c3c73
AppSecret(小程序密钥)   e4bc0e6aa27182297397c36d05b7a5e9

获取用户手机号
1. wxApp小程序端，提示用户获取手机号授权，得到授权code 参考(https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/getPhoneNumber.html)
2. 小程序服务端，基于获取接口调用凭据获得的 access_token , 调用获取手机号API 
    - GET https://api.weixin.qq.com/cgi-bin/token 参考(https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/mp-access-token/getAccessToken.html)
    - POST https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token=ACCESS_TOKEN  参考(https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/user-info/phone-number/getPhoneNumber.html)


服务端同时存储用户的openid和手机号，获取手机号接口需收费，尽量使用openid来本地匹配信息

全国互联网安全管理服务平台的账号
实名身份证   psw: KingXun2018#

# ICP 备案

备案参考  https://cloud.tencent.com/document/product/243

沪ICP备2024096205号

# 公安网站备案

公安备案流程参考
https://cloud.tencent.com/document/product/243/19142#.E4.B8.8B.E8.BD.BD.E4.BA.92.E8.81.94.E7.BD.91.E7.AB.99.E5.AE.89.E5.85.A8.E6.9C.8D.E5.8A.A1.E5.B9.B3.E5.8F.B0.E6.93.8D.E4.BD.9C.E6.8C.87.E5.8D.97
备案网站： https://beian.mps.gov.cn/


沪公网安备31011702889934号