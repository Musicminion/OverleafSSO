#!/bin/bash

# Overleaf SSO Updater By Musicminion
# [Attention]需要在Sharelatex的容器内运行
# Run In Your Overleaf Sharelatex Docker Inner!

# 脚本目录
CURRENT_DIR=$(cd $(dirname $0); pwd)

# 安装依赖（如果在国内安装请加上这句话 --registry=https://registry.npm.taobao.org）
cd /overleaf/services/web/
npm install axios
npm install jsonwebtoken
npm install node-rsa
# npm install axios  --registry=https://registry.npm.taobao.org
# npm install jsonwebtoken --registry=https://registry.npm.taobao.org

cd $CURRENT_DIR
# 拷贝router
rm /overleaf/services/web/app/src/router.js
cp ./src/OAuth/router.js /overleaf/services/web/app/src/

# 拷贝Auth Control
rm /overleaf/services/web/app/src/Features/Authentication/AuthenticationController.js
cp ./src/OAuth/AuthenticationController.js /overleaf/services/web/app/src/Features/Authentication/

# 拷贝Auth Manager
rm /overleaf/services/web/app/src/Features/Authentication/AuthenticationManager.js
cp ./src/OAuth/AuthenticationManager.js /overleaf/services/web/app/src/Features/Authentication/

# 拷贝
rm /overleaf/services/web/app/views/user/login.pug
cp ./src/OAuth/login.pug /overleaf/services/web/app/views/user/



echo 'Finish SSO Update!'