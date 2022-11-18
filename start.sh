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
npm insatll fs
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

# 拷贝login.pug
rm /overleaf/services/web/app/views/user/login.pug
cp ./src/OAuth/login.pug /overleaf/services/web/app/views/user/

# 拷贝Server.js
rm /overleaf/services/web/app/src/infrastructure/Server.js
cp ./src/OAuth/Server.js /overleaf/services/web/app/src/infrastructure/


if [ "${SHARELATEX_OAUTH_APPLE_ENABLED}" == "true" ]; then
    echo $SHARELATEX_OAUTH_APPLE_AUTH_SERVICE_SECRET_KEY_LINE_1 >> ./src/OAuth/AuthKey.p8
    echo $SHARELATEX_OAUTH_APPLE_AUTH_SERVICE_SECRET_KEY_LINE_2 >> ./src/OAuth/AuthKey.p8
    echo $SHARELATEX_OAUTH_APPLE_AUTH_SERVICE_SECRET_KEY_LINE_3 >> ./src/OAuth/AuthKey.p8
    echo $SHARELATEX_OAUTH_APPLE_AUTH_SERVICE_SECRET_KEY_LINE_4 >> ./src/OAuth/AuthKey.p8
    echo $SHARELATEX_OAUTH_APPLE_AUTH_SERVICE_SECRET_KEY_LINE_5 >> ./src/OAuth/AuthKey.p8
    echo $SHARELATEX_OAUTH_APPLE_AUTH_SERVICE_SECRET_KEY_LINE_6 >> ./src/OAuth/AuthKey.p8
    # 拷贝密钥文件
    cp ./src/OAuth/AuthKey.p8 /overleaf/services/web/app/src/Features/Authentication/AuthKey.p8

    echo 'Apple Auth Key Imported!'
fi

echo 'Finish SSO Update!'