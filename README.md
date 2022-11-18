# Overleaf OAuth2 Tool

Attention！Project Still In Beta！Don't use directly!

This is a tool for Update your Overleaf to support Single Sign On(SSO)

First of all, let's suppose you install Overleaf via [Overleaf Toolkit](https://github.com/overleaf/toolkit/). If you install Your Overleaf via other method, don't use this tool.

Reminder: After Upgrade, all of your changes to Docker 'Sharelatex' will lose! Backup your Files Please!

To get started, you need to reconfig your docker env variable.

Here I give an example for github OAuth.
```
# 总控制 是否允许单点登录
SHARELATEX_OAUTH_AUTH_ENABLED=true


SHARELATEX_OAUTH_COMMON_AUTH_URL=https://github.com/login/oauth/authorize
SHARELATEX_OAUTH_COMMON_CLIENT_ID=24989********cb8f9be5c8
SHARELATEX_OAUTH_COMMON_CLIENT_SECRET=c78*************************
SHARELATEX_OAUTH_COMMON_REDIRECT_URL=http://127.0.0.1:3000/oauth/callback
SHARELATEX_OAUTH_COMMON_ACCESS_TOKEN_URL=https://github.com/login/oauth/access_token
SHARELATEX_OAUTH_COMMON_USER_PROFILE_URL=https://api.github.com/user
SHARELATEX_OAUTH_COMMON_SCOPE=user:email

# Login Button Text 
SHARELATEX_OAUTH_COMMON_BUTTON_NAME=Login Via Github


# 通过单点登录获取到的用户信息是否包含电子邮件字段
# 默认为否，那么在新用户通过单点登录的时候，就会创建
# 一个邮箱 [username]@[SHARELATEX_OAUTH_COMMON_USER_EMAIL_DOMAIN]
# 其中username = USER_JSON['SHARELATEX_OAUTH_COMMON_USER_EMAIL_NAME_IDENTIFIER']
SHARELATEX_OAUTH_COMMON_USER_PROFILE_CONTAIN_EMAIL=false

# 如果获取到的USER_JSON中，包括邮件地址，请把此项设置为邮件对应的字段，例如'mail'
# 如果获取到的USER_JSON中，不包括邮箱地址，请把此项设置为标识用户唯一性的字段,例如username
SHARELATEX_OAUTH_COMMON_USER_EMAIL_NAME_IDENTIFIER=name

# 当且仅当如果获取到的USER_JSON中，不包括邮件地址，此时如果新用户通过单点登录
# 这时候需要处理好注册的逻辑，此时注册的用户的邮箱的域名为：SHARELATEX_OAUTH_COMMON_USER_EMAIL_DOMAIN
# 默认值是oauth2.localhost
SHARELATEX_OAUTH_COMMON_USER_EMAIL_DOMAIN=oauth2.localhost

# 也就是说，如果获取到的USER_JSON中，不包括邮箱地址，当一个名叫Musicminion新用户登录进来的时候
# Overleaf会默认创建一个名叫 Musicminion@oauth2.localhost。密码会随机生成一个32位的无规律字符串
#（当然前提是你没有修改SHARELATEX_OAUTH_COMMON_USER_EMAIL_DOMAIN）

```

Add All these env into your variables.env 
```
sudo nano ~/overleaf-toolkit/config/variables.env 
cd ~/overleaf-toolkit
sudo bin/up
sudo bin/start
```

Then, 
```
# enter docker 
sudo docker exec -it sharelatex /bin/bash
git clone https://github.com/Musicminion/OverleafSSO
cd OverleafSSO
chmod -R 777 ./*
./bash
# you will see 'Finish SSO Update!' in the end.
exit

# restart your overleaf
sudo bin/stop
sudo bin/start
```

Finally, If you want to edit your SSO button name, please edit: [here](https://github.com/Musicminion/OverleafSSO/blob/main/src/login.pug#L39)


## Environment Variable
```bash
# Common OAuth (Support Main OAuth like Github/Google and so on)
# If you allow OAUTH : true | false



SHARELATEX_OAUTH_ENABLED=

# Auth Related
SHARELATEX_OAUTH_COMMON_ENABLED=
SHARELATEX_OAUTH_COMMON_AUTH_URL=
SHARELATEX_OAUTH_COMMON_CLIENT_ID=
SHARELATEX_OAUTH_COMMON_CLIENT_SECRET=
SHARELATEX_OAUTH_COMMON_REDIRECT_URL=
SHARELATEX_OAUTH_COMMON_ACCESS_TOKEN_URL=
SHARELATEX_OAUTH_COMMON_USER_PROFILE_URL=
SHARELATEX_OAUTH_COMMON_BUTTON_NAME=
SHARELATEX_OAUTH_COMMON_SCOPE=

# User Related
SHARELATEX_OAUTH_COMMON_USER_PROFILE_CONTAIN_EMAIL=
SHARELATEX_OAUTH_COMMON_USER_EMAIL_NAME_IDENTIFIER=
SHARELATEX_OAUTH_COMMON_USER_EMAIL_DOMAIN=



```
