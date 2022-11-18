# Overleaf Plus ToolBox
## 简介和准备工作
这是一个将Overleaf升级到带有自动注册和单点登录的小工具，要将您的Overleaf升级到Overleaf Plus版本，你需要做好下面的准备工作：
- 首先，你是通过官网的[Overleaf Toolkit](https://github.com/overleaf/toolkit/)安装的你的Overleaf
- 你基本熟悉Overleaf拥有三个容器：
    - Sharelatex容器作为Web服务
    - Redis作为缓存服务
    - MongoDB作为数据存储服务
- 你的Sharelatex容器没有做任何更改，或者你准备放弃你曾经对Sharelatex容器所做的更改，亦或者你已经备份好你的旧数据（并且熟悉如何恢复）。
- 你需要按照要求配置好环境变量，由于配置环境变量后，再次执行`bin/up`使得更新生效的时候，会摧毁旧的Sharelatex容器，并创建一个全新的容器，所以旧的Sharelatex容器的内容会全部丢失！
- 如果你没有做好准备，请不要开始。

## 环境变量配置
必须配置好环境变量后，才可以继续执行后面的步骤，否则会出现错误。
```bash
# OAuth相关的配置
# 是否允许全局的OAuth登录，值为`true`或者`false`,如果你需要使用单点登录，请把
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


# Apple Related 
SHARELATEX_OAUTH_APPLE_ENABLED=true
SHARELATEX_OAUTH_APPLE_AUTH_URL=https://appleid.apple.com/auth/authorize
SHARELATEX_OAUTH_APPLE_TOKEN_URL=https://appleid.apple.com/auth/token
SHARELATEX_OAUTH_APPLE_PUBLIC_KEY_URL=https://appleid.apple.com/auth/keys
SHARELATEX_OAUTH_APPLE_CLIENT_ID=
SHARELATEX_OAUTH_APPLE_CLIENT_SECRET=
SHARELATEX_OAUTH_APPLE_REDIRECT_URL=
SHARELATEX_OAUTH_APPLE_SCOPE=name email
```