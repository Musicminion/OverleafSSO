ARG BASE=sharelatex/sharelatex
ARG TEXLIVE_IMAGE=registry.gitlab.com/islandoftex/images/texlive:latest

ARG SOURCE=./src/Oauth
# i set SOURCE because I put my source file at './src/' not like this './src/Oauth/'
# i do not use Apple Oauth2, so I do not move Authkey.p8


FROM $TEXLIVE_IMAGE as texlive

FROM $BASE as app

# set workdir (might solve issue #2 - see https://stackoverflow.com/questions/57534295/)
WORKDIR /overleaf/services/web/

# install latest npm
RUN npm install axios --registry=https://registry.npm.taobao.org
RUN npm install jsonwebtoken --registry=https://registry.npm.taobao.org
RUN npm install node-rsa --registry=https://registry.npm.taobao.org
RUN npm install fs --registry=https://registry.npm.taobao.org

# install pygments and some fonts dependencies
RUN apt-get update && apt-get -y install python3-pygments nano fonts-noto-cjk fonts-noto-cjk-extra fonts-noto-color-emoji xfonts-wqy fonts-font-awesome

# COPY router
RUN rm /overleaf/services/web/app/src/router.js
COPY $SOURCE/router.js /overleaf/services/web/app/src/

# COPY Auth Control
RUN rm /overleaf/services/web/app/src/Features/Authentication/AuthenticationController.js
COPY .$SOURCE/AuthenticationController.js /overleaf/services/web/app/src/Features/Authentication/

# COPY Auth Manager
RUN rm /overleaf/services/web/app/src/Features/Authentication/AuthenticationManager.js
COPY $SOURCE/AuthenticationManager.js /overleaf/services/web/app/src/Features/Authentication/

# COPY login.pug
RUN rm /overleaf/services/web/app/views/user/login.pug
COPY $SOURCE/login.pug /overleaf/services/web/app/views/user/


# Update TeXLive
COPY --from=texlive /usr/local/texlive /usr/local/texlive
RUN tlmgr path add
RUN echo "shell_escape = t" >> /usr/local/texlive/2022/texmf.cnf