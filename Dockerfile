ARG BASE=sharelatex/sharelatex
ARG TEXLIVE_IMAGE=registry.gitlab.com/islandoftex/images/texlive:latest

# ARG SRC=./src
# ARG FONTS=./fonts

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
RUN apt-get update && apt-get -y install \
    python3-pygments \
    nano \
    fonts-noto-cjk \
    fonts-noto-cjk-extra \
    fonts-noto-color-emoji \
    xfonts-wqy \
    fonts-font-awesome

# COPY router
RUN rm /overleaf/services/web/app/src/router.js
COPY ./src/router.js /overleaf/services/web/app/src/

# COPY Auth Control
RUN rm /overleaf/services/web/app/src/Features/Authentication/AuthenticationController.js
COPY ./src/AuthenticationController.js /overleaf/services/web/app/src/Features/Authentication/

# COPY Auth Manager
RUN rm /overleaf/services/web/app/src/Features/Authentication/AuthenticationManager.js
COPY ./src/AuthenticationManager.js /overleaf/services/web/app/src/Features/Authentication/

# COPY login.pug
RUN rm /overleaf/services/web/app/views/user/login.pug
COPY ./src/login.pug /overleaf/services/web/app/views/user/


# extend pdflatex with option shell-esacpe (fix for closed overleaf/overleaf/issues/217 and overleaf/docker-image/issues/45)
# RUN sed -iE "s%-synctex=1\",%-synctex=1\", \"-shell-escape\",%g" /overleaf/services/clsi/app/js/LatexRunner.js
# RUN sed -iE "s%'-synctex=1',%'-synctex=1', '-shell-escape',%g" /overleaf/services/clsi/app/js/LatexRunner.js


# Update TeXLive
COPY --from=texlive /usr/local/texlive /usr/local/texlive
RUN echo "shell_escape = t" >> /usr/local/texlive/2022/texmf.cnf
# RUN cd /usr/local/texlive
# Add a mirrors
RUN tlmgr option repository https://mirrors.ustc.edu.cn/CTAN/systems/texlive/tlnet
RUN tlmgr path add
RUN tlmgr update --self --all 
RUN tlmgr install scheme-full

# add fonts
RUN mkdir -p /usr/share/fonts/winfonts
COPY ./fonts/ /usr/share/fonts/winfonts/
RUN cd /usr/share/fonts/winfonts
RUN mkfontscale
RUN mkfontdir
RUN fc-cache -fv
