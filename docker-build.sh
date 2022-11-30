#!/bin/bash
###
# @Descripttion:
# @version:
# @Author: Tao Chen
# @Date: 2022-12-01 02:07:32
 # @LastEditors: Tao Chen
 # @LastEditTime: 2022-12-01 02:21:30
###

imageTag="$1"

if [ -z "$imageTag" ]; then
    imageTag=latest
fi

echo "Building sharelatex docker image tagged as [$imageTag]"
# read -p "Press [Enter] to continue..." any_key;

docker build --tag="overleaf-oauth2:$imageTag" . \
&& echo "Built sharelatex image successfully tagged as overleaf-oauth2:$imageTag" \
&& docker images "overleaf-oauth2:$imageTag"