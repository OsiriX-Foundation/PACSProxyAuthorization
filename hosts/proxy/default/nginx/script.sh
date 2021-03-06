#!/bin/bash

chmod a+w /opt/openresty/nginx/conf/nginx.conf

missing_env_var_secret=false

#Verify secrets
if [ -f /run/secrets/kheops_auth_hmasecret ]; then
    filename="/run/secrets/kheops_auth_hmasecret"
    word_count=$(wc -w $filename | cut -f1 -d" ")
    line_count=$(wc -l $filename | cut -f1 -d" ")

    if [ ${word_count} != 1 ] || [ ${line_count} != 1 ]; then
        echo Error with secret $filename. He contains $word_count word and $line_count line
        missing_env_var_secret=true
    fi
    kheops_auth_hmasecret=$(head -n 1 $filename)
else
    echo "Missing auth_hmasecret secret"
    missing_env_var_secret=true
fi

if [ -f /run/secrets/kheops_auth_hmasecret_post ]; then
    filename="/run/secrets/kheops_auth_hmasecret_post"
    word_count=$(wc -w $filename | cut -f1 -d" ")
    line_count=$(wc -l $filename | cut -f1 -d" ")

    if [ ${word_count} != 1 ] || [ ${line_count} != 1 ]; then
        echo Error with secret $filename. He contains $word_count word and $line_count line
        missing_env_var_secret=true
    fi
    kheops_auth_hmasecret_post=$(head -n 1 $filename)
else
    echo "Missing auth_hmasecret_post secret"
    missing_env_var_secret=true
fi

#Verify environment variables
if [ -z "$KHEOPS_PROXY_PACS_WADO_URI" ]; then
    echo "Missing KHEOPS_PROXY_PACS_WADO_URI environment variable"
    missing_env_var_secret=true
fi
if [ -z "$KHEOPS_PROXY_PACS_WADO_RS" ]; then
    echo "Missing KHEOPS_PROXY_PACS_WADO_RS environment variable"
    missing_env_var_secret=true
fi


#if missing env var or secret => exit
if [ "$missing_env_var_secret" = true ]; then
    exit 1
fi


#set env var
sed -i "s|\${pacs_wado_uri}|$KHEOPS_PROXY_PACS_WADO_URI|" /opt/openresty/nginx/conf/nginx.conf
sed -i "s|\${pacs_wado_rs}|$KHEOPS_PROXY_PACS_WADO_RS|" /opt/openresty/nginx/conf/nginx.conf

#set secrets
export JWT_SECRET=$kheops_auth_hmasecret
export JWT_POST_SECRET=$kheops_auth_hmasecret_post


echo "Ending setup PEP secrets and env var"

nginx -g 'daemon off; error_log /dev/stderr info;'
