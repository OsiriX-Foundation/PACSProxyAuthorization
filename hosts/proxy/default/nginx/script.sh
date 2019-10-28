#!/bin/bash

chmod a+w /opt/openresty/nginx/conf/nginx.conf

missing_env_var_secret=false



#set secrets
export JWT_SECRET="12345678"
export JWT_POST_SECRET="12345678"


echo "Ending setup PEP secrets and env var"




nginx -g 'daemon off; error_log /dev/stderr info;'
