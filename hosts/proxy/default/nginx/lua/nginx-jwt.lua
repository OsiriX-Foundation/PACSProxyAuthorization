local jwt = require "resty.jwt"
local cjson = require "cjson"
local basexx = require "basexx"
local http = require "resty.http"
local cjson = require "cjson"

local secret = os.getenv("JWT_SECRET")
local post_secret = os.getenv("JWT_POST_SECRET")

function string.starts(String,Start)
   return string.sub(String,1,string.len(Start))==Start
end

assert(secret ~= nil, "Environment variable JWT_SECRET not set")
assert(post_secret ~= nil, "Environment variable JWT_POST_SECRET not set")

local M = {}

function M.auth(claim_specs, use_post_secret)

    -- require Authorization request header
    local auth_header = ngx.var.http_Authorization
    local token = nil
    local validation_secret = nil
    if auth_header ~= nil then
        _, _, token = string.find(auth_header, "Bearer%s+(.+)")
    else
        if ngx.var.arg_access_token ~= nil then
            token=ngx.var.arg_access_token
        else
            ngx.log(ngx.WARN,"access_token: missing")
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    end
    if use_post_secret == true then
        validation_secret = post_secret
    else
        validation_secret = secret;
    end

    -- require valid JWT
    local jwt_obj = jwt:verify(validation_secret, token, 0)
    if jwt_obj.verified == false then
        ngx.log(ngx.WARN, "token:"..token)
        ngx.log(ngx.WARN, "Invalid token: ".. jwt_obj.reason)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

   if jwt_obj.payload["sub"] ~= nil then
      ngx.var.lua_remote_user = jwt_obj.payload["sub"]
   end
   if jwt_obj.payload["azp"] ~= nil then
      ngx.var.azp = jwt_obj.payload["azp"]
   end
   if jwt_obj.payload["cap_token"] ~= nil then
      ngx.var.cap_token = jwt_obj.payload["cap_token"]
   end 
   if jwt_obj.payload["act"] ~= nil then
      ngx.var.act = jwt_obj.payload["act"]
   end
   
    -- if wado uri request
    if string.starts(ngx.var.request_uri, "/wado") then
        if ngx.var.arg_requestType == "WADO" then
            if ngx.var.arg_studyUID ~= nil then
                if ngx.var.arg_studyUID ~= jwt_obj.payload["study_uid"] then
                    ngx.log(ngx.WARN,"studyUID: error (not same as JWT)")
                    ngx.exit(ngx.HTTP_UNAUTHORIZED)
                end
            else
                ngx.log(ngx.WARN,"studyUID: missing")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
            end
            if ngx.var.arg_seriesUID ~= nil then
                if ngx.var.arg_seriesUID ~= jwt_obj.payload["series_uid"] then
                    ngx.log(ngx.WARN,"seriesUID: error (not same as JWT)")
                    ngx.exit(ngx.HTTP_UNAUTHORIZED)
                end
            else
                ngx.log(ngx.WARN,"seriesUID: missing")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
            end
        else
            ngx.log(ngx.WARN,"requestType: missing")
            ngx.exit(ngx.HTTP_BAD_REQUEST)
        end
    end


    -- optionally require specific claims
    if claim_specs ~= nil then
        -- make sure they passed a Table
        if type(claim_specs) ~= 'table' then
            ngx.log(ngx.STDERR, "Configuration error: claim_specs arg must be a table")
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        -- process each claim
        local blocking_claim = ""
        for claim, spec in pairs(claim_specs) do

            -- make sure token actually contains the claim
            local claim_value = jwt_obj.payload[claim]
            if claim_value == nil then
                blocking_claim = claim .. " (missing)"
                break
            end

            local spec_actions = {
                -- claim spec is a string (pattern)
                ["string"] = function (pattern, val)
                    return string.match(val, pattern) ~= nil
                end,

                -- claim spec is a predicate function
                ["function"] = function (func, val)
                    -- convert truthy to true/false
                    if func(val) then
                        return true
                    else
                        return false
                    end
                end
            }

            local spec_action = spec_actions[type(spec)]

            -- make sure claim spec is a supported type
            if spec_action == nil then
                ngx.log(ngx.STDERR, "Configuration error: claim_specs arg claim '" .. claim .. "' must be a string or a table")
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            end

            -- make sure token claim value satisfies the claim spec
            if not spec_action(spec, claim_value) then
                blocking_claim = claim
                break
            end
        end

        if blocking_claim ~= "" then
            ngx.log(ngx.WARN, "User did not satisfy claim: ".. blocking_claim)
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    end



    --get an access token for the google pacs
    --JWT
    header={}
    header["typ"]="JWT"
    header["alg"]="RS256"
    payload={}
    payload["iss"]="pacspep@kheopsdicomwebproject.iam.gserviceaccount.com"
    payload["scope"]="https://www.googleapis.com/auth/cloud-platform"
    payload["aud"]="https://oauth2.googleapis.com/token"
    payload["iat"]=os.time(os.date("!*t"))
    payload["exp"]=os.time(os.date("!*t"))+1000
    table_of_jwt = {}
    table_of_jwt["header"]=header
    table_of_jwt["payload"]=payload
   
    ngx.log(ngx.WARN,"iat: "..payload["iat"])
    ngx.log(ngx.WARN,"exp: "..payload["exp"])


    --read privkey.pem
    local file = '/run/secrets/privkey.pem'
    local lines = lines_from(file)

    --extract content
    local key=""
    for k,v in pairs(lines) do
       key=key..v.."\n"
    end
    ngx.log(ngx.WARN,"key: "..key)
    --sign the jwt with the privkey
    local jwt_token = jwt:sign(key, table_of_jwt)
    ngx.log(ngx.WARN,jwt_token)

    --Get an access token for the google pacs
    local httpc = http.new()
    httpc:set_proxy_options(proxy_options)
    local res, err =httpc:request_uri("https://oauth2.googleapis.com/token", {
                    method="POST", 
                    keepalive=false, 
                    body="grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="..jwt_token,
                    headers={["Content-Type"]="application/x-www-form-urlencoded"}
                 })

    if res ~= nil then
       if res.body ~=nil then
          if res.status == 200 then
             local access_token=cjson.decode(res.body)
             ngx.var.pacs_bearer_access_token="Bearer "..access_token["access_token"]
          else
             ngx.log(ngx.WARN,"body: "..res.body)
             ngx.log(ngx.WARN,"status: "..res.status)
             ngx.exit(res.status)
          end
       else 
          ngx.log(ngx.WARN,"status: "..res.status)
          ngx.exit(ngx.HTTP_UNAUTHORIZED)
       end
    else 
       ngx.log(ngx.WARN,"err: "..err)
       ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end


    -- write the X-Auth-UserId header
    ngx.header["X-Auth-UserId"] = jwt_obj.payload.sub
end

-- see if the file exists
function file_exists(file)
  local f = io.open(file, "rb")
  if f then f:close() end
  return f ~= nil
end

-- get all lines from a file, returns an empty 
-- list/table if the file does not exist
function lines_from(file)
  if not file_exists(file) then return {} end
  lines = {}
  for line in io.lines(file) do 
    lines[#lines + 1] = line
  end
  return lines
end


return M






