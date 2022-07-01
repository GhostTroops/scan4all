#!/bin/bash
#DELETE /${1}_index* HTTP/1.1
#host:127.0.0.1:9200
#User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15
#Connection: keep-alive
#Content-Type: application/json;charset=UTF-8
#Content-Length: 0
#
sed $'s/$/\r/' <<EOF | nc 127.0.0.1 9200
PUT /${1}_index HTTP/1.1
host:127.0.0.1:9200
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15
Connection: keep-alive
Content-Type: application/json;charset=UTF-8
Content-Length: 405

{
  "settings": {
   "analysis": {
     "analyzer": {
       "default": {
         "type": "custom",
         "tokenizer": "ik_smart",
         "char_filter": [
            "html_strip"
          ]
       },
       "default_search": {
         "type": "custom",
         "tokenizer": "ik_smart",
         "char_filter": [
            "html_strip"
          ]
      }
     }
   }
  }
}
PUT /${1}_index/_settings HTTP/1.1
host:127.0.0.1:9200
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15
Connection: close
Content-Type: application/json;charset=UTF-8
Content-Length: 171

{
    "index.translog.durability": "async",
    "index.translog.sync_interval": "5s",
    "index.translog.flush_threshold_size":"100m",
   "refresh_interval": "30s"
}

EOF

xxx=$(/usr/bin/curl -s -k -q http://localhost:9200/${1}_index/_settings &2>/dev/null)
echo  $xxx|jq
