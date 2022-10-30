import requests
from urllib import parse
import json

# url与请求头
url = "https://twitter.com/i/api/2/search/adaptive.json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_ext_alt_text=true&include_quote_count=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweet=true&q={}&count=20&query_source=typed_query&pc=1&spelling_corrections=1&ext=mediaStats%2ChighlightedLabel%2CvoiceInfo"
url_token = 'https://api.twitter.com/1.1/guest/activate.json'
headers = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
  'Accept': '*/*',
  'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
  'x-guest-token': '',
  'x-twitter-client-language': 'zh-cn',
  'x-twitter-active-user': 'yes',
  'x-csrf-token': '25ea9d09196a6ba850201d47d7e75733',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Site': 'same-origin',
  'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
  'Referer': 'https://twitter.com/',
  'Connection': 'keep-alive',
}

# q字符串
q = '(CVE-2022- and POC) until:2022-10-18 since:2022-10-01'

if __name__ == "__main__":
    token = json.loads(requests.post(url_token, headers=headers).text)['guest_token']
    headers['x-guest-token'] = token
    res = requests.get(url.format(parse.quote(q)), headers=headers)
    print(res.text)
