import re
'''
https://github.com/TONG0S/encrypt

'''


config={"&":"&amp;",
        "<":"&lt;",
        ">":"&gt;",
        '(':"&#40;",
        ')':"&#41;",
        '=':"&#61;",
        '"':"&quot;",
        '\'': "&#x27;"}

def escape(s, quote=True):
    for k,v in config.items():
        s = s.replace(k, v)
    return s
def unescape(s, quote=True):
    for k,v in config.items():
        s = s.replace(v, k)
    return s