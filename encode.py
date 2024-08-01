import tkinter as tk
import base64
from urllib import request, parse
import hashlib
import  library.html_encoding as html
import time
from base64 import b64decode,b32decode,b16decode
import re,math
from html import escape, unescape
import quopri
from nltk.corpus import words
from urllib.parse import unquote
import  re
import requests
import threading
'''
未完成

   

'''


# 定义Base64字符集

def base32_decoded_length(base32_length):
    return math.floor(base32_length * 5 / 8)
def base64_decoded_length(base64_length):
    return math.floor(base64_length * 3 / 4)
def base16_decoded_length(base16_length):
    return math.floor(base16_length / 2)
def base64_decode(info):
    try:
        # print(info)
        info=b64decode(info)
        # print(info)
    except:
        pass
    return info
def base32_decode(info):
    try:
        # print(info)
        info=b32decode(info)
    except:
        pass
    return info
def base16_decode(info):
    try:
        # print(info)
        info=b16decode(info)
    except:
        pass
    return info
def to_str(info_,num,size_):

    try:
        info_ = info_.decode('utf-8')
    except:
        try:
            info_ = info_.decode('gbk')
        except:
            return "False"
    #解码验证
    # if num=="16":
    #     size_new=base16_decoded_length(size_)
    #     if len(info_)==size_new:
    #         return info_
    # elif num=="32":
    #     size_new=base32_decoded_length(size_)
    #     if len(info_)==size_new:
    #         return info_
    # elif num=="64":
    #     size_new=base64_decoded_length(size_)
    #     print(size_new)
    #     print(size_)
    #     print(len(info_))
    #     print(info_)
    #     if len(info_)==size_new:
    #         return info_
    return info_
def is_valid_input(info):
    num=set("0123456789")
    base16 = set("ABCDEF0123456789")
    base32 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
    base64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+/")
    # print(info)
    info_=""
    # 判断是否只包含允许的字符
    if set(info).issubset(num):
        return info

    else:
        size_ = len(info.replace("=","").replace("/","").replace("+",""))
        if set(info).issubset(base16):
            info_=base16_decode(info)
            t=to_str(info_,"16",size_)
            if t!="False":
                return t
        if set(info).issubset(base32):
            info_=base32_decode(info)
            t=to_str(info_,"32",size_)
            if t!="False":
                return t
        if set(info).issubset(base64):
            info_=base64_decode(info)
            t=to_str(info_,"64",size_)
            if t!="False":
                return t


    return info
def chr_encode(words_):
    t = r'(chr\(([0-9]{1,3})\)+)'
    t = re.findall(t, str(words_))
    if len(t) >= 1:
        words_ = re.sub(r'chr\(([0-9]{1,3})\)', lambda x: chr(int(x.group(1))), words_)
    return words_
def x_hexadecimal(x):
    t = r'(\\x[a-zA-Z0-9]{2})'
    t = re.findall(t, x)
    if len(t) >= 1:
        # x = x.encode('unicode_escape')

        ss = re.sub(r'\\x[a-zA-Z0-9]{2}', lambda x: x.group(0).replace('\\x', '%'), x)
        x = unquote(ss)
    return x
def  unicode_decode(x):
    t = r'((\\u[a-zA-Z0-9]{4})+)'
    t = re.findall(t, str(x))
    if len(t) >= 1:
        x = re.sub(r'\\u([0-9a-fA-F]{4})', lambda x: chr(int(x.group(1), 16)), x)
    return x
def uri_decode(x):
    x = unquote(x)
    return x
def html_decode(x):
    x = unescape(x)
    return x
def QuotedPrintable_decode(x):
    x = quopri.decodestring(x.encode()).decode()
    return x
def fist_(x):
    #尝试\x前缀解码
    x=x_hexadecimal(x)

    # unicode解码
    x=unicode_decode(x)
    #html实体编码
    x=html_decode(x)
    #uri解码
    x=uri_decode(x)
    print(x)
    #Quoted-Printable 解码
    # x=QuotedPrintable_decode(x)
    t=re.split('([^\d\w\+\\\/])',x)

    words_=""
    for i in t:
        size_=len(i)
        temp=str(i)
        # if str(size_) in encode_info.keys():
        #     print(encode_info[str(size_)])
        # print(temp)
        if len(temp)>=3:
            #尝试两次加=
            if temp in words.words():
                pass
            else:
                for n in range(1,3):
                    temp=is_valid_input(temp)
                    # print(temp)
                    x=str(i)+"="*n
                    if temp+"="!=x:
                        # print(temp)
                        break
                    else:
                        temp=temp+"="

            if temp==x:
                temp=temp[:-n]

        words_+=temp
    #chr解码
    # words_ = chr_encode(words_)

    # print("\n")
    # print("******"*20)
    # print("解密结果：")
    # print("\n")
    # print(words_)
    return words_
def php_(payload):
    info={}
    payload=payload.replace('"."',"")
    payload=re.sub('([^\d\w]\.[^\d\w]*?)',lambda x: x.group(1).replace('"."', '').replace('.', ''),payload)
    payload=payload.split(";")
    words_=""
    for i in payload:
        temp=str(i)
        t = r'\$([_0-9a-zA-Z]+)='

        variable_ = re.findall(t, str(i))
        variable_ = list(set(variable_))
        for j in variable_:
            if len(info) >=1:
                for k, v in info.items():
                    t = r'(\${}[^\d\w_=]+)'.format(str(k))
                    t = re.findall(t, str(i))
                    if len(t) >= 1:
                        temp = re.sub('(\${}[^\d\w_=]+)'.format(k),
                                      lambda x: x.group(1).replace("${}".format(str(k)), v), temp)
            t = r'(\${}=([^;]+))'.format(str(j))
            t = re.findall(t, str(temp))
            if len(t)>=1:
                # print(t)
                info[str(j)]=list(t)[0][1]
        words_+=temp+";"

    words_=chr_encode(words_)
    words_=chr_encode(words_)
    print("\n"*2)
    print("尝试php 解码"+"*"*20)
    print("\n"*2)
    print(words_)

class test(tk.Tk):

    def __init__(self):
        super().__init__()         #需要继承tk
        self.title("加密解密")
        self.geometry("700x700")
        self.type_info = ""  # 设置编码类型
        self.character_encode = ["utf-8", 'gbk']  # 设置字符编码列表
        self.encode_info = "utf-8"  # 设置字符编码
        self.base_encode = ["16进制", '2进制','10进制']  # 设置进制列表
        self.url_dictionary = ["PHP", 'JSP', 'ASP']    #设置语言
        self.base_encode_url = ["no", 'yes']  # 设置进制列表
        self.base_info = "16进制"  # 设置进制编码
        self.url_info = ["协议:  ", "域名: ", "路径: ", "参数: ", "查询: ", " "]  # 设置进制编码
        self.BASE64_CHARS="gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6"
        self.url_dictionary_info="PHP"
        self.choose_base = 0  # 是否是加密列表
        self.choose_url = 0  # 是否是url处理列表
        self.choose_base_url =0
        self.choose_encode_url="no"
        self.header={'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36'}
        self.choose_encode_ascii = 0
        self.choose_urldic = 0          #设置语言单选框
        self.choose = 0
        self.main()
    def main(self):
        self.mainmenu = tk.Menu(self)
        self.addfile = tk.Menu(self.mainmenu, tearoff=0, foreground="white", bg="black")  # 实例化一个菜单
        self.mainmenu.add_cascade(label="文件", menu=self.addfile)
        self.addfile.add_command(label="首页",command=self.index_main)  # 创建二级菜单
        self.addfile.add_command(label="保存", command=self.url_code)  # 创建二级菜单
        self.addfile.add_command(label="打开", command=self.base64_code)

        self.mainfile = tk.Menu(self.mainmenu, tearoff=0, foreground="white", bg="black")  # 实例化一个菜单
        self.mainmenu.add_cascade(label="加解密", menu=self.mainfile)
        self.mainfile.add_command(label="judge", command=self.len_judge)
        self.mainfile.add_command(label="URL", command=self.url_code)  # 创建二级菜单
        self.mainfile.add_command(label="HTML实体", command=self.html_code)
        self.mainfile.add_command(label="BASE64", command=self.base64_code)
        self.mainfile.add_command(label="BASE32", command=self.base32_code)
        self.mainfile.add_command(label="BASE16", command=self.base16_code)
        self.mainfile.add_command(label="ASCII", command=self.ascii_code)
        self.mainfile.add_command(label="SHA1", command=self.sha1_code)
        self.mainfile.add_command(label="SHA256", command=self.sha256_code)
        self.mainfile.add_command(label="MD5", command=self.md5_code)
        self.mainfile.add_command(label="Seeyon", command=self.seeyon_code)
        self.mainfile.add_command(label="Auto", command=self.auto_)
        self.config(menu=self.mainmenu)

        self.urlfile = tk.Menu(self.mainmenu, tearoff=0, foreground="white", bg="black")  # 实例化一个菜单
        self.mainmenu.add_cascade(label="URL", menu=self.urlfile)
        self.urlfile.add_command(label="url处理", command=self.domain_deal)  # 创建二级菜单
        self.urlfile.add_command(label="目录扫描", command=self.urldic_scan)  # 创建二级菜单
        self.urlfile.add_command(label="fuzz", command=self.base64_code)

        self.lb = tk.Label(self, text="首页")
        self.lb.place(relx=0, rely=0, relwidth=1, relheight=0.05)


        self.lb1 = tk.Label(self, text="结果：")
        self.lb1.place(relx=0.05, rely=0.3, relwidth=0.1, relheight=0.05)
        self.text_info = tk.Text(self)
        self.text_info.place(relx=0.05, rely=0.35, relwidth=0.9, relheight=0.2)
        self.lb2 = tk.Label(self, text="临时存储：")
        self.lb2.place(relx=0.05, rely=0.55, relwidth=0.1, relheight=0.05)
        self.text_backup = tk.Text(self)
        self.text_backup.place(relx=0.05, rely=0.6, relwidth=0.4, relheight=0.2)
        self.judge_show()




    '''
    控件的显示与删除
    '''


   #清除控件
    def delete_control(self):
        try:
            self.frame1.place_forget()
            self.frame2.place_forget()
        except Exception as e:
            pass
        try:
            self.frame3.place_forget()
        except Exception as e:
            pass
        try:
            self.entry_url.place_forget()
            self.button_url.place_forget()
        except Exception as e:
            pass

    #决定显示的控件
    def judge_show(self):
        self.delete_control()
        if self.choose_base == 1:
            self.temp()
        elif self.choose_url == 1:
            self.url_show()
        elif self.choose == 1:
            pass




    #加解密显示的控件
    def temp(self):
        self.frame1=tk.Frame(self)                        #添加一个框架，便于清除控件
        self.entry_encode = tk.Entry(self.frame1)
        # 框架的内部似乎不能使用place //尝试过place  失败！
        self.entry_encode.pack(padx=20, pady=0, ipadx=150, ipady=10, side=tk.LEFT)
        self.button_encode = tk.Button(self.frame1, text="加密", command=self.encode_deal)
        self.button_encode.pack(padx=1, pady=0, ipadx=20, ipady=7, side=tk.LEFT)
        self.button_decode = tk.Button(self.frame1, text="解密", command=self.decode_deal)
        self.button_decode.pack(padx=1, pady=0, ipadx=20, ipady=7,side=tk.LEFT)
        self.frame1.place(relx=0, rely=0.05, relwidth=1, relheight=0.1)

        # 设置字符编码
        self.var = tk.IntVar()

        self.frame2= tk.Frame(self)
        #单选框，字符集编码选择
        for i in range(len(self.character_encode)):
            self.redio_coding_1 = tk.Radiobutton(self.frame2, text=self.character_encode[i], variable=self.var,
                                                 value=i, command=self.judge_coding)
            self.redio_coding_1.pack(padx=10, pady=10,ipadx=20,ipady=5,side=tk.LEFT)
        self.frame2.place(relx=0, rely=0.15, relwidth=1, relheight=0.07)


        if self.choose_base_url == 1:
            self.frame3 = tk.Frame(self)
            self.lb_url = tk.Label(self.frame3, text="是否加密英文数字")
            self.lb_url.pack(padx=10, pady=10,ipadx=20,ipady=5,side=tk.LEFT)

            # 设置字符编码
            # 设置转换进制选择
            self.var2 = tk.IntVar()
            for var_i in range(len(self.base_encode)-1):
                self.base_coding_1 = tk.Radiobutton(self.frame3, text=self.base_encode_url[var_i], variable=self.var2,
                                                    value=var_i,
                                                    command=self.judge_base_url)
                self.base_coding_1.pack(padx=10, pady=0, ipadx=20, ipady=10, side=tk.LEFT)

        elif self.choose_encode_ascii == 1:
            self.frame3 = tk.Frame(self)
            # 设置字符编码

            # 设置转换进制选择
            self.var1= tk.IntVar()
            for var_i in range(len(self.base_encode)):

                if var_i==1:
                    pass
                else:
                    self.base_coding_1 = tk.Radiobutton(self.frame3, text=self.base_encode[var_i], variable=self.var1,
                                                        value=var_i,command=self.judge_base)
                    self.base_coding_1.pack(padx=10, pady=0, ipadx=20, ipady=10, side=tk.LEFT)


        else:
            self.frame3 = tk.Frame(self)
        # self.lb5= tk.Label(self.frame3, text="进制选择：默认16进制")
        # self.lb5.pack(padx=10, pady=0,ipadx=20,ipady=10,side=tk.LEFT)

        # 设置字符编码
            #设置转换进制选择
            self.var1 = tk.IntVar()
            for var_i in range(len(self.base_encode)-1):
                self.base_coding_1 = tk.Radiobutton(self.frame3, text=self.base_encode[var_i], variable=self.var1, value=var_i,
                                                    command=self.judge_base)
                self.base_coding_1.pack(padx=10, pady=0,ipadx=20,ipady=10,side=tk.LEFT)

        self.frame3.place(relx=0, rely=0.2, relwidth=1, relheight=0.05)



     #url分割显示控件
    def url_show(self):
        self.entry_url = tk.Entry(self)
        self.entry_url.place(relx=0.1, rely=0.1, relwidth=0.5, relheight=0.05)
        self.button_url = tk.Button(self, text="提交", command=self.url_deal)
        self.button_url.place(relx=0.6, rely=0.1, relwidth=0.15, relheight=0.05)
        # self.button_decode = tk.Button(self, text="解密", command=self.decode_deal)
        # self.button_decode.place(relx=0.75, rely=0.1, relwidth=0.15, relheight=0.05)
        if self.choose_urldic == 1:
            self.frame3 = tk.Frame(self)
            self.lb_url = tk.Label(self.frame3, text="请选择语言")
            self.lb_url.pack(padx=10, pady=10, ipadx=20, ipady=5, side=tk.LEFT)

            # 设置字符编码
            # 设置转换进制选择
            self.var2 = tk.IntVar()
            for var_i in range(len(self.url_dictionary)):
                self.base_coding_1 = tk.Radiobutton(self.frame3, text=self.url_dictionary[var_i], variable=self.var2,
                                                    value=var_i,
                                                    command=self.judge_urldic)
                self.base_coding_1.pack(padx=10, pady=0, ipadx=20, ipady=10, side=tk.LEFT)
            self.choose_urldic = 0
            self.frame3.place(relx=0, rely=0.2, relwidth=1, relheight=0.05)

    def fruzz_show(self):
        self.entry_url = tk.Entry(self)
        self.entry_url.place(relx=0.1, rely=0.1, relwidth=0.5, relheight=0.05)
        self.button_url = tk.Button(self, text="提交", command=self.url_deal)
        self.button_url.place(relx=0.6, rely=0.1, relwidth=0.15, relheight=0.05)

    # 设置字符编码
    def judge_base(self):
        self.base_info = self.base_encode[self.var1.get()]


    # 设置字符编码
    def judge_coding(self):
        self.choose_base = 1
        self.encode_info = self.character_encode[self.var.get()]

    #url是否加密英文数字
    def judge_base_url(self):
        self.choose_encode_url = self.base_encode_url[self.var2.get()]
    #选择编程语言
    def judge_urldic(self):
        self.url_dictionary_info = self.url_dictionary[self.var2.get()]
    '''
    页面跳转的判断设置
    '''


     #首页
    def index_main(self):
        self.choose_base = 0
        self.choose_url=0
        self.choose_base_url = 0
        self.choose_encode_ascii=0
        self.choose=1
        self.main()


    # 设置url编码
    def url_code(self):
        self.lb.config(text='URL')
        self.choose_base = 1
        self.choose_base_url = 1
        self.choose_encode_ascii = 0
        self.choose_url = 0
        self.judge_show()
        self.type_info = "url"

    def len_judge(self):
        self.lb.config(text='JUDGE')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.type_info = "judge"

    # 设置base64编码
    def base64_code(self):
        self.lb.config(text='BASE64')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.type_info = "base64"
    def base32_code(self):
        self.lb.config(text='BASE32')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.type_info = "base32"
    def base16_code(self):
        self.lb.config(text='BASE16')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.type_info = "base16"
    #
    def html_code(self):
        self.lb.config(text='HTML实体')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.type_info = "html"


    # 设置ascii编码
    def ascii_code(self):
        self.lb.config(text='ASCII')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 1
        self.judge_show()
        self.type_info = "ascii"

    # 设置sha1编码
    def sha1_code(self):
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.lb.config(text='SHA1')
        self.type_info = "sha1"
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, "不可逆")

    def sha256_code(self):
        self.lb.config(text='SHA256')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.type_info = "sha256"
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, "不可逆")


    def md5_code(self):
        self.lb.config(text='MD5')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.type_info = "md5"
        self.text_info.delete(1.0, tk.END)       #清空文本框
        self.text_info.insert(tk.END, "不可逆")   #添加信息
    def seeyon_code(self):
        self.lb.config(text='seeyon')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.type_info = "seeyon"
        self.text_info.delete(1.0, tk.END)       #清空文本框
        self.text_info.insert(tk.END, "不可逆")   #添加信息
    def auto_(self):
        self.lb.config(text='Auto')
        self.choose_base = 1
        self.choose_url = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.judge_show()
        self.type_info = "Auto"
        self.text_info.delete(1.0, tk.END)       #清空文本框
        self.text_info.insert(tk.END, "不可逆")   #添加信息
    def domain_deal(self):
        self.lb.config(text='URL分解')
        self.choose_base = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.choose_url=1
        self.choose_urldic = 0
        self.judge_show()
        self.type_info = "domain_deal"
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, "协议，域名，文件路径 ")
    #目录扫描
    def urldic_scan(self):
        self.lb.config(text='文件目录扫描')
        self.choose_base = 0
        self.choose_base_url = 0
        self.choose_encode_ascii = 0
        self.choose_url = 1
        self.choose_urldic=1
        self.judge_show()
        self.type_info = "urldic_scan"
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, "成功的将保存在默认目录下../temp/ ")
    # 加密处理
    def encode_deal(self):
        try:
            self.data_info = self.entry_encode.get()  # 获取提交的数据
            if self.type_info == "base64":  # 如果是base64加密
                self.data_info = base64.b64encode(self.data_info.encode(self.encode_info))
            elif self.type_info == "base32":  # 如果是base64加密
                self.data_info = base64.b32encode(self.data_info.encode(self.encode_info))
            elif self.type_info == "base16":  # 如果是base64加密
                self.data_info = base64.b16encode(self.data_info.encode(self.encode_info))
            elif self.type_info == "url":
                #self.data_info = parse.quote(self.data_info, encoding=self.encode_info)
                strOut = ''
                if self.choose_encode_url=='yes':
                    for c in self.data_info:
                        ch = "".join("{:02x}".format(ord(c)))
                        strOut += "%" + ch
                    self.data_info=strOut
                else:
                    self.data_info = parse.quote(self.data_info, encoding=self.encode_info)

            elif self.type_info == "ascii":
                data_temp = ""
                if self.base_info == "16进制":
                    for c in self.data_info:
                        ch = "".join("{:02x}".format(ord(c)))
                        data_temp += ch
                    data_temp='0x'+str(data_temp)
                elif self.base_info == "10进制":
                    for i in range(len(self.data_info)):
                        temp= ord(self.data_info[i:i + 1])
                        data_temp += str(temp)
                self.data_info=data_temp
            elif self.type_info=='html':
                self.data_info=html.escape(self.data_info)
            elif self.type_info == 'seeyon':
                # print(self.data_info)
                self.data_info = self.base64_encode_seeyon(self.data_info.encode(self.encode_info))
            elif self.type_info == "sha1":
                self.sha1_temp = hashlib.sha1()  # 选择需要的加密方式
                self.sha1_temp.update(self.data_info.encode(self.encode_info))  # 对需要加密的数据进行加密
                if self.base_info=="2进制":
                    self.data_info = self.sha1_temp.digest()  # 获取加密值，返回二进制数据字符串值
                elif self.base_info == "16进制":
                    self.data_info = self.sha1_temp.hexdigest()  # 获取加密值，返回十六进制数据字符串值

            elif self.type_info == "sha256":
                self.sha256_temp = hashlib.sha256()  # 选择需要的加密方式
                self.sha256_temp.update(self.data_info.encode(self.encode_info))  # 对需要加密的数据进行加密
                if self.base_info == "2进制":
                    self.data_info = self.sha256_temp.digest()  # 获取加密值，返回二进制数据字符串值
                elif self.base_info == "16进制":
                    self.data_info = self.sha256_temp.hexdigest()  # 获取加密值，返回十六进制数据字符串值

            elif self.type_info == "md5":
                self.md5_temp = hashlib.md5()  # 选择需要的加密方式
                self.md5_temp.update(self.data_info.encode(self.encode_info))  # 对需要加密的数据进行加密
                if self.base_info == "2进制":
                    self.data_info = self.md5_temp.digest()  # 获取加密值，返回二进制数据字符串值
                elif self.base_info == "16进制":
                    self.data_info = self.md5_temp.hexdigest()  # 获取加密值，返回十六进制数据字符串值

            else:
                pass
        except Exception as e:
            self.data_info = "提交错误，请重试！"
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, self.data_info)


    # 解密处理
    def decode_deal(self):
        try:
            self.data_info = self.entry_encode.get()  # 获取提交的数据
            if self.type_info == "base64":
                self.data_info = base64.b64decode(self.data_info).decode(self.encode_info)
            elif self.type_info == "base32":
                self.data_info = base64.b32decode(self.data_info).decode(self.encode_info)
            elif self.type_info == "base16":
                self.data_info = base64.b16decode(self.data_info).decode(self.encode_info)
            elif self.type_info == "Auto":  # 如果是Auto
                payload = fist_(self.data_info)
                num=1
                try:
                    for i in range(num):
                        payload = fist_(payload)
                except:
                    pass
                self.data_info =payload
            elif self.type_info == "url":

                strOut = ''
                # if self.choose_encode_url == 'yes':
                #     temp_info = re.sub('%', ',0x', self.data_info)
                #     list1 = list(re.split(',', temp_info))
                #     list1.pop(0)
                #     for c in list1:
                #         ch = chr(int(c, 16))
                #         strOut += ch
                #     self.data_info = strOut
                # else:
                #     data_all = re.sub('%\w\w', ',%#%', self.data_info)     #正则匹配
                #     list1 = re.split(',%#', data_all)
                #     for a in list1:
                #         s = re.search('%', a)
                #         if s is not None:
                #             w = parse.unquote(a[:3],  encoding=self.encode_info)
                #             strOut += w
                #             strOut += a[3:]
                #
                #         else:
                #             pass
                #             strOut += a
                    # self.data_info = parse.quote(self.data_info, encoding=self.encode_info)
                self.data_info = parse.unquote(self.data_info, encoding=self.encode_info)

            elif self.type_info == "ascii":
                data_temp = ""

                if self.base_info == "16进制":
                    a=re.findall('(0x\d\d)+',self.data_info)     #未完成，判断0x3131  0x310x31

                    for i in range(len(self.data_info) // 2):
                        i = i * 2
                        data_temp+=',0x'+self.data_info[i:i + 2]
                    list1 = list(re.split(',', data_temp))
                    list1.pop(0)
                    data_temp=""
                    for c in list1:
                        ch = chr(int(c, 16))
                        data_temp += ch
                elif self.base_info == "10进制":
                    for i in range(len(self.data_info) // 2):
                        i = i * 2
                        b = chr(int(self.data_info[i:i + 2]))
                        data_temp += str(b)
                self.data_info = data_temp
            elif self.type_info == 'html':

                self.data_info =html.unescape(self.data_info)
            elif self.type_info == 'seeyon':
                self.data_info = self.base64_decode_seeyon(self.data_info)
            elif self.type_info == "sha1":
                pass
            elif self.type_info == "sha256":
                pass
            elif self.type_info == "md5":
                pass
            elif self.type_info=='judge':
                self.data_info = len(self.data_info)
                if self.data_info == 32:
                    self.data_info = str(self.data_info) + "个字符，可能是md5加密"
                elif self.data_info == 16:
                    self.data_info = str(self.data_info) + "个字符，可能是md5加密"
                elif self.data_info == 40:
                    self.data_info = str(self.data_info) + "个字符，可能是sha1加密"
                elif self.data_info == 64:
                    self.data_info = str(self.data_info) + "个字符，可能是sha256加密"
                else:
                    self.data_info = str(self.data_info) + "个字符"
        except Exception as e:
            self.data_info = "提交错误，请重试！"
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, self.data_info)
    #扫描设置，会崩溃
    def dicfile_scan(self,data_all1,dic, dic_type):
        headers={"referer":data_all1,
                 "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.10 Safari/537.36"}
        scan_file = "file/temp/" + dic_type + '.txt'
        for i in range(len(dic)):
            url = data_all1 + dic[i]
            # print(url)

            respone = requests.get(url,timeout=1)
            if (respone.status_code == 200 or respone.status_code == 403):
                with open(scan_file, "a+") as file:
                    file.write(url + "\n")
                print(url)
                self.text_info.delete(1.0, tk.END)
                self.text_info.insert(tk.END, url)

            time.sleep(0.3)




    def url_deal(self):
        self.data_info = self.entry_url.get()  # 获取提交的数据

        data_all1 = re.search(r'((http|https)://)', self.data_info)
        if data_all1 is not None:
            data_all= self.data_info
        else:
            #设置协议
            data_all = "http://" + self.data_info
        temp = list(parse.urlparse(data_all))

        url_resolve=""
        try:
            for i in range(6):
                url_resolve+=(self.url_info[i]+temp[i]+'\n')
        except Exception as e:
            url_resolve="格式不正确，请输入如：http://xxx.xxx.xxx/xxxx.php"

        #域名扫描
        if self.type_info == "domain_deal":
            self.data_info=url_resolve
            self.text_info.delete(1.0, tk.END)
            self.text_info.insert(tk.END, self.data_info)

        #文件目录扫描
        elif self.type_info == "urldic_scan":
            dic = data_all[-1]
            dic_len = len(data_all) - 1
            if dic is '/':
                data_all1 = data_all[0:dic_len]
            else:
                data_all1 = data_all
            choose_file=self.url_dictionary_info

            choose_file="file/dictionary/"+choose_file+".txt"
            page = []
            dic_enum = []
            file_scan =self.url_dictionary_info
            dic_scan = "dir"
            print(data_all1)
            try:
                with open("file/dictionary/DIR.txt", "r") as f:
                    for line in f:
                        line = line.strip('\n')
                        dic_enum.append(line)
                print(dic_enum)
                with open(choose_file, "r") as f:
                    for line in f:
                        line = line.strip('\n')
                        page.append(line)
            except Exception as e:
                url_resolve = "字典不存在"
            #threading.Thread(target=self.dicfile_scan(data_all1,dic_enum, dic_scan)).start()
            threading.Thread(target=self.dicfile_scan(data_all1,page, file_scan)).start()

    def base64_encode_seeyon(self,data):
        # 初始化编码结果

        encoded = []
        padding = 0
        print(data)
        # 将字节数据转换为整数列表
        bytes_data = [byte for byte in data]
        print(bytes_data)
        # 处理每三个字节
        for i in range(0, len(bytes_data) - padding, 3):
            # 将三个字节合并为24位的整数
            bits = (bytes_data[i] << 16) + (bytes_data[i + 1] << 8) + bytes_data[i + 2]
            # 将24位整数转换为4个6位的组
            for j in range(4):
                if i * 8 + j * 6 <= len(data) * 8:
                    encoded.append(self.BASE64_CHARS[(bits >> (18 - j * 6)) & 0x3F])
                else:
                    encoded.append('=')
        print(encoded)
        print(''.join(encoded))
        return ''.join(encoded)

    def base64_decode_seeyon(self,encoded):
        # 移除填充字符
        encoded = encoded.rstrip('=')
        # print(encoded)
        # 初始化解码结果
        decoded = bytearray()
        bits = 0
        bits_count = 0
        # print("test")
        # 处理每个Base64字符
        for char in encoded:
            # print(char)
            # 将字符转换为6位的整数
            value = self.BASE64_CHARS.index(char)
            bits = (bits << 6) + value
            bits_count += 6

            # 当有8位有效位时，提取一个字节
            if bits_count >= 8:
                bits_count -= 8
                decoded.append((bits >> bits_count) & 0xFF)
        # print(decoded)
        return bytes(decoded)




if __name__ == '__main__':
    root = test()
    root.mainloop()


