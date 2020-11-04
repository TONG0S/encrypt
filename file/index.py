import tkinter as tk
import base64
from urllib import request, parse
import hashlib

'''
未完成
可以添加从文件中读取
产生随机数？
一键复制
按钮保存到临时存储中  （添加对比字符串）
md5彩虹表            (爬虫之后做)
ascii 16进制转换
md5 16位（2进制转换)
进制转换  原本进制（单选 var.get() 获取）  目标进制（单选)


'''
class test(tk.Tk):

    def __init__(self):
        super().__init__()         #需要继承tk
        self.title("加密解密")
        self.geometry("700x700")
        self.type_info = ""  # 设置编码类型
        self.character_encode = ["utf-8", 'gbk']  # 设置字符编码列表
        self.encode_info = "utf-8"  # 设置字符编码
        self.base_encode = ["16进制", '2进制']  # 设置进制列表
        self.base_encode_2 = ["16进制", '2进制']  # 设置进制列表
        self.base_info = "16进制"  # 设置进制编码
        self.url_info = ["协议:  ", "域名: ", "路径: ", "参数: ", "查询: ", " "]  # 设置进制编码
        self.choose_base = 0  # 是否是加密列表
        self.choose_url = 0  # 是否是url处理列表
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
        self.mainfile.add_command(label="MD5", command=self.md5_code)
        self.mainfile.add_command(label="URL", command=self.url_code)  # 创建二级菜单
        self.mainfile.add_command(label="BASE64", command=self.base64_code)
        self.mainfile.add_command(label="ASCII", command=self.ascii_code)
        self.mainfile.add_command(label="SHA1", command=self.sha1_code)
        self.mainfile.add_command(label="SHA256", command=self.sha256_code)
        self.mainfile.add_command(label="MD5", command=self.md5_code)
        self.config(menu=self.mainmenu)

        self.urlfile = tk.Menu(self.mainmenu, tearoff=0, foreground="white", bg="black")  # 实例化一个菜单
        self.mainmenu.add_cascade(label="URL", menu=self.urlfile)
        self.urlfile.add_command(label="url处理", command=self.domain_deal)  # 创建二级菜单
        self.urlfile.add_command(label="保存", command=self.url_code)  # 创建二级菜单
        self.urlfile.add_command(label="打开", command=self.base64_code)

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
        if self.choose_base==1:
            self.temp()
        elif self.choose_url==1:
            self.url_show()
        elif self.choose==1:
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
        # if self.choose_base == 1:

        self.frame3 = tk.Frame(self)
        self.lb5 = tk.Label(self.frame1, text="进制选择：默认16进制")
        self.lb5.pack(padx=20, pady=50,ipadx=20,ipady=10)

        # 设置字符编码
        #设置转换进制选择
        self.var1 = tk.IntVar()
        for var_i in range(len(self.base_encode)):
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



    # 设置字符编码
    def judge_base(self):
        self.base_info = self.base_encode[self.var1.get()]


    # 设置字符编码
    def judge_coding(self):
        self.choose_base = 1
        self.encode_info = self.character_encode[self.var.get()]

    '''
    页面跳转的判断设置
    '''


     #首页
    def index_main(self):
        self.choose_base = 0
        self.choose_url=0
        self.choose=1
        self.main()


    # 设置url编码
    def url_code(self):
        self.lb.config(text='URL')
        self.choose_base = 1
        self.choose_url = 0
        self.judge_show()
        self.type_info = "url"

    def len_judge(self):
        self.lb.config(text='JUDGE')
        self.choose_base = 1
        self.choose_url = 0
        self.judge_show()
        self.type_info = "judge"

    # 设置base64编码
    def base64_code(self):
        self.lb.config(text='BASE64')
        self.choose_base = 1
        self.choose_url = 0
        self.judge_show()
        self.type_info = "base64"



    # 设置ascii编码
    def ascii_code(self):
        self.lb.config(text='ASCII')
        self.choose_base = 1
        self.choose_url = 0
        self.judge_show()
        self.type_info = "ascii"

    # 设置sha1编码
    def sha1_code(self):
        self.choose_base = 1
        self.choose_url = 0
        self.judge_show()
        self.lb.config(text='SHA1')
        self.type_info = "sha1"
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, "不可逆")

    def sha256_code(self):
        self.lb.config(text='SHA256')
        self.choose_base = 1
        self.choose_url = 0
        self.judge_show()
        self.type_info = "sha256"
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, "不可逆")


    def md5_code(self):
        self.lb.config(text='MD5')
        self.choose_base = 1
        self.choose_url = 0
        self.judge_show()
        self.type_info = "md5"
        self.text_info.delete(1.0, tk.END)       #清空文本框
        self.text_info.insert(tk.END, "不可逆")   #添加信息

    def domain_deal(self):
        self.lb.config(text='URL分解')
        self.choose_base = 0
        self.choose_url=1
        self.judge_show()
        self.type_info = "domain_deal"
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, "协议，域名，文件路径 ")

    # 加密处理
    def encode_deal(self):
        try:
            self.data_info = self.entry_encode.get()  # 获取提交的数据
            if self.type_info == "base64":  # 如果是base64加密
                self.data_info = base64.b64encode(self.data_info.encode(self.encode_info))

            elif self.type_info == "url":
                self.data_info = parse.quote(self.data_info, encoding=self.encode_info)

            elif self.type_info == "ascii":
                data_temp = ""
                for i in range(len(self.data_info)):
                    temp= ord(self.data_info[i:i + 1])
                    data_temp += str(temp)
                self.data_info=data_temp

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
            elif self.type_info == "url":
                self.data_info = parse.unquote(self.data_info, encoding=self.encode_info)
            elif self.type_info == "ascii":
                data_temp = ""
                for i in range(len(self.data_info) // 2):
                    i = i * 2
                    b = chr(int(self.data_info[i:i + 2]))
                    data_temp += str(b)

                self.data_info = data_temp
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

    def url_deal(self):
        self.data_info = self.entry_url.get()  # 获取提交的数据
        temp = list(parse.urlparse(self.data_info))

        url_resolve=""
        try:
            for i in range(6):
                url_resolve+=(self.url_info[i]+temp[i]+'\n')
        except Exception as e:
            url_resolve="格式不正确，请输入http://www.xxx.com/index.php"
        self.data_info=url_resolve
        self.text_info.delete(1.0, tk.END)
        self.text_info.insert(tk.END, self.data_info)


if __name__ == '__main__':
    root = test()
    root.mainloop()


