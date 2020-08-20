# -*- coding: utf-8 -*-
#author:ja0k@SecurityCN

import os,io
import sys
import re
import time
from datetime import datetime

localtime= datetime.now().strftime("%Y%m%d%H%M%S")

rulelist = [
'(\$_(GET|POST|REQUEST)\[.{0,15}\]\s{0,10}\(\s{0,10}\$_(GET|POST|REQUEST)\[.{0,15}\]\))',
'(base64_decode\([\'"][\w\+/=]{200,}[\'"]\))',
'(eval(\s|\n)*\(base64_decode(\s|\n)*\((.|\n){1,200})',
'((eval|assert)(\s|\n)*\((\s|\n)*\$_(POST|GET|REQUEST)\[.{0,15}\]\))',
'(\$[\w_]{0,15}(\s|\n)*\((\s|\n)*\$_(POST|GET|REQUEST)\[.{0,15}\]\))',
'(call_user_func\(.{0,15}\$_(GET|POST|REQUEST))',
'(preg_replace(\s|\n)*\(.{1,100}[/@].{0,3}e.{1,6},.{0,10}\$_(GET|POST|REQUEST))',
'(wscript\.shell)',
'(cmd\.exe)',
'(powershell)',
'(/usr/bin)',
'(bash)',
'(shell\.application)',
'(documents\s+and\s+settings)',
'(system32)',
'(serv-u)',
'(phpspy)',
'(netspy)',
'(hack)',
'(jspspy)',
'(webshell)',
'(Program\s+Files)',
]

def Scanfile(filepath):
    lastmodifytime = datetime.fromtimestamp(os.path.getmtime(filepath))
    #print(lastmodifytime)
    if filepath.find(u'.') != -1:
        _ext = filepath[(filepath.rindex(u'.')+1):].lower()
        if 'php' in _ext  or 'jsp' in _ext  or 'asp' in _ext  or 'cer' in _ext  or  'asa' in _ext:
            try:
                file = io.open(filepath,'r',encoding="gbk")
            except  e as Exception:
                file = io.open(filepath,'r',encoding="utf-8")
                
            filestr = file.read()
             #print(filestr)
            # file.close()
            for rule in rulelist:
                result = re.compile(rule).findall(filestr)
                #print(result)
                if result:
                    print(u'file:'+filepath)
                    print(u'evilcode:'+str(result[0])[0:200])
                    print(u'lastmodifytime：'+str(lastmodifytime))
                    print(u'\n\n')
                    break # find a evil function to find the shell. If you want to traverse all functions, please comment this line
        else:
            pass



def Scandir(dirname):

    print(u'################################')
    for root,dirs,files in os.walk(dirname):
        for filespath in files:
            filepath = root+filespath
            Scanfile(filepath)

def _Get_starttime_Files(_path,_starttime,_endtime):
    # _starttime = time.mktime(time.strptime(_starttime,'%Y-%m-%d %H:%M:%S'))
    _starttime = time.mktime(time.strptime(_starttime,'%Y%m%d%H%M%S'))
    _endtime  = time.mktime(time.strptime(_endtime,'%Y%m%d%H%M%S'))
    print(u'\n') 
    print(u'#############################')

    for _root,_dirs,_files in os.walk(_path):
        for _file in _files:
            _File_starttime = os.path.getmtime(_root+'/'+_file)
            if _endtime > _File_starttime > _starttime:
                path=_root+_file
                #print(path+' '+ localtime)
                if os.path.isfile(path):
                    Scanfile(path)
                else:
                    Scandir(path)


if len(sys.argv) != 4 and len(sys.argv) != 3 and len(sys.argv) != 2:
    print(u'arg error：')
    print(u'\tfile dir：'+sys.argv[0]+' dirname')
    print(u'\tmodifytime：'+sys.argv[0]+' dirname modifytime(format:"20190730 or  201907301120")')

if os.path.lexists(sys.argv[1]) == False:
    print(u'notice：the dirname is non-existent')
    print(u'\n\nstart detect：'+sys.argv[1])

if len(sys.argv) == 2:   
    path =  sys.argv[1]     
    if os.path.isfile(path):
        Scanfile(path)
    else:
        Scandir(path)
else:
    if len(sys.argv) == 3:
        _starttime = str(sys.argv[2]).ljust(12,'0') 
        _endtime =  (time.strftime("%Y%m%d%H%M%S", time.localtime()))
        #print(_endtime)
    if len(sys.argv) == 4:
        _starttime = str(sys.argv[2]).ljust(12,'0') 
        _endtime = str(sys.argv[3]).ljust(12,'0')

    _Get_starttime_Files(sys.argv[1],_starttime,_endtime)

print(u'notice：detect over!')