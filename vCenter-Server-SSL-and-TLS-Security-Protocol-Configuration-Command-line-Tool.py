#!/usr/bin/env python
# Copyright (c) 2015
# Author : Ajay Ahire, Mohan Bollu
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
#     The above copyright notice and this permission notice shall be
#     included in all copies or substantial portions of the Software.
#
#     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
#     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
#     OTHER DEALINGS IN THE SOFTWARE.

import os
import re
import shutil
import xml.etree.ElementTree as ET
import mmap
import time
import subprocess
import sys
if os.name == 'nt':
    from _winreg import *

VAMI_bak=None
syslog_bak=None
ngc_server_xml_bak=None
vpxd_bak=None
is_config_bak=None
tc_bak=None
sps_spring_config_bak=None
xdb_config_bak=None
def reg_query():
    global HKLM
    global p_data
    global hash
    HKLM="\"HKEY_LOCAL_MACHINE\\"
    p_data = subprocess.check_output("echo %ProgramData%",shell=True)
    p_data=p_data.strip(' \t\n\r')
    hash={
          #'sts_7444':{'reg':'SOFTWARE\VMware, Inc.\VMware Infrastructure\SSOServer', 'installed':'', 'path':p_data+"\\VMware\\CIS\\runtime\\VMwareSTS\\conf\\", 'port':'', 'name':"STS"},
          #'vmdir':{'reg':'SOFTWARE\VMware, Inc.\VMware Directory Services', 'installed':'', 'path':'', 'port':'', 'name':"VMDIR"},
          'tc_8443':{'reg':'SOFTWARE\VMware, Inc.\VMware Infrastructure\Web Server', 'installed':'', 'path':'', 'port':'', 'name':"Management Web ", 'svc_name':'vctomcat'},
	      'xdb_10109':{'reg':'SOFTWARE\VMware, Inc.\VMware Infrastructure\Inventory Service', 'installed':'', 'path':'', 'port':'', 'name': 'Inventory Service XDB', 'svc_name':''},
          'invsvc_10443':{'reg':'SOFTWARE\VMware, Inc.\VMware Infrastructure\Inventory Service', 'installed':'', 'path':'', 'port':'', 'name':"Inventory" , 'svc_name':'vimQueryService'},
	      'sps_21100_31100':{'reg':'SOFTWARE\VMware, Inc.\VMware Infrastructure\Profile-Driven Storage', 'installed':'', 'path':'', 'port':'', 'name':'SPS', 'svc_name':'vimPBSM'},
	      'ngc_client_9443':{'reg':'SOFTWARE\VMware, Inc.\VMware Infrastructure\VMware Web Client', 'installed':'', 'path':'', 'port':'', 'name':'vSphere Web Client', 'svc_name':'vspherewebclientsvc'},
	      'vpx_443':{'reg':'SOFTWARE\VMware, Inc.\VMware VirtualCenter', 'installed':'', 'path':p_data+"\\VMware\\VMware VirtualCenter\\", 'port':'', 'name':'VPXD', 'svc_name':'vpxd'},
	      'syslog_1514':{'reg':None, 'installed':'', 'path':p_data+"\\VMware\\VMware Syslog Collector\\", 'port':'1514', 'name':'Syslog', 'svc_name':'vmware-syslog-collector'},
              'jre':{'reg':'SOFTWARE\VMware, Inc.\VMware Infrastructure\JRE\VIM_JRE', 'installed':'', 'path':'', 'port':'', 'name':'jre','svc_name':''},
              'jre_ngc':{'reg':'SOFTWARE\VMware, Inc.\VMware Infrastructure\JRE\JRE_SERENITY', 'installed':'', 'path':'', 'port':'', 'name':'jre_ngc', 'svc_name':''}
	     }
    if os.path.exists(hash['syslog_1514']['path'])==True:
        hash['syslog_1514']['installed']="yes"
        # get the port number form config file
        syslog_conf = hash['syslog_1514']['path'] + "vmconfig-syslog.xml"
        tree = ET.parse(syslog_conf)
        root = tree.getroot()
        for child in root.findall('defaultValues'):
            hash['syslog_1514']['port'] = child.find('sslPort').text
    for service in ["tc_8443", "vpx_443", "invsvc_10443", "xdb_10109","sps_21100_31100", "ngc_client_9443", "jre", "jre_ngc"]:
        try:
            reg=ConnectRegistry(None, HKEY_LOCAL_MACHINE)
            k=OpenKey(reg, hash[service]['reg'])
            hash[service]['installed']="yes"
            hash[service]['reg']=HKLM+hash[service]['reg']+"\""
        except:
            hash[service]['installed']="no"
        if hash[service]['installed']=="yes":
            if service not in ["vpx_443", "syslog_1514"]:
                reg_query_path_cmd="reg query "+hash[service]['reg']+" /v InstallPath"
                out=subprocess.check_output(reg_query_path_cmd,shell=True)
                start=out.index(":")
                hash[service]['path']=out[start-1:].strip(' \t\n\r')
            if service=="xdb_10109":
                reg_query_port_cmd="reg query "+hash['vpx_443']['reg']+"\Install /v QSXdbPort"
            elif service=="invsvc_10443":
                reg_query_port_cmd="reg query "+hash['vpx_443']['reg']+"\Install /v QSHttpsPort"
            elif service=="sps_21100_31100":
                reg_query_port_cmd="reg query "+hash['vpx_443']['reg']+"\Install /v SPSHttpsPort"
            elif service=="vpx_443":
                reg_query_port_cmd="reg query "+hash[service]['reg']+" /v HttpsProxyPort"
            elif service!="jre" and service!="jre_ngc":
                reg_query_port_cmd="reg query "+hash[service]['reg']+" /v HttpsPort"
            out=subprocess.check_output(reg_query_port_cmd,shell=True)
            port=[int(s) for s in out.split() if s.isdigit()]
            hash[service]['port']=str(port[0]).strip(' \t\n\r')
    #for service in ["pbm_8191", "sps_22100_32100"]:
        #hash[service]['installed']=hash["sps_21100_31100"]['installed']
        #hash[service]['path']=hash["sps_21100_31100"]['path']

def logger(msg, trail):
    if log_type == 'print' and trail == '1':
        print msg,
    elif log_type == 'print' and trail == '0':
        print msg
    else:
        #print to file
        exit(0)

def create_backup (source_file,target_file):
    global result
    result=0
    logger("| Taking backup of file", "1")
    logger(source_file, "1")
    logger( "as", "1")
    logger(target_file, "1")
    try:
        shutil.copyfile(source_file,target_file)
        result |= 0
    except IOError as e:
        logger(e,"0")
        result |= 1
    if result == 0:
        logger("done.\n", "0")
    else:
        logger("Failed to take backup", "0")

def subprocess_execute(command, time_out=4):

    p = subprocess.Popen(command, shell=True)
    i = 0
    while i < time_out and p.poll() is None:
        #wait for 2 secs to complete
        time.sleep(1)
        i += 1
    if p.poll() is None:
        # took more than 2secs -> assuming protocol is enabled
        p.terminate()
        returncode = 0
    else:
        # process completed, assuming protocol is disabled
        returncode = 1
    return returncode

def ssl_scan(do_print):
    if do_print == "yes":
        logger("Scanning vCenter Server ports..", "1")
    tls_protocols = { "ssl3":"SSLv3", "tls1":"TLSv1" }
    global current_config
    global vsphere_ports
    dir_path = os.path.dirname(os.path.realpath(__file__))
    if (os.name == "nt"):
        vsphere_ports = { }
        current_config = { }
        # get list of services installed and respective ports
        for service in hash:
            if hash[service]['installed']=="yes" and service != 'jre' and service!="jre_ngc":
                if service == 'xdb_10109':
                   svc = hash['invsvc_10443']['svc_name']
                else:
                   svc = hash[service]['svc_name']
                status_cmd="sc query "+svc+" | find \"STATE\""
                if ((subprocess.check_output(status_cmd, shell=True)).find("RUNNING"))>0:
                    vsphere_ports[str(hash[service]['port'])] = str(hash[service]['name'])
                    current_config[str(hash[service]['port'])] = []
                elif do_print == "yes":
                    logger("\n"+hash[service]['name']+" is not running.","0")
        if os.path.exists(hash['jre']['path']) == True:
            jre_path = '\"'+hash['jre']['path']+ '\\bin\\java.exe\"'
        elif os.path.exists(hash['jre_ngc']['path']) == True:
            jre_path = '\"'+hash['jre_ngc']['path']+ '\\bin\\java.exe\"'
        else:
            logger("| Java is not available for scanning the ports! \nPlease use external SSL scanners for scanning the vCenter Server ports.", "0")
            exit(0)
        dir_path = dir_path +'\\ProtocolScanner.jar'
        if os.path.exists(dir_path) != True:
            logger("| ProtocolScanner.jar is not available for scanning the ports! \nPlease copy the jar file and python script in the same directory.", "0")
            exit(0)
        #vsphere_ports = { "1514":"Syslog", "9443":"vSphere Web Client", "443":"VPXD", "10443":"Inventory Service", "8443":"Management Web Service", "31100":"SPS", "10109":"Inventory Service XDB Port"  }
        #current_config = {"1514":[], "9443":[], "443":[], "10443":[], "8443":[], "31100":[], "10109":[]}
    else:
        vsphere_ports = { "5480":"VAMI", "1514":"Syslog", "9443":"vSphere Web Client", "443":"VPXD", "10443":"Inventory Service", "8443":"Management Web Service", "21100":"SPS", "10109":"Inventory Service xDB"  }
        current_config = { "5480":[], "1514":[], "9443":[], "443":[], "10443":[], "8443":[], "21100":[], "10109":[]}
        #openssl_path = '/usr/bin/openssl'
        jre_path = '/usr/lib/vmware-vpx/jre/bin/java'
        dir_path = dir_path +'/ProtocolScanner.jar'
        if os.path.exists(dir_path) != True:
            logger("| Java is not available for scanning the ports! \nPlease use external SSL scanners for scanning the vCenter Server ports.", "0")
            exit(0)
    for port,port_name in vsphere_ports.iteritems():
        if do_print == "yes":
            logger("\n| Protocols enabled on "+port_name+" port ("+port+"): ", "1")
        if (os.name == "nt"):
            cmd = jre_path+ ' -jar '+ dir_path +' localhost '+port
            result = subprocess.check_output(cmd, shell=True)
            matchobj = re.match(r'(.*)(Enabled Protocols:\[)(.*)(\])',result,re.I)
            list  = matchobj.group(3).split(",")
            if do_print == "yes":
                logger(','.join(list), "0")
            for l in list:
                current_config[port].append(l)
        else:
            cmd = jre_path+ ' -jar '+ dir_path +' localhost '+port + ' 2>/dev/null'
            cmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            for line in cmd.stdout:
                matchobj = re.match(r'(.*)(Enabled Protocols:\[)(.*)(\])',line,re.I)
                list  = matchobj.group(3).split(",")
                if do_print == "yes":
                    logger(','.join(list), "0")
                for l in list:
                    current_config[port].append(l)
    return current_config

def change_VAMI_5480_ssl(option):
    global VAMI_bak
    result=0
    if (os.name == "nt"):
        return 0
        #logger("NA","0")
    elif(os.name== "posix"):
        VAMI_lighttpd="/opt/vmware/etc/lighttpd/lighttpd.conf"
        VAMI_bak="/opt/vmware/etc/lighttpd/lighttpd-bak.conf"
        if option== '1':
            rep='ssl.use-sslv3 = "enable"'
        else:
            rep='ssl.use-sslv3 = "disable"'
        logger("| Configuring SSLv3 protocol for VAMI port (5480)...", "0")
        create_backup(VAMI_lighttpd,VAMI_bak)
        try:
            fh = open(VAMI_lighttpd, 'r')
            lines = fh.readlines()
            fh.close()
            match = 0
            for i in range(0,len(lines)):
                if re.match( r'.*ssl.use-sslv3\s*=.*', lines[i], re.I):
                    match = 1
                    lines[i] = re.sub(r".*ssl.use-sslv3\s*=.*", rep,lines[i])
                    break
            if match == 0:
                with open(VAMI_lighttpd, 'a+') as fh:
                    fh.write(rep)
                    fh.close()
            else:
                fh = open(VAMI_lighttpd, 'w')
                fh.writelines(lines)
                fh.close()
        except IOError as e:
            logger(e,"0")
            result |= 1
        if result == 0:
            logger("Successful.\n", "0")
        else:
            logger("failed.", "0")
            rollback('all')

def change_syslog_1514_ssl(option):
    global syslog_bak
    result=0
    flag=0
    if (os.name == "nt"):
        if hash["syslog_1514"]["installed"] != "yes":
            logger("| Syslog is not installed, skipping 1514 port!\n", "0")
            return(0)
        syslog_file = hash["syslog_1514"]["path"]+"vmconfig-syslog.xml"
        syslog_bak = hash["syslog_1514"]["path"]+"vmconfig-syslog-bak.xml"
        logger("| Configuring SSLv3 protocol for Syslog port ("+hash["syslog_1514"]["port"]+")...", "0")
        create_backup (syslog_file,syslog_bak)
        try:
            fh = open(syslog_file, 'r')
            lines = fh.readlines()
            fh.close()
            for i in range(0,len(lines)):
                if re.match(r'.*<disableSSLv3>\s*</disableSSLv3>.*',lines[i],re.I):
                    flag=1
                    if option== '1':
                        lines[i]=re.sub(r'<disableSSLv3>\s*</disableSSLv3>',"",lines[i])
                        break
            if option== '2':
                if not flag:
                    for i in range(0,len(lines)):
                        if re.match(r'.*<certificate>.*',lines[i],re.I):
                            lines.insert(i+1,"<disableSSLv3></disableSSLv3>")
                            lines.insert(i+2,"\n")
                            break
            fh = open(syslog_file, 'w')
            fh.writelines(lines)
            fh.close()
        except IOError as e:
            logger(e,"0")
            result |= 1
        if result == 0:
            logger("Successful.\n", "0")
        else:
            logger("failed.", "0")
            rollback('all')
    elif(os.name== "posix"):
        if option== '2':
            rep='\noptions = NO_SSLv3\n'
            rep1='.*options\s*=\s*NO_SSLv3'
        syslog_file="/etc/syslog-ng/stunnel.conf"
        syslog_bak="/etc/syslog-ng/stunnel-bak.conf"
        logger("| Configuring SSLv3 protocol for Syslog port (1514)...", "0")
        create_backup (syslog_file,syslog_bak)
        try:
            fh = open(syslog_file, 'r')
            lines = fh.readlines()
            fh.close()
            if option== '1':
                for i in range(0,len(lines)):
                    if re.match(r'options\s*=\s*NO_SSLv3',lines[i],re.I):
                        lines[i]=re.sub(r'options\s*=\s*NO_SSLv3',"",lines[i])
                        break
            else:
                with open(syslog_file,'a+') as f:
                    data=mmap.mmap(f.fileno(),0)
                    if not re.search(rep1,data):
                        for i in range(0,len(lines)):
                            if i==4:
                                lines[i]+=rep
                                break
            fh = open(syslog_file, 'w')
            fh.writelines(lines)
            fh.close()
        except IOError as e:
            logger(e,"0")
            result |= 1
        if result == 0:
            logger("Successful.\n", "0")
        else:
            logger("failed.", "0")
            rollback('all')

def change_webclients_9443_ssl(option):
    global ngc_server_xml_bak
    result=0
    if option== '1':
        rep='protocols="SSLv3,TLSv1"'
    else:
        rep='protocols="TLSv1"'
    if (os.name == "nt"):
        if hash["ngc_client_9443"]["installed"] != "yes":
           logger("| Web client is not installed, skipping 9443 port!\n", "0")
           return(0)
        install_path="reg query \"HKLM\SOFTWARE\VMware, Inc.\VMware Infrastructure\DMServer\VIM_DMServer\" /v InstallPath"
        out=subprocess.check_output(install_path,shell=True)
        start=out.index(":")
        install_path=out[start-1:].strip(' \t\n\r')
        ngc_server_xml = install_path+"\config\\tomcat-server.xml"
        ngc_server_xml_bak = install_path+"\config\\tomcat-server-bak.xml"
        logger("| Configuring SSLv3 protocol for vSphere Web Client port ("+hash["ngc_client_9443"]["port"]+")...", "0")
    elif(os.name== "posix"):
        ngc_server_xml="/usr/lib/vmware-vsphere-client/server/config/tomcat-server.xml"
        ngc_server_xml_bak="/usr/lib/vmware-vsphere-client/server/config/tomcat-server-bak.xml"
        logger("| Configuring SSLv3 protocol for vSphere Web Client port (9443)...", "0")
    create_backup (ngc_server_xml,ngc_server_xml_bak)
    try:
        fh = open(ngc_server_xml, 'r')
        lines = fh.readlines()
        fh.close()
        for i in range(0,len(lines)):
            if re.match(r'.*protocols.*',lines[i],re.I):
                lines[i]=re.sub(r'protocols\s*=\s*".*TLSv1"',rep,lines[i])
                break
        fh = open(ngc_server_xml, 'w')
        fh.writelines(lines)
        fh.close()
    except IOError as e:
        logger(e,"0")
        result |= 1
    if result == 0:
        logger("Successful.\n", "0")
    else:
        logger("failed.", "0")
        rollback('all')

def change_vpxd_443_ssl(option):
    global vpxd_bak
    result=0
    if option== '2':
        new_option = 50479104
    if (os.name == "nt"):
        if hash["vpx_443"]["installed"] != "yes":
           logger("| VPXD is not installed, skipping 443 port!\n", "0")
           return(0)
        vpxd_file = hash["vpx_443"]["path"]+"vpxd.cfg"
        vpxd_bak = hash["vpx_443"]["path"]+"vpxd-bak.cfg"
        logger("| Configuring SSLv3 protocol for VPXD port ("+hash["vpx_443"]["port"]+")...", "0")
    elif(os.name== "posix"):
        vpxd_file="/etc/vmware-vpx/vpxd.cfg"
        vpxd_bak="/etc/vmware-vpx/vpxd-bak.cfg"
        logger("| Configuring SSLv3 protocol for VPXD port (443)...", "0")
    create_backup (vpxd_file,vpxd_bak)
    try:
        if option== '2':
            tree = ET.parse(vpxd_file)
            root = tree.getroot()
            for child in root.findall('vmacore'):
                ssl = child.find('ssl')
                if ssl.find('sslOptions') is None:
                    new_child = ET.Element("sslOptions")
                    new_child.text = str(new_option)
                    ssl.insert(1, new_child)
                else:
                    ssl.find('sslOptions').text = str(new_option)
            tree.write(vpxd_file)
        else:
            fh = open(vpxd_file, 'r')
            lines = fh.readlines()
            fh.close()
            for i in range(0,len(lines)):
                if re.match(r'.*<sslOptions>.*',lines[i],re.I):
                    lines[i]=re.sub(r'<sslOptions>.*</sslOptions>',"",lines[i])
                    break
            fh = open(vpxd_file, 'w')
            fh.writelines(lines)
            fh.close()
    except IOError as e:
        logger(e,"0")
        result |= 1
    if result == 0:
        logger("Successful.\n", "0")
    else:
        logger("failed.", "0")
        rollback('all')

def change_inventory_10443_ssl(option):
    global is_config_bak
    result=0
    if option== '1':
        rep='value="SSLv3,TLSv1"'
    else:
        rep='value="TLSv1"'
    if (os.name == "nt"):
       if hash["invsvc_10443"]["installed"] != "yes":
           logger("| Inventory Service is not installed, skipping 10443 port!\n", "0")
           return(0)
       is_config_file = hash["invsvc_10443"]["path"]+"\\lib\\server\\config\\server-config.xml"
       is_config_bak = hash["invsvc_10443"]["path"]+"\\lib\\server\\config\\server-config-bak.xml"
    elif(os.name== "posix"):
        is_config_file="/usr/lib/vmware-vpx/inventoryservice/lib/server/config/server-config.xml"
        is_config_bak="/usr/lib/vmware-vpx/inventoryservice/lib/server/config/server-config-bak.xml"
    logger("| Configuring SSLv3 protocol for Inventory Service (10443)..", "0")
    create_backup (is_config_file,is_config_bak)
    try:
        fh = open(is_config_file, 'r')
        lines = fh.readlines()
        fh.close()
        for i in range(0,len(lines)):
            if re.match(r'.*<property.*enabledProtocols.*',lines[i],re.I):
                lines[i]=re.sub(r'value=".*TLSv1"',rep,lines[i])
                break
        fh = open(is_config_file, 'w')
        fh.writelines(lines)
        fh.close()
    except IOError as e:
        logger(e,"0")
        result |= 1
    if result == 0:
        logger("Successful.\n", "0")
    else:
        logger("failed.", "0")
        rollback('all')

def change_management_web_8443_ssl(option):
    global tc_bak
    result=0
    if option== '1':
        rep='sslProtocols="SSLv3,TLSv1'
    else:
        rep='sslProtocols="TLSv1'
    if (os.name == "nt"):
       if hash["tc_8443"]["installed"] != "yes":
          logger("| Tomcat Service is not installed, skipping 10443 port!\n", "0")
          return(0)
       tc_file = hash["tc_8443"]["path"]+"conf\\server.xml"
       tc_bak = hash["tc_8443"]["path"]+"conf\\server-bak.xml"
    elif(os.name== "posix"):
        tc_file="/usr/lib/vmware-vpx/tomcat/conf/server.xml"
        tc_bak="/usr/lib/vmware-vpx/tomcat/conf/server-bak.xml"
    logger("| Configuring SSLv3 protocol for vCenter Management Web port (8443)..", "0")
    create_backup (tc_file,tc_bak)
    try:
        fh = open(tc_file, 'r')
        lines = fh.readlines()
        fh.close()
        for i in range(0,len(lines)):
            if re.match(r'.*sslProtocols\s*=.*',lines[i],re.I):
                if re.match(r'.*sslProtocols\s*=\s*".*TLSv1,',lines[i],re.I):
                    lines[i]=re.sub(r'sslProtocols\s*=\s*".*TLSv1,',rep+",",lines[i])
                    break
                else:
                    lines[i]=re.sub(r'sslProtocols\s*=\s*".*TLSv1',rep,lines[i]) 
                    break
        fh = open(tc_file, 'w')
        fh.writelines(lines)
        fh.close()
    except IOError as e:
        logger(e,"0")
        result |= 1
    if result == 0:
        logger("Successful.\n", "0")
    else:
        logger("failed.", "0")
        rollback('all')

def change_sps_21100_31100_ssl(option):
    global sps_spring_config_bak
    result=0
    if option=='1':
        rep='value="SSLv3,TLSv1'
    else:
        rep='value="TLSv1'
    if (os.name == "nt"):
        if hash["sps_21100_31100"]["installed"] != "yes":
           logger("| SPS Service is not installed, skipping 31100 port!\n", "0")
           return(0)
        sps_spring_config = hash["sps_21100_31100"]["path"]+"\\conf\\sps-spring-config.xml"
        sps_spring_config_bak= hash["sps_21100_31100"]["path"]+"\\conf\\sps-spring-config-bak.xml"
        logger("| Configuring SSLv3 protocol for SPS port ("+hash["sps_21100_31100"]["port"]+")...", "0")
    elif(os.name== "posix"):
        sps_spring_config="/usr/lib/vmware-vpx/sps/conf/sps-spring-config.xml"
        sps_spring_config_bak="/usr/lib/vmware-vpx/sps/conf/sps-spring-config-bak.xml"
        logger("| Configuring SSLv3 protocol for SPS port (21100)...", "0")
    create_backup (sps_spring_config,sps_spring_config_bak)
    try:
        fh = open(sps_spring_config, 'r')
        lines = fh.readlines()
        fh.close()
        for i in range(0,len(lines)):
            if re.match(r'.*<property.*enabledProtocols.*',lines[i],re.I):
                if re.match(r'.*value\s*=\s*".*TLSv1,',lines[i],re.I):
                    lines[i]=re.sub(r'value\s*=\s*".*TLSv1,',rep+",",lines[i])
                    break
                else:
                    lines[i]=re.sub(r'value\s*=\s*".*TLSv1',rep,lines[i])
                    break
        fh = open(sps_spring_config, 'w')
        fh.writelines(lines)
        fh.close()
    except IOError as e:
        logger(e,"0")
        result |= 1
    if result == 0:
        logger("Successful.\n", "0")
    else:
        logger("failed.", "0")
        rollback('all')

def change_invsvc_10109_ssl(option):
    global xdb_config_bak
    result=0
    if option== '1':
        rep='value="SSLv3,TLSv1"'
    else:
        rep='value="TLSv1"'
    if (os.name == "nt"):
        if hash["xdb_10109"]["installed"] != "yes":
           logger("| Inventory Service is not installed, skipping 10109 port!\n", "0")
           return(0)
        xdb_config_file = hash["xdb_10109"]["path"]+"\\lib\\server\\config\\query-server-config.xml"
        xdb_config_bak= hash["xdb_10109"]["path"]+"\\lib\\server\\config\\query-server-config-bak.xml"
    elif(os.name== "posix"):
        xdb_config_file="/usr/lib/vmware-vpx/inventoryservice/lib/server/config/query-server-config.xml"
        xdb_config_bak="/usr/lib/vmware-vpx/inventoryservice/lib/server/config/query-server-config-bak.xml"
    logger("| Configuring SSLv3 protocol for Inventory Service xDB port (10109)..", "0")
    create_backup (xdb_config_file,xdb_config_bak)
    try:
        fh = open(xdb_config_file, 'r')
        lines = fh.readlines()
        fh.close()
        for i in range(0,len(lines)):
            if re.match(r'.*<property.*protocols.*',lines[i],re.I):
                lines[i]=re.sub(r'value\s*=\s*".*TLSv1"',rep,lines[i])
                break
        fh = open(xdb_config_file, 'w')
        fh.writelines(lines)
        fh.close()
    except IOError as e:
        logger(e,"0")
        result |= 1
    if result == 0:
        logger("Successful.\n", "0")
    else:
        logger("failed.", "0")
        rollback('all')

def restart_service():
    logger("Restarting all Services. This may take some time!\n", "0")
    result=0
    nt_services={}#["vimQueryService","vctomcat","vpxd","vspherewebclientsvc","vimPBSM","vmware-syslog-collector"]
    posix_services=["vami-lighttp","vmware-inventoryservice","vmware-vpxd","vsphere-client","syslog-collector","syslog"]
    if (os.name == "nt"):
        for service in hash:
            if hash[service]['installed']=="yes" and hash[service]['svc_name'] != '':
                nt_services[hash[service]['svc_name']] = hash[service]['name']
        for service in nt_services:
            logger("| Stopping "+nt_services[service]+" service...", "1")
            if service == 'vpxd':
               cmd_stop="net stop vctomcat /y >NUL 2>&1"
               error = os.system(cmd_stop)
               if error == 2:
                  error = 0
               result |= error
               status_cmd="sc query vctomcat | find \"STATE\""
               count=0
               while ((subprocess.check_output(status_cmd, shell=True)).find("STOPPED"))<0 and count<10:
                   logger("\n| Waiting for stopping the tomcat service completely.", "0")
                   count+=1
                   time.sleep(30)       
            cmd_stop="net stop "+service+" /y >NUL 2>&1"
            error = os.system(cmd_stop)
            if error == 2:
               error = 0
            result |= error
            status_cmd="sc query "+service+" | find \"STATE\""
            count=0
            while ((subprocess.check_output(status_cmd, shell=True)).find("STOPPED"))<0 and count<10:
                logger("\n| Waiting for stopping the "+ service+" service completely.", "0")
                count+=1
                time.sleep(30)
            if result == 0:
                logger("done.\n", "0")
            else:
                logger("failed!\n", "0")
            #print "stop result of " , service , ": " , result
        time.sleep(30)
        for service in nt_services:
            logger("| Starting "+nt_services[service]+" service...", "1")
            cmd_start="net start "+service+" /y >NUL 2>&1"
            error = os.system(cmd_start)
            if error == 2:
               error = 0
            result |= error
            if result == 0:
                logger("done.\n", "0")
            else:
                logger("failed!\n", "0")
            #print "start result of " , service , ": " , result
        logger("Waiting for the ports to be up and running...", "1")
        time.sleep(240)
        logger("done.\n", "0")
    elif (os.name == "posix"):
        #os.system('ps aux |grep sps')
        for service in posix_services:
            logger("| Stopping "+service+" service...", "1")
            cmd_start="service "+service+" stop 2>&1 &>/dev/null"
            result|=os.system(cmd_start)
            if result == 0:
                logger("done.\n", "0")
            else:
                logger("failed!\n", "0")
            #print "stop result of " , service , ": " , result
        time.sleep(30)
        for service in posix_services:
            logger("| Starting "+service+" service...", "1")
            cmd_stop="service "+service+" start 2>&1 &>/dev/null"
            result|=os.system(cmd_stop)
            if result == 0:
                logger("done.\n", "0")
            else:
                logger("failed!\n", "0")
            #print "start result of " , service , ": " , result
            #os.system('ps aux |grep sps')
        if result == 0:
            logger("Waiting for the ports to be up and running...", "1")
            time.sleep(120)
            logger("done.\n", "0")
    return result
def print_ssl_config(config):
    for port,protocol in config.iteritems():
        list = ','.join(str(x) for x in protocol)
        logger("\n| Protocols enabled on "+port+" port: "+list+"", "0")

def check_product_version():
    version = ""
    valid_version = "5.0.0"
    if (os.name == "nt"):
        path = " \"HKLM\\Software\\VMware, Inc.\\VMware VirtualCenter\" "
        for service in [  "vpx_443", "ngc_client_9443",  "invsvc_10443"  ]:
            if hash[service]['installed']=="yes":
                if service == 'invsvc_10443':
                    cmd = "reg query " + hash[service]['reg'] + " /v " + " Version"
                else:
                    cmd = "reg query " + hash[service]['reg'] + " /v " + " InstalledVersion"
                break
        try:
           result = subprocess.check_output(cmd, shell=True)
           result = result.rstrip('\r\n')	   
           result = re.sub('\s+', ' ', result).strip()          
           matchobj = re.match(r'(.*) (\d.\d.\d)(.\d+)$',result,re.I)
           version = matchobj.group(2)
           #print version
        except Exception as e:
           print e
           return 1
    elif (os.name=="posix"):
        cmd = "/usr/sbin/vpxd -v"
        cmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        for line in cmd.stdout:
            matchobj = re.match(r'(.*) (.*) (\d.\d.\d) (\S+-)(\d+)$',line,re.I)
            #result = subprocess.check_output(cmd, shell=True)
            version = matchobj.group(3)
    if version == valid_version:
        return 0
    else:
        return 1

def restore_file(source_file):
    dst_file = re.sub("-bak","",source_file)
    os.rename(source_file,dst_file)

def rollback(port):
    if port == 'all':
        logger("Rolling back the configuration of vCenter Server ports...", "1")
        global VAMI_bak
        global syslog_bak
        global ngc_server_xml_bak
        global vpxd_bak
        global is_config_bak
        global tc_bak
        global sps_spring_config_bak
        global logbrowser_bak
        global xdb_config_bak
        if (os.name == "nt"):
            bak_files=[syslog_bak, ngc_server_xml_bak, vpxd_bak, is_config_bak, tc_bak, sps_spring_config_bak, xdb_config_bak]
        else:
            bak_files=[VAMI_bak, syslog_bak, ngc_server_xml_bak, vpxd_bak, is_config_bak, tc_bak, sps_spring_config_bak, xdb_config_bak]
        for bak_file in bak_files:
            if bak_file:
                if os.path.exists(bak_file):
                    restore_file(bak_file)
        result = restart_service()
        exit(0)

def parse_arguments():
    if (os.name == "nt"):
       os_type = "ciswin"
       reg_query()
    valid = check_product_version()
    if valid != 0:
        print "This script is supported on vCenter Server 5.0.0 only! Please check the version."
        exit(1)
    if (len(sys.argv) < 2 ):
        print " " 
        print "-----------------------------------------   W  A R N I N G  ---------------------------------"
        print " "    
        print "Configuring SSLv3 protocol on vCenter Server might break the interoperability with other solutions."
        print "Please refer to KB article http://kb.vmware.com/kb/2145484, before proceeding. \nNote: This tool is not handling Autodeploy, Authentication Proxy and Update Manager components. Please configure them manually.\n"
        proceed = raw_input("Would you like to continue? [yes]: ")
        proceed = str( proceed)
        if re.match(r'yes', proceed, re.I) or proceed  == '' or proceed  == 'y' or proceed  == 'Y':
           print "\n"
        else:   
           print "Ending the script execution"
           exit(0)
        port = 0
        while(port not in ['1','2','3','4']):
            if port == 0:
                port = ''
            else:
                print "Invalid option! Re-try with valid option."
            print " -------------------------------------------------"
            print "|  Welcome to vSphere Security Management Tool    |"
            print " -------------------------------------------------"

            print "\n| Choose an option to configure SSLv3 Protocol:    |"
            print "|  1. Enable SSLv3 on all vCenter Server Ports     |"
            print "|  2. Disable SSLv3 on all vCenter Server Ports    |"
            print "|  3. Scan all vCenter Server Ports                |"
            print "|  4. Exit                                         |"
            print " -------------------------------------------------"
            port = raw_input("Option:  ")
            port = str (port)
    else:
       #handle the arguments
       port = str(sys.argv[1])
    if port == '4':
        exit(0)
    elif port == '3':
        ssl_scan("yes")
    elif port== '1' or port== '2':
        #logger("| Scanning vCenter Server ports..", "1")
        config_before = ssl_scan("no")
        #logger("done.", "0")
        if port == '1':
            print "\n  -------------------------------------------- "
            logger("| Enabling SSLv3 on all vCenter Server ports. |","0")
            print "  -------------------------------------------- "
        elif port == '2':
            print "\n  -------------------------------------------- "
            logger("| Disabling SSLv3 on all vCenter Server ports. |","0")
            print "  -------------------------------------------- "
        change_syslog_1514_ssl(str(port))
        change_webclients_9443_ssl(str(port))
        change_vpxd_443_ssl(str(port))
        change_inventory_10443_ssl(str(port))
        change_management_web_8443_ssl(str(port))
        change_sps_21100_31100_ssl(str(port))

        change_invsvc_10109_ssl(str(port))
        change_VAMI_5480_ssl(str(port))
        result=restart_service()
        if result == 0:
            if port == '1':
                 logger("\r\nSuccessfully enabled SSLv3 on all vCenter Server ports.","0")
            elif port == '2':
                 logger("\r\nSuccessfully disabled SSLv3 on all vCenter Server ports.","0")
            #logger("| Scanning vSphere ports..", "1")
            config_after = ssl_scan("no")
            #logger("done.", "0")
            #print scan results before and after the config
            print " \n -------------------------------------"
            print "|  Scan result before configuration   |"
            print " -------------------------------------"
            print_ssl_config(config_before)
            print " \n -------------------------------------"
            print "|  Scan result after configuration    |"
            print " -------------------------------------"
            print_ssl_config(config_after)
            logger("\r\nNote: Please configure SSLv3 for other services like Autodeploy, Authentication Proxy and Update Manager components manually. \nFor more information Refer KB article http://kb.vmware.com/kb/2139396.", "0")
        else:
            logger("|  Failed to restart services.","0")
    else:
        print "Invalid option! Re-try with valid option from above."

def main():
    global log_type
    log_type = 'print'
    try:
        parse_arguments()
    except EOFError as e:
        logger(e,"0")
        logger("FAILED !!!","0")

if __name__ == '__main__':
    exit(main())
