#!/bin/bash
#version 1.0
#author:si1ent
cat <<EOF
*************************************************************************************
*****				Linux基线检查脚本	  	     		*****
*************************************************************************************
*****				Linux基线配置规范设计				*****
*****			输出结果/tmp/${ipadd}linux_check_out.txt			*****
*************************************************************************************
EOF
rm -rf /tmp/linux_check_out.txt

echo "***************************"
echo "系统账户检查中..."
echo "***************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m 系统账户安全检查 \033[0m——————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
UIDS=`awk -F[:] 'NR!=1{print $3}' /etc/passwd`
flag=0
for i in $UIDS
do
  if [ $i = 0 ];then
    echo -e "0x1、存在非root账号的账号UID为0:\033[31m 不符合要求\033[0m" >> /tmp/${ipadd}linux_check_out.txt
  else
    flag=1
  fi
done
if [ $flag = 1 ];then
  echo -e "0x1、不存在非root账户以外UID为0账户:符合要求" >> /tmp/${ipadd}linux_check_out.txt
fi
#echo "******************************************************************************" >> /tmp/${ipadd}linux_check_out.txt

#echo -e '\n'i

w1=`w` #显示用户登陆系统的pts
echo -e "0x2、显示当前用户tty:\n$w1" >> /tmp/${ipadd}linux_check_out.txt
echo -e "使用命令pkill -kill -t pts/1踢出" >>/tmp/${ipadd}linux_check_out.txt
#echo "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&" >> /tmp/${ipadd}linux_check_out.txt

ipadd1=`grep 'Accepted ' /var/log/secure-20191222 | awk '{print $11}' | sort | uniq -c | sort -nr | more`
echo -e "0x3、最近成功登陆服务器IP及登陆次数:\n$ipadd1"  >> /tmp/${ipadd}linux_check_out.txt

#user11=`ls -l | awk -F: '$3==0 {print $1}' /etc/passwd`
#if [ $user11 = "root" ];then
# echo "Linux系统内不存在除root以外UID为0账户,复合要求" >> /tmp/${ipadd}_out.txt
#else
# echo "Linux系统内存在不明账户,不符合要求" >> /tmp/${ipadd}_out.txt
#fi
#echo "******************************************************************************" >> /tmp/${ipadd}linux_check_out.txt

echo -e "\n"
echo "***************************"
echo "重要文件权限检查中..."
echo "***************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m 重要文件权限检查 \033[0m——————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt

file1=`ls -l /etc/passwd | awk '{print $1}'`
file2=`ls -l /etc/shadow | awk '{print $1}'`
file3=`ls -l /etc/group | awk '{print $1}'`
file4=`ls -l /etc/securetty | awk '{print $1}'`
file5=`ls -l /etc/services | awk '{print $1}'`
#file6=`ls -l /etc/xinetd.conf | awk '{print $1}'`
#file7=`ls -l /etc/grub.conf | awk '{print $1}'`
#file8=`ls -l /etc/lilo.conf | awk '{print $1}'`

if [ $file1 = "-rw-r--r--" ];then
 echo -e "0x4、/etc/passwd文件权限为644:符合要求" >> /tmp/${ipadd}linux_check_out.txt
else
  echo -e "0x4、/etc/passwd文件权限不为644:\033[31m 不符合要求\033[0m，建议设置权限为644" >> /tmp/${ipadd}linux_check_out.txt
fi

if [ $file2 = "-r--------" ];then
  echo -e "0x5、/etc/shadow文件权限为400:符合要求" >> /tmp/${ipadd}linux_check_out.txt
else
  echo -e "0x5、/etc/shadow文件权限不为400:\033[31m 不符合要求\033[0m，建议设置权限为400" >> /tmp/${ipadd}linux_check_out.txt
fi

if [ $file3 = "-rw-r--r--" ];then
  echo -e "0x6、/etc/group文件权限为644:符合要求" >> /tmp/${ipadd}linux_check_out.txt
else
  echo -e "0x6、/etc/group文件权限不为644:\033[31m 不符合要求\033[0m，建议设置权限为644" >> /tmp/${ipadd}linux_check_out.txt
fi

if [ $file4 = "-rw-------" ];then
  echo -e "0x7、/etc/security文件权限为600:符合要求" >> /tmp/${ipadd}linux_check_out.txt
else
  echo -e "0x7、/etc/security文件权限不为600:\033[31m 不符合要求\033[0m，建议设置权限为600" >> /tmp/${ipadd}linux_check_out.txt
fi

if [ $file5 = "-rw-r--r--" ];then
  echo -e "0x8、/etc/services文件权限为644:符合要求" >> /tmp/${ipadd}linux_check_out.txt
else
  echo -e "0x8、/etc/services文件权限不为644:\033[31m 不符合要求\033[0m，建议设置权限为644" >> /tmp/${ipadd}linux_check_out.txt
fi
#echo "******************************************************************************" >> /tmp/${ipadd}linux_check_out.txt
echo -e "\n"

echo "***************************"
echo "账号策略检查中..."
echo "***************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m 系统账户安全检查 \033[0m——————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
ipadd=`ifconfig -a | grep Bcast | awk -F "[ :]+" '{print $4}'`
passmax=`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}'`
passmin=`cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print $2}'`
passlen=`cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}'`
passage=`cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print $2}'`

if [ $passmax -le 90 -a $passmax -gt 0 ];then
  echo -e "0x9、 口令生存周期为${passmax}天:符合要求" >> /tmp/${ipadd}linux_check_out.txt
else
  echo -e "0x9、 口令生存周期为${passmax}天:\033[31m 不符合要求\033[0m,建议设置不大于90天" >> /tmp/${ipadd}linux_check_out.txt
fi

if [ $passmin -ge 6 ];then
  echo -e "0x10、口令更改最小时间间隔为${passmin}天:符合要求" >> /tmp/${ipadd}linux_check_out.txt
else
  echo -e "0x10、口令更改最小时间间隔为${passmin}天:\033[31m 不符合要求\033[0m，建议设置大于等于6天" >> /tmp/${ipadd}linux_check_out.txt
fi

if [ $passlen -ge 8 ];then
  echo -e "0x11、口令最小长度为${passlen}:符合要求" >> /tmp/${ipadd}linux_check_out.txt
else
  echo -e "0x11、口令最小长度为${passlen}:\033[31m 不符合要求\033[0m，建议设置最小长度大于等于8" >> /tmp/${ipadd}linux_check_out.txt
fi

if [ $passage -ge 30 -a $passage -lt $passmax ];then
  echo -e "0x12、口令过期警告时间天数为${passage}:符合要求" >> /tmp/${ipadd}linux_check_out.txt
else
  echo -e "0x12、口令过期警告时间天数为${passage}:\033[31m 不符合要求\033[0m，建议设置大于等于30并小于口令生存周期" >> /tmp/${ipadd}linux_check_out.txt
fi
echo -e "\n"

echo "**************************"
echo "系统计划任务检查中..."
echo "**************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m 系统计划任务检查 \033[0m——————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt

cron1=`ls -l /var/spool/cron`
echo -e "0x13、系统内计划任务统计:\n${cron1}" >> /tmp/${ipadd}linux_check_out.txt
echo -e '\n'

echo "***************************"
echo "系统端口监听检查中..."
echo "***************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m 系统端口监听检查 \033[0m——————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt

netstat1=`netstat -ltupa`
echo -e "0x14、系统监听信息:\n${netstat1}" >> /tmp/${ipadd}linux_check_out.txt
echo -e "\n"

echo "***************************"
echo "最近10天修改php检查中..."
echo "***************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m 10天修改php检查 \033[0m———————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
#查询最近10天内修改的php文件，目录输入绝对路径
find1=`ls -l | find /home/git/dxx/public/ -name "*.html" -mtime -10`
echo -e "0x15、修改的php文件信息如:\n$find1" >> /tmp/${ipadd}linux_check_out.txt
echo -e "\n"

echo "**************************"
echo "Webshell检查中..."
echo "**************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m Webshell安全检查 \033[0m——————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt

find2=`find /public/ -name "*.html" |xargs egrep 'assert|phpspy|c99sh|milw0rm|eval|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec|passthru|\(\$\_\POST\[|eval \(str_rot13|\.chr\(|\$\{\"\_P|eval\(\$\_R|file_put_contents\(\.\*\$\_|base64_decode'`
echo -e "此处需填写WEB应用程序目录" >> /tmp/${ipadd}linux_check_out.txt
echo -e "0x16、系统内可能存在\033[31mWebshell\033[0m路径(手工):\n$find2" >> /tmp/${ipadd}linux_check_out.txt
echo -e "\n"

echo "**************************"
echo "系统进程检测(查详情)"
echo "**************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m 系统进程安全检查 \033[0m——————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
#echo -e "\n"
#echo -e "系统进程信息"
echo -e "0x17、ps -aux |grep server_name"  >> /tmp/${ipadd}linux_check_out.txt  #显示所有进程信息
echo -e "0x18、lsof -p PID" >> /tmp/${ipadd}linux_check_out.txt		              #查看该进程所打开端口和文件
echo -e "0x18、netstat -lnp" >> /tmp/${ipadd}linux_check_out.txt		            #显示正在监听状态端口信息包含PID号
echo -e "0x18.1、自行Google" >> /tmp/${ipadd}linux_check_out.txt

echo -e "\n"
echo "**************************"
echo "系统用户登陆信息统计"
echo "**************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m 系统用户登陆检查 \033[0m——————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt

last1=`last -15`
echo -e "0x19、下表是登陆成功用户信息:\n$last1" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
last2=`lastb -15`
echo -e "0x20、下表是远程失败登陆日志:\n$last2" >> /tmp/${ipadd}linux_check_out.txt

echo -e "\n"
echo "*************************"
echo "tmp目录是否存在敏感目录&文件"
echo "*************************"
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————\033[36m tmp目录安全检查 \033[0m———————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt
echo -e "——————————————————————————————————————————————————————————————————————————————" >> /tmp/${ipadd}linux_check_out.txt

ls1=`ls -al /tmp`
echo -e "0x21、tmp目录信息如下:\n$ls1" >> /tmp/${ipadd}linux_check_out.txt
