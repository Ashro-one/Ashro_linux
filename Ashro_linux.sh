#!/usr/bin/env bash
#!/bin/bash

echo "Linux安全检查与应急响应工具"
echo "Version: 2.0"
echo "Author: Ashro"
echo "Date: 2024-5-10"

# 检查是否存在 ifconfig 命令，如果不存在则尝试使用 ip addr 命令
if command -v ifconfig &>/dev/null; then
    ip_command="ifconfig -a"
elif command -v ip &>/dev/null; then
    ip_command="ip addr"
else
    echo "无法找到合适的命令来获取 IP 地址，请手动检查。"
    exit 1
fi

date=$(date +%Y%m%d-%H%M%S)
ipadd=$($ip_command | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d '/' -f 1)

check_dir="/tmp/Ashro_${date}/check_file/"
danger_file="/tmp/Ashro_${date}/danger_file.txt"
log_dir="/tmp/Ashro_${date}/log/"
webshell_file="/tmp/Ashro_${date}/webshell/"

# 删除目录及文件，使用引号防止意外的空格或特殊字符
rm -rf "$check_dir" "$danger_file" "$log_dir" "$webshell_file"
mkdir -p "/tmp/Ashro_${date}/" # 使用 -p 选项以确保路径中的所有父目录都存在
echo "检查发现危险项，请注意:" > "${danger_file}"
mkdir -p "$check_dir" "$log_dir" "$webshell_file"
cd "$check_dir"

if [ "$(id -u)" != "0" ]; then
    echo "安全检查必须使用 root 账号，否则某些项无法检查。"
    exit 1
fi

Ashro_saveresult="tee -a ${log_dir}Ashro_checkresult.txt"
echo -e "\n************ 1.系统范围 ************\n" | $Ashro_saveresult
echo "正在检查 IP 地址....." | $Ashro_saveresult
echo "------------- IP 及版本 -------------"
echo "------------ IP 地址 -------------"
echo "正在检查 IP 地址....." | $Ashro_saveresult
if [ -n "$ipadd" ]; then
    (echo "[*] 本机 IP 地址信息:" && echo "$ipadd") | $Ashro_saveresult
else
    echo "[!!!] 本机未配置 IP 地址" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo -e "************ 2.用户信息 ************\n"
echo "------------ 查看登录用户 ------------" | $Ashro_saveresult
echo "正在检查正在登录的用户....." | $Ashro_saveresult

echo "[*] 系统登录用户:" | $Ashro_saveresult
who | $Ashro_saveresult
printf "\n" | $Ashro_saveresult

echo "------------ 查看用户信息 ------------" | $Ashro_saveresult
echo "正在查看用户信息....." | $Ashro_saveresult

echo "[*] 用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录 Shell" | $Ashro_saveresult
cat /etc/passwd | $Ashro_saveresult
printf "\n" | $Ashro_saveresult

echo "------------ 检查超级用户 --------------" | $Ashro_saveresult
echo "正在检查是否存在超级用户....." | $Ashro_saveresult

Superuser=$(awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd)
if [ -n "$Superuser" ]; then
    echo "[!!!] 除 root 外发现超级用户:" | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*] 未发现超级用户" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------ 空口令账户检测 --------------" | $Ashro_saveresult
echo "正在检查空口令账户....." | $Ashro_saveresult

empty_password_accounts=$(awk -F: '($2 == "") {print $1}' /etc/shadow)

if [ -n "$empty_password_accounts" ]; then
    echo "[!!!] 发现空口令账户:" | tee -a "$danger_file" | $Ashro_saveresult
    echo "$empty_password_accounts" | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*] 未发现空口令账户" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------ 新增用户检查 --------------" | $Ashro_saveresult
echo "正在检查新增用户....." | $Ashro_saveresult

new_users=$(awk -F: '$3 >= 1000 && $3 != 65534' /etc/passwd)
if [ -n "$new_users" ]; then
    echo "[!!!] 发现以下新增用户:" | tee -a "$danger_file" | $Ashro_saveresult
    echo "$new_users" | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*] 未发现新增用户" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------ 新增用户组检查 --------------" | $Ashro_saveresult
echo "正在检查新增用户组....." | $Ashro_saveresult

new_groups=$(awk -F: '$3 >= 1000' /etc/group)
if [ -n "$new_groups" ]; then
    echo "[!!!] 发现以下新增用户组:" | tee -a "$danger_file" | $Ashro_saveresult
    echo "$new_groups" | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*] 未发现新增用户组" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

# 检测sudoers文件中用户权限
echo "------------ 检查sudoers文件中用户权限 --------------" | $Ashro_saveresult
echo "正在检查sudoers文件中用户权限....." | $Ashro_saveresult

# 使用 visudo 命令查找具有 NOPASSWD 权限的用户
sudoers_users=$(visudo -c 2>&1 | grep -E '^[^#]*[[:space:]]ALL=.*NOPASSWD' | awk '{print $1}')

if [ -n "$sudoers_users" ]; then
    echo "[!!!] 发现具有 NOPASSWD 权限的用户:" | tee -a "$danger_file" | $Ashro_saveresult
    echo "$sudoers_users" | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*] 未发现具有 NOPASSWD 权限的用户" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

# 检查各账户下登录公钥
echo "------------ 检查各账户下登录公钥 --------------" | $Ashro_saveresult
echo "正在检查各账户下登录公钥....." | $Ashro_saveresult

# 获取所有用户目录路径
home_dirs=$(getent passwd | cut -d: -f6)

# 遍历所有用户目录
for dir in $home_dirs; do
    authorized_keys_file="$dir/.ssh/authorized_keys"
    if [ -f "$authorized_keys_file" ]; then
        echo "[!!!] 在用户 $dir 下发现登录公钥：" | tee -a "$danger_file" | $Ashro_saveresult
        cat "$authorized_keys_file" | tee -a "$danger_file" | $Ashro_saveresult
    fi
done

printf "\n" | $Ashro_saveresult

# 账户密码文件权限检测
echo "------------ 账户密码文件权限检测 --------------" | $Ashro_saveresult
echo "正在检查账户密码文件权限....." | $Ashro_saveresult

# 定义函数检查文件权限
check_permission() {
    file="$1"
    permission=$(stat -c "%a" "$file" 2>/dev/null)
    if [ -n "$permission" ] && [ "$permission" != "644" ]; then
        echo "[!!!] $file 文件权限异常！当前权限为 $permission" | tee -a "$danger_file" | $Ashro_saveresult
    else
        echo "[*] $file 文件权限正常" | $Ashro_saveresult
    fi
}

# 调用函数检查各密码文件权限
check_permission "/etc/passwd"
check_permission "/etc/shadow"
check_permission "/etc/group"
check_permission "/etc/gshadow"

printf "\n" | $Ashro_saveresult

# 暴力破解攻击检测
echo "------------ 暴力破解攻击检测 --------------" | $Ashro_saveresult
echo "正在检测是否遭受暴力破解攻击....." | $Ashro_saveresult

# 定义函数检测暴力破解攻击
check_bruteforce() {
    logfile="$1"
    if [ -f "$logfile" ]; then
        failed_attempts=$(grep "Failed password" "$logfile" | wc -l)
        if [ "$failed_attempts" -gt 5 ]; then
            echo "[!!!] $logfile 中检测到 $failed_attempts 次失败密码尝试，可能遭受暴力破解攻击！" | tee -a "$danger_file" | $Ashro_saveresult
        else
            echo "[*] $logfile 中暴力破解攻击检测正常" | $Ashro_saveresult
        fi
    else
        echo "[*] $logfile 不存在，暴力破解攻击检测未执行" | $Ashro_saveresult
    fi
}

# 调用函数检测暴力破解攻击
check_bruteforce "/var/log/auth.log"
check_bruteforce "/var/log/secure"

printf "\n" | $Ashro_saveresult
# 检测端口进程信息
echo "************3.端口进程信息************"
echo "------------网络连接---------------------" | $Ashro_saveresult
# 病毒木马端口检测
echo "------------病毒木马端口检测------------------" | $Ashro_saveresult
echo "正在检测系统中的网络连接和监听端口....." | $Ashro_saveresult

# 检查正在监听的端口
listening_ports=$(netstat -tuln | awk 'NR > 2 {print $4}' | awk -F':' '{print $NF}' | sort -nu)
if [ -n "$listening_ports" ]; then
    echo "[*] 系统中正在监听的端口如下：" | tee -a "$danger_file" | $Ashro_saveresult
    echo "$listening_ports" | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*] 系统中未发现正在监听的端口" | $Ashro_saveresult
fi

# 检查建立的网络连接
established_connections=$(netstat -tun | grep ESTABLISHED)
if [ -n "$established_connections" ]; then
    echo "[!!!] 系统中存在建立的网络连接：" | tee -a "$danger_file" | $Ashro_saverult
    echo "$established_connections" | tee -a "$danger_file" | $Ashro_saverult

    # 分析建立的网络连接，查看是否有可疑连接
    suspicious_connections=$(echo "$established_connections" | awk '{print $5}' | grep -E '0.0.0.0:|127.0.0.1:' | sort -u)
    if [ -n "$suspicious_connections" ]; then
        echo "[!!!] 发现可疑的网络连接：" | tee -a "$danger_file" | $Ashro_saverult
        echo "$suspicious_connections" | tee -a "$danger_file" | $Ashro_saverult
    fi
else
    echo "[*] 系统中未发现建立的网络连接" | $Ashro_saverult
fi

printf "\n" | $Ashro_saverult

# 进程分析
echo "------------进程分析---------------------" | $Ashro_saverult

# 系统进程
echo "------------系统进程------------------" | $Ashro_saverult
echo "正在检查系统进程....." | $Ashro_saverult
ps_output=$(ps aux)
if [ -n "$ps_output" ]; then
    echo "[*] 系统进程如下:" | tee -a "$danger_file" | $Ashro_saverult
    echo "$ps_output" | tee -a "$danger_file" | $Ashro_saverult
else
    echo "[*] 未发现系统进程" | $Ashro_saverult
fi
printf "\n" | $Ashro_saverult

# 守护进程
echo "------------守护进程------------------" | $Ashro_saverult
echo "正在检查守护进程....." | $Ashro_saverult
if [ -d "/etc/init.d" ]; then
    echo "[*] 系统守护进程:" | tee -a "$danger_file" | $Ashro_saverult
    ls -l /etc/init.d | grep "^-" | awk '{print $9}' | tee -a "$danger_file" | $Ashro_saverult
else
    echo "[*] 未发现守护进程" | $Ashro_saverult
fi
printf "\n" | $Ashro_saverult

# CPU和内存使用异常进程排查
echo "------------CPU和内存使用异常进程排查------------------" | $Ashro_saverult

# 查找CPU使用率最高的进程
cpu_high_processes=$(ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu | head -n 5)
if [ -n "$cpu_high_processes" ]; then
    echo "[!!!] CPU使用率最高的进程：" | tee -a "$danger_file" | $Ashro_saverult
    echo "$cpu_high_processes" | tee -a "$danger_file" | $Ashro_saverult
else
    echo "[*] 未发现CPU使用率异常的进程" | $Ashro_saverult
fi

# 查找内存使用率最高的进程
memory_high_processes=$(ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%mem | head -n 5)
if [ -n "$memory_high_processes" ]; then
    echo "[!!!] 内存使用率最高的进程：" | tee -a "$danger_file" | $Ashro_saverult
    echo "$memory_high_processes" | tee -a "$danger_file" | $Ashro_saverult
else
    echo "[*] 未发现内存使用率异常的进程" | $Ashro_saverult
fi

printf "\n" | $Ashro_saverult

# 隐藏进程和反弹shell类进程扫描
echo "------------隐藏进程和反弹shell类进程扫描------------------" | $Ashro_saverult

# 检查隐藏进程
hidden_processes=$(ps aux | awk '{if($8 == "S" || $8 == "D") print $0}')
if [ -n "$hidden_processes" ]; then
    echo "[!!!] 发现隐藏进程：" | tee -a "$danger_file" | $Ashro_saverult
    echo "$hidden_processes" | tee -a "$danger_file" | $Ashro_saverult
else
    echo "[*] 未发现隐藏进程" | $Ashro_saverult
fi

# 检查反弹shell类进程
# 查询所有监听端口的网络连接
shell_processes=$(netstat -tuln | grep -E "nc -l -p|netcat|ncat|socat|shell|bind|reverse|listen|connect|exec|sh|bash|zsh|ksh|telnet|ssh|rsh|rcp|sshpass|pexpect|paramiko|plink|pscp|putty|ssh-keygen|ssh-agent|tsh|rbash|dash|mkfifo|expect|bash -c|python -c|perl -e|curl|wget|php -r|lua -e|bash -i|php -a|python -m|perl -M|ruby -e|perl -n|python -p|ruby -n|bash -s|php -l|wget -O|curl -o")
if [ -n "$shell_processes" ]; then
    echo "[!!!] 发现反弹shell类进程：" | tee -a "$danger_file" | $Ashro_saverult
    echo "$shell_processes" | tee -a "$danger_file" | $Ashro_saverult
else
    echo "[*] 未发现反弹shell类进程" | $Ashro_saverult
fi

printf "\n" | $Ashro_saverult


# 检查进程对应的可执行文件并保存到指定目录
echo "[*] 正在检查进程对应的可执行文件，并保存到目录：$webshell_file" | $Ashro_saveresult
# 获取所有正在运行的进程的 PID
pids=$(pgrep -d ' ' -f .)

# 遍历所有 PID，复制其可执行文件到指定目录
for pid in $pids; do
    # 获取进程对应的可执行文件路径
    process_executable=$(readlink -f /proc/"$pid"/exe)
    
    # 检查是否为有效路径
    if [ -n "$process_executable" ]; then
        # 获取进程名称
        process_name=$(basename "$process_executable")
        
        # 复制可执行文件到指定目录
        cp "$process_executable" "$webshell_file/$process_name-$pid"
    fi
done

echo "[*] 所有进程对应的可执行文件已保存到目录：$webshell_file" | $Ashro_saveresult

echo "------------系统命令hash值打包------------------" | $Ashro_saveresult
# 指定要保存CSV文件的路径和文件名
csv_file="$check_dir/command_hashes.csv"
# 创建CSV文件并写入标题行
echo "Command Path,Hash Value" > "$csv_file"
# 查找系统命令文件并计算哈希值
find /bin /usr/bin -type f | while IFS= read -r file_path; do
    hash_value=$(md5sum "$file_path" | awk '{print $1}')
    echo "$file_path,$hash_value" >> "$csv_file"
done

echo "哈希值已保存到 $csv_file 文件中。" | $Ashro_saveresult


echo "------------运行服务----------------------" | $Ashro_saveresult
echo "正在检查运行服务....." | $Ashro_saveresult
if command -v systemctl &>/dev/null; then
    if systemctl list-units --type=service --state=running &>/dev/null; then
        echo "[*]以下服务正在运行：" | $Ashro_saveresult
        systemctl list-units --type=service --state=running | awk '{print $1}' | $Ashro_saveresult
    else
        echo "未发现正在运行的服务！" | $Ashro_saveresult
    fi
else
    echo "[!!!]Systemd 未安装，无法检查正在运行的服务。" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "************4.关键文件************" | $Ashro_saveresult
# 检查系统文件的权限变更
# 保存信息到结果文件
echo "------------系统文件的权限变更检查------------------" | $Ashro_saveresult
echo "正在检查系统文件的权限变更....." | $Ashro_saveresult


# 保存信息到结果文件
echo "------------系统文件的权限变更检查------------------" | $Ashro_saveresult
echo "正在检查系统文件的权限变更....." | $Ashro_saveresult

# 查找最近一周内具有执行权限的普通文件，并输出文件名和修改日期
changed_files=$(find / -type f -mtime -7 -executable -not -path "/tmp/Ashro*" 2>/dev/null)
if [ -n "$changed_files" ]; then
    echo "[!!!]发现最近一周内具有执行权限的文件:" | tee -a "$danger_file" | $Ashro_saveresult
    echo "$changed_files" | while IFS= read -r file; do
        file_date=$(stat -c "%y" "$file")
        echo "$file ($file_date)" | tee -a "$danger_file" | $Ashro_saveresult
    done
else
    echo "[*]未发现最近一周内有具有执行权限的文件" | $Ashro_saveresult
fi

echo | $Ashro_saveresult  # 输出一个空行到结果文件中


echo "------------历史命令--------------------------" | $Ashro_saveresult
echo "正在检查操作系统历史命令....." | $Ashro_saveresult

history_file="/root/.bash_history"
if [ -s "$history_file" ]; then
    echo "[*]操作系统历史命令如下:" | $Ashro_saveresult
    cat "$history_file" | $Ashro_saveresult
else
    echo "[!!!]未发现历史命令,请检查是否记录及已被清除" | tee -a "$danger_file" | $Ashro_saveresult
fi

printf "\n" | $Ashro_saveresult


echo "-------------启动项-----------------------" | $Ashro_saveresult
echo "-------------用户自定义启动项-----------------------" | $Ashro_saveresult
echo "正在检查用户自定义启动项....." | $Ashro_saveresult
chkconfig_output=$(chkconfig --list 2>/dev/null | grep -E ":on|启用" | awk '{print $1}')
if [ -n "$chkconfig_output" ]; then
    (echo "[*]用户自定义启动项:" && echo "$chkconfig_output") | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "未发现用户自定义启动项" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "-------------系统自启动项-----------------------" | $Ashro_saveresult
echo "正在检查系统自启动项....." | $Ashro_saveresult
systemctl_output=$(systemctl list-unit-files --type=service 2>/dev/null | awk '/enabled/ {print $1}')
if [ -n "$systemctl_output" ]; then
    (echo "[*]系统自启动项如下:" && echo "$systemctl_output") | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*]未发现系统自启动项" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "-------------危险启动项-----------------------" | $Ashro_saveresult
echo "正在检查危险启动项....." | $Ashro_saveresult

# 检查系统是否支持systemctl命令
if command -v systemctl &>/dev/null; then
    # 使用systemctl命令获取启用的服务列表
    danger_startup=$(systemctl list-unit-files --type=service | grep enabled | awk '{print $1}' | grep -E "\.service$")
    if [ -n "$danger_startup" ]; then
        (echo "[!!!]发现危险启动项:" && echo "$danger_startup") | tee -a "$danger_file" | $Ashro_saveresult
    else
        echo "[*]未发现危险启动项" | $Ashro_saveresult
    fi
else
    # 如果系统不支持systemctl命令，则输出提示信息
    echo "[!!!]系统不支持systemctl命令，无法检查启动项" | tee -a "$danger_file" | $Ashro_saveresult
fi

printf "\n" | $Ashro_saveresult


echo "------------系统定时任务分析-------------------" | $Ashro_saveresult
echo "------------查看系统定时任务-------------------" | $Ashro_saveresult
echo "正在分析系统定时任务....." | $Ashro_saveresult
syscrontab=$(grep -v "# run-parts" /etc/crontab 2>/dev/null | grep run-parts)
if [ -n "$syscrontab" ]; then
    (echo "[!!!]发现存在系统定时任务:" && cat /etc/crontab ) | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*]未发现系统定时任务" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------分析系统可疑定时任务-------------------" | $Ashro_saveresult
echo "正在分析系统可疑任务....." | $Ashro_saveresult


# 分析可疑定时任务
dangersyscron=$(egrep "(chmod|useradd|groupadd|chattr|wget|curl|su|sudo|rsync).*\.(sh|pl|py|bash|ksh|csh|zsh)$" /etc/cron*/* /var/spool/cron/* 2>/dev/null)

if [ -n "$dangersyscron" ]; then
    echo "[!!!]发现下面的定时任务可疑，请注意！！！" | tee -a "$danger_file" | $Ashro_saveresult
    echo "$dangersyscron" | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*]未发现可疑系统定时任务" | $Ashro_saveresult
fi

printf "\n" | $Ashro_saverult


echo "------------分析用户定时任务-------------------" | $Ashro_saveresult
echo "------------查看用户定时任务-------------------" | $Ashro_saveresult
echo "正在查看用户定时任务....." | $Ashro_saveresult

# 检查是否存在 /var/spool/cron 目录
if [ -d "/var/spool/cron" ]; then
    # 使用 ls 命令列出所有用户的定时任务
    for user_crontab in /var/spool/cron/*; do
        username=$(basename "$user_crontab")
        crontab_content=$(cat "$user_crontab" 2>/dev/null)
        if [ -n "$crontab_content" ]; then
            (echo "[!!!]用户 $username 的定时任务如下:" && echo "$crontab_content") | $Ashro_saveresult
        fi
    done
else
    echo "[!!!]未找到 /var/spool/cron 目录，无法查找用户定时任务" | tee -a "$danger_file" | $Ashro_saveresult
fi

printf "\n" | $Ashro_saveresult


echo "------------查看可疑用户定时任务-------------------" | $Ashro_saveresult
echo "正在分析可疑用户定时任务....." | $Ashro_saverult
danger_crontab=$(crontab -l 2>/dev/null | egrep "((chmod|useradd|groupadd|chattr|wget|curl|su|sudo|rsync).*\.(sh|pl|py|bash|ksh|csh|zsh)))")
if [ -n "$danger_crontab" ]; then
    (echo "[!!!]发现可疑定时任务,请注意！！！" && echo "$danger_crontab") | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*]未发现可疑定时任务" | $Ashro_saverult
fi
printf "\n" | $Ashro_saverult

echo "------------最近24小时内变动的文件---------------------" | $Ashro_saveresult

changed_files=$(find / -type f -mtime 0 2>/dev/null | grep -E "\.(py|sh|per|pl|php|asp|jsp)$")
if [ -n "$changed_files" ]; then
    echo "最近24小时内发现以下文件有改变:" | $Ashro_saverult
    echo "$changed_files" | tee -a "$danger_file" | $Ashro_saverult
else
    echo "未发现最近24小时内有改变的文件" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------CPU分析-----------------" | $Ashro_saveresult
echo "------------CPU情况-----------------" | $Ashro_saveresult
echo "正在检查CPU相关信息....." | $Ashro_saveresult
(echo "CPU硬件信息如下:" && cat /proc/cpuinfo ) | $Ashro_saveresult
(echo "CPU使用情况如下:" && ps -aux --sort=-%cpu | awk 'NR<=5 {print $1,$2,$3,$NF}') | $Ashro_saveresult
printf "\n" | $Ashro_saveresult
echo "------------占用CPU前5进程-----------------" | $Ashro_saveresult
echo "正在检查占用CPU前5资源的进程....." | $Ashro_saveresult
(echo "占用CPU资源前5进程：" && ps -aux --sort=-%cpu | head -6 | tail -n +2)  | $Ashro_saveresult
printf "\n" | $Ashro_saveresult
echo "------------占用CPU较大进程-----------------" | $Ashro_saveresult
echo "正在检查占用CPU较大的进程....." | $Ashro_saveresult
pscpu=$(ps -aux --sort=-%cpu | awk '{if($3>=20) print $0}' | tail -n +2)
if [ -n "$pscpu" ];then
    echo "[!!!]以下进程占用的CPU超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD" 
    echo "$pscpu" | tee -a 20.2.3_pscpu.txt | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*]未发现进程占用资源超过20%" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saverult


echo "------------日志分析------------------------------" | $Ashro_saveresult

echo "------------查看日志配置----------------------" | $Ashro_saveresult
echo "正在查看日志配置....."  | $Ashro_saveresult
logconf=$(cat /etc/rsyslog.conf 2>/dev/null | grep -vE "^$|^#" | tee /dev/tty)
if [ -n "$logconf" ]; then
    echo "[*]日志配置如下:" | $Ashro_saveresult 
    echo "$logconf" | $Ashro_saveresult
else
    echo "[!!!]未发现日志配置文件" | tee -a "$danger_file" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------日志是否存在----------------------" | $Ashro_saveresult
echo "正在分析日志文件是否存在....." | $Ashro_saveresult
if ls /var/log/* &>/dev/null; then
    echo "[*]日志文件存在" | $Ashro_saveresult
else
    echo "[!!!]日志文件不存在，请分析是否被清除！" | tee -a "$danger_file" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------日志审核是否开启-------------------" | $Ashro_saveresult
echo "正在分析日志审核是否开启....."
if systemctl is-active auditd.service &>/dev/null; then
    echo "[*]系统日志审核功能已开启，符合要求" | $Ashro_saveresult
else
    echo "[!!!]系统日志审核功能已关闭，不符合要求。建议开启日志审核。可使用以下命令开启：systemctl start auditd.service" | tee -a "$danger_file" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------打包日志-------------------" | $Ashro_saveresult
echo "正在打包日志......" | $Ashro_saveresult

# 检查不同的 Linux 发行版，使用相应的打包命令，并将输出重定向到 /dev/null
if command -v zip &>/dev/null; then
    # 如果 zip 命令可用，则使用 zip 进行打包，并将输出重定向到 /dev/null
    zip -r "${log_dir}system_log.zip"  /var/log/  &>/dev/null
    if [ $? -eq 0 ]; then
        echo "[*]日志打包成功" | $Ashro_saveresult
    else
        echo "[!!!]日志打包失败，请导出日志" | tee -a "$danger_file" | $Ashro_saveresult
    fi
elif command -v tar &>/dev/null; then
    # 如果 zip 命令不可用，尝试使用 tar 命令进行打包，并将输出重定向到 /dev/null
    tar -czf "${log_dir}system_log.tar.gz"  /var/log/  &>/dev/null
    if [ $? -eq 0 ]; then
        echo "[*]日志打包成功" | $Ashro_saveresult
    else
        echo "[!!!]日志打包失败，请导出日志" | tee -a "$danger_file" | $Ashro_saveresult
    fi
else
    # 如果 zip 和 tar 命令都不可用，提示用户手动导出日志
    echo "[!!!]找不到适合的打包工具，请手动导出日志" | tee -a "$danger_file" > /dev/null
fi


echo "------------secure 日志分析-------------------" | $Ashro_saveresult
echo "------------成功登录-------------------" | $Ashro_saveresult
echo "正在检查日志中成功登录的情况....." | $Ashro_saveresult
loginsuccess=$(grep "Accepted password" /var/log/secure* 2>/dev/null | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginsuccess" ]; then
    echo "[*]日志中分析到以下用户成功登录:"  | tee -a "$danger_file" | $Ashro_saveresult
    echo "$loginsuccess" | $Ashro_saveresult
    echo "[*]登录成功的IP及次数如下：" | tee -a "$danger_file" | $Ashro_saveresult
    grep "Accepted " /var/log/secure* | awk '{print $11}' | sort | uniq -c
    echo "[*]登录成功的用户及次数如下:"  | tee -a "$danger_file" | $Ashro_saveresult
    grep "Accepted" /var/log/secure* | awk '{print $9}' | sort | uniq -c
else
    echo "[*]日志中未发现成功登录的情况" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------登录失败-------------------" | $Ashro_saveresult
echo "正在检查日志中登录失败的情况....." | $Ashro_saveresult
loginfailed=$(grep "Failed password" /var/log/secure* 2>/dev/null | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginfailed" ]; then
    echo "[!!!]日志中发现以下登录失败的情况:"  | tee -a "$danger_file" | $Ashro_saveresult
    echo "$loginfailed"  | tee -a "$danger_file" | $Ashro_saveresult
    echo "[!!!]登录失败的IP及次数如下:"  | tee -a "$danger_file" | $Ashro_saveresult
    grep "Failed password" /var/log/secure* | awk '{print $11}' | sort | uniq -c
    echo "[!!!]登录失败的用户及次数如下:"  | tee -a "$danger_file" | $Ashro_saveresult
    grep "Failed password" /var/log/secure* | awk '{print $9}' | sort | uniq -c
else
    echo "[*]日志中未发现登录失败的情况" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "-----------本机登录情况-----------------" | $Ashro_saveresult
echo "正在检查本机登录情况....." | $Ashro_saveresult
secure_log=$(find /var/log/ -type f \( -name "secure" -o -name "auth.log" -o -name "messages" \) 2>/dev/null | head -n1)
if [ -n "$secure_log" ]; then
    systemlogin=$(awk '/sshd:session.*session opened/ {print $1,$2,$3,$11}' "$secure_log")
    if [ -n "$systemlogin" ]; then
        echo "[*]本机登录情况:"  | $Ashro_saveresult
        echo "$systemlogin" | $Ashro_saveresult
        echo "[*]本机登录账号及次数如下:"  | $Ashro_saveresult
        awk '/sshd:session.*session opened/ {print $11}' "$secure_log" | sort -nr | uniq -c
    else
        echo "[!!!]未发现在本机登录退出情况，请注意！！！" | $Ashro_saveresult
    fi
else
    echo "[!!!]未找到安全日志文件，请注意！！！" | tee -a "$danger_file" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult


echo "------------新增用户组-----------------" | $Ashro_saveresult
echo "正在检查新增用户组....." | $Ashro_saveresult

# 检查新增用户组
newgroup_log=""
if [ -f "/var/log/secure" ]; then
    newgroup_log="/var/log/secure"
elif [ -f "/var/log/auth.log" ]; then
    newgroup_log="/var/log/auth.log"
elif [ -f "/var/log/messages" ]; then
    newgroup_log="/var/log/messages"
fi

if [ -n "$newgroup_log" ]; then
    newgroup=$(awk '/new group/ {print $1,$2,$3,$9}' "$newgroup_log")

    if [ -n "$newgroup" ]; then
        echo "[!!!]日志中发现新增用户组:" | tee -a "$danger_file" | $Ashro_saveresult
        echo "$newgroup" | tee -a "$danger_file" | $Ashro_saveresult
        (echo "[*]新增用户组及次数如下:" && awk '/new group/ {print $8}' "$newgroup_log" | awk -F '[=,]' '{print $2}' | sort | uniq -c) | tee -a "$danger_file" | $Ashro_saveresult
    else
        echo "[*]日志中未发现新增加用户组" | $Ashro_saveresult
    fi
fi

printf "\n" | $Ashro_saverult


echo "------------message日志分析---------------" | $Ashro_saveresult
echo "------------传输文件--------------------" | $Ashro_saveresult
echo "正在检查传输文件....." | $Ashro_saveresult
zmodem=$(grep "ZMODEM:.*BPS" /var/log/message*)
if [ -n "$zmodem" ]; then
	(echo "[!!!]传输文件情况:" && echo "$zmodem") | tee -a $danger_file | $Ashro_saveresult
else
	echo "[*]日志中未发现传输文件" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult


echo "-----------cron日志分析---------------" | $Ashro_saveresult

echo "------------定时下载-----------------" | $Ashro_saveresult
echo "正在分析定时下载....." 
cron_download=$(grep "wget\|curl" /var/log/cron /var/log/cron.* 2>/dev/null)
if [ -n "$cron_download" ]; then
    (echo "[!!!]定时下载情况:" && echo "$cron_download") | tee -a "$danger_file" | $save_result_command
else
    echo "[*]未发现定时下载情况" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult


echo "------------定时执行脚本-----------------" | $Ashro_saveresult
echo "正在分析定时执行脚本....." | $Ashro_saveresult
cron_shell=$(grep -E "\.py$|\.sh$|\.pl$" /var/log/cron* 2>/dev/null)
if [ -n "$cron_shell" ]; then
    (echo "[!!!]发现定时执行脚本:" && echo "$cron_shell") | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*]未发现定时执行脚本" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------btmp日志分析----------------------" | $Ashro_saveresult
echo "------------错误登录日志分析-----------------" | $Ashro_saveresult 
echo "正在分析错误登录日志....." | $Ashro_saveresult 
lastb=$(lastb 2>/dev/null)
if [ -n "$lastb" ]; then
    (echo "[*]错误登录日志如下:" && echo "$lastb") | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*]未发现错误登录日志" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------lastlog日志分析----------------------" | $Ashro_saveresult
echo "------------所有用户最后一次登录日志分析-----------------" | $Ashro_saveresult 
echo "正在分析所有用户最后一次登录日志....." | $Ashro_saveresult 
lastlog=$(lastlog 2>/dev/null)
if [ -n "$lastlog" ]; then
    (echo "[*]所有用户最后一次登录日志如下:" && echo "${lastlog}") | tee -a "$danger_file" | $Ashro_saveresult
else
    echo "[*]未发现所有用户最后一次登录日志" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------wtmp日志分析----------------------" | $Ashro_saveresult
echo "------------所有登录用户分析-----------------" | $Ashro_saveresult 
echo "正在检查历史上登录到本机的用户:" | $Ashro_saveresult 
lasts=$(last | grep pts | grep -vw :0 2>/dev/null)
if [ -n "$lasts" ]; then
    (echo "[*]历史上登录到本机的用户如下:" && echo "$lasts") | $Ashro_saveresult
else
    echo "[*]未发现历史上登录到本机的用户信息" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult

echo "------------sshd配置文件-------------------" | $Ashro_saveresult
echo "------------sshd配置-------------------" | $Ashro_saveresult
echo "正在检查sshd配置....." | $Ashro_saveresult 
sshdconfig=$(grep -vE "^$|^#" /etc/ssh/sshd_config 2>/dev/null)
if [ -n "$sshdconfig" ]; then
    (echo "[*]sshd配置文件如下:" && echo "$sshdconfig") | $Ashro_saveresult
else
    echo "[！]未发现sshd配置文件" | $Ashro_saveresult
fi
printf "\n" | $Ashro_saveresult


# Alias 后门检测
echo "正在检测 Alias 后门..." | tee -a "$danger_file" | $Ashro_saveresult

# 列出当前用户的别名并搜索其中是否包含可疑命令
if [ -f ~/.bashrc ]; then
    echo "检查 ~/.bashrc..." | tee -a "$danger_file" | $Ashro_saveresult
    grep -E 'alias[[:space:]]+(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.bashrc | tee -a "$danger_file" | $Ashro_saveresult
fi

if [ -f ~/.bash_profile ]; then
    echo "检查 ~/.bash_profile..." | tee -a "$danger_file" | $Ashro_saveresult
    grep -E 'alias[[:space:]]+(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.bash_profile | tee -a "$danger_file" | $Ashro_saveresult
fi

if [ -f ~/.profile ]; then
    echo "检查 ~/.profile..." | tee -a "$danger_file" | $Ashro_saveresult
    grep -E 'alias[[:space:]]+(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.profile | tee -a "$danger_file" | $Ashro_saveresult
fi

# SSH 后门检测
echo "正在检测 SSH 后门..." | tee -a "$danger_file" | $Ashro_saveresult

# 检查 SSH 配置文件是否包含可疑命令
if [ -f ~/.ssh/config ]; then
    echo "检查 ~/.ssh/config..." | tee -a "$danger_file" | $Ashro_saveresult
    grep -E '(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.ssh/config  | tee -a "$danger_file" | $Ashro_saveresult
fi

# SSH Wrapper 后门检测
echo "正在检测 SSH Wrapper 后门..." | tee -a "$danger_file" | $Ashro_saveresult

# 检查 SSH 授权密钥文件是否包含可疑命令
if [ -f ~/.ssh/authorized_keys ]; then
    echo "检查 ~/.ssh/authorized_keys..." | tee -a "$danger_file" | $Ashro_saveresult
    grep -E 'command="(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.ssh/authorized_keys | tee -a "$danger_file" | $Ashro_saveresult
fi


# 检查特定目录中是否存在可疑文件
if [ -d /var/tmp ]; then
    echo "检查 /var/tmp..." | tee -a "$danger_file" | $Ashro_saveresult
    ls -la /var/tmp | grep -E '(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' | tee -a "$danger_file" | $Ashro_saveresult
fi

# 检查系统日志中是否包含可疑内容
echo "检查系统日志..." | $Ashro_saveresult
if [ -f /var/log/auth.log ]; then
    grep -E '(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' /var/log/auth.log | tee -a "$danger_file" | $Ashro_saveresult
fi

# 检查是否安装并配置了 iptables
if command -v iptables &> /dev/null; then
    echo "检测到 iptables 防火墙" | $Ashro_saveresult
    echo "正在检查是否存在 any 到 any 的策略..." | $Ashro_saveresult

    # 检查是否存在 any 到 any 的策略
    if iptables -L | grep -q 'Chain INPUT (policy ACCEPT)' && \
       iptables -L | grep -q 'Chain FORWARD (policy ACCEPT)' && \
       iptables -L | grep -q 'Chain OUTPUT (policy ACCEPT)'; then
        echo "未发现 any 到 any 的策略" | $Ashro_saveresult
    else
        echo "iptables警告：检测到 any 到 any 的策略" | tee -a "$danger_file" | $Ashro_saveresult
    fi

    echo "显示最近修改的 5 条规则："
    iptables -L --line-numbers | head -n 6 | tee -a "$danger_file" | $Ashro_saveresult

# 检查是否安装并配置了 ufw
elif command -v ufw &> /dev/null; then
    echo "检测到 ufw 防火墙" | $Ashro_saveresult
    echo "正在检查是否存在 any 到 any 的策略..." | $Ashro_saveresult

    # 检查是否存在 any 到 any 的策略
    if ufw status | grep -q 'Anywhere'; then
        echo "警告：ufw检测到 any 到 any 的策略" | tee -a "$danger_file" | $Ashro_saveresult
    else
        echo "未发现 any 到 any 的策略" | $Ashro_saveresult
    fi

    echo "显示最近修改的 5 条规则：" | tee -a "$danger_file" | $Ashro_saveresult
    ufw status numbered | head -n 6| tee -a "$danger_file" | $Ashro_saveresult

# 检查是否安装并配置了 firewalld
elif command -v firewalld &> /dev/null; then
    echo "检测到 firewalld 防火墙" | $Ashro_saveresult
    echo "正在检查是否存在 any 到 any 的策略..." | $Ashro_saveresult

    # 检查是否存在 any 到 any 的策略
    if firewall-cmd --list-all | grep -q 'rule family="ipv4" source address="0.0.0.0/0"'; then
        echo "警告：firewall检测到 any 到 any 的策略" | tee -a "$danger_file" | $Ashro_saveresult
    else
        echo "未发现 any 到 any 的策略" | $Ashro_saveresult
    fi

    echo "显示最近修改的 5 条规则："
    firewall-cmd --list-all | grep -Po 'rule.*' | head -n 5

# 检查是否安装并配置了 nftables
elif command -v nft &> /dev/null; then
    echo "检测到 nftables 防火墙"| $Ashro_saveresult
    echo "正在检查是否存在 any 到 any 的策略..."| $Ashro_saveresult

    # 检查是否存在 any 到 any 的策略
    if nft list ruleset | grep -q 'ip saddr 0.0.0.0/0'; then
        echo "警告：nftables检测到 any 到 any 的策略"| tee -a "$danger_file" | $Ashro_saveresult
    else
        echo "未发现 any 到 any 的策略"| $Ashro_saveresult
    fi

    echo "显示最近修改的 5 条规则："| tee -a "$danger_file" | $Ashro_saveresult
    nft list ruleset | head -n 6| tee -a "$danger_file" | $Ashro_saveresult

# 如果没有安装支持的防火墙
else
    echo "未检测到支持的防火墙"| tee -a "$danger_file" | $Ashro_saveresult
fi

echo "检查结束！！！" | $Ashro_saveresult

