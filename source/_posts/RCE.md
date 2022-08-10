---
title: RCE
date: 2022-08-10 15:40:03
tags: 网络攻防
---

# 命令执行漏洞（RCE)

## 命令连接符

<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805140559715.png" alt="image-20220805140559715" style="zoom: 67%;" />

## 常用的cmd命令

whoami——查看当前用户名
ipconfig——查看网卡信息
shutdown -s -t 0——关机————（-s：shutdown    -t 0 ：time 0	立即关机）
net user [username] [password] /add——增加一个用户名为username密码为password的新用户![image-20220805142829485](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805142829485.png)
type [file_name]——查看filename文件内容
<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805143137202.png" alt="image-20220805143137202" style="zoom:67%;" />
## 原理分析
### Command Injection 防御 low

#### 注入点(代码)

![image-20220805144142143](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805144142143.png)

#### 运行实例

<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805143829190.png" alt="image-20220805143829190" style="zoom:67%;" />

<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805143911922.png" alt="image-20220805143911922" style="zoom:67%;" />

### Command Injection 防御 low

防御命令执行的最高效的方法，就是过滤命令连接符
将| ；& || && 符号替换成空，或判断用户输入这些符号就终止执行

#### Command Injection 防御 medium 
![image-20220805145443638](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805145443638.png)
str_replace(find,replace,string,count)：字符替换函数。find：规定要查找的值	replace：规定替换find中的值	string：被搜索的字符串  count：对替换数进行计数的变量
array_keys(array,value,strict):返回一个包含所有键名的一个新数组。array：规定数组	value：指定健值（可选)	strict：可能的值：true  false  是否依赖类型

~~~php
//需要替换的元素少于查到到的元素
<?php
$find = array("Hello","world");
$replace = array("B");
$arr = array("Hello","world","!");
print_r(str_replace($find,$replace,$arr));
?>
    
运行结果
Array ( [0] => B [1] => [2] => ! )
~~~

~~~php
<?php
$substitutions = array( 
    '&&' => '', 
    ';'  => '', 
); 
print_r(array_keys($substitutions));
print_r($substitutions);
?>

运行结果
Array ( [0] => && [1] => ; ) Array ( [&&] => [;] => )
~~~

### Command Injection 攻击 medium 

在medium防御中看到只过滤；和&&，所以使用其他三种即可。
<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805155321480.png" alt="image-20220805155321480" style="zoom:67%;" />
<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805155720842.png" alt="image-20220805155720842" style="zoom:67%;" />

### Command Injection 防御 high

![image-20220805155807981](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805155807981.png)
**注意上面‘| ’拦截并非是|，而是|加空格**————代码不规范导致的漏洞

### Command Injection 攻击 high

<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220805160204332.png" alt="image-20220805160204332" style="zoom:67%;" />

### Command Injection 防御 impossible

~~~php
<?php 
if( isset( $_POST[ 'Submit' ]  ) ) { 
    // Check Anti-CSRF token 
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' ); 
    // Get input 
    $target = $_REQUEST[ 'ip' ];        //将输入内容赋值给变量$target
    $target = stripslashes( $target );      //去除用户输入的\
    // Split the IP into 4 octects 
    $octet = explode( ".", $target );       //把用户输入的数据根据.分开
    // Check IF each octet is an integer 
    if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) //分别判断分成的四个部分是不是数字，并判断是不是四个数字
    	{ 
        // If all 4 octets are int's put the IP back together. 
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3]; //后端格式验证，用.拼接起来

        // Determine OS and execute the ping command. 
        if( stristr( php_uname( 's' ), 'Windows NT' ) ) { 
            // Windows 
            $cmd = shell_exec( 'ping  ' . $target ); 
        }                                                                   
        else { 
            // *nix 
            $cmd = shell_exec( 'ping  -c 4 ' . $target ); 
        } 

        // Feedback for the end user 
        echo "<pre>{$cmd}</pre>"; 
    } 
    else { 
        // Ops. Let the user name theres a mistake 
        echo '<pre>ERROR: You have entered an invalid IP.</pre>'; 
    } 
} 

// Generate Anti-CSRF token 
generateSessionToken(); 

?>
~~~
