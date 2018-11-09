# taint_for_php7.0
修复了</br>
1、sprintf、vsprintf这两个函数在使用%d时，存在强制转换为int型</br>
2、使用针对XSS的过滤函数时，sql注入的漏洞无法检测 </br>
3、使用base64_decode、json_decode、urldecode进行处理后的参数，无法检测漏洞 </br>
增加了</br>
1、taint的log，只包含当前函数名、产生漏洞的函数名、提示信息、当前行这些信息，无法根据这些信息对上层的action进行定位。所以，为taint添加了request_uri信息

#安装方法参照博客：https://www.cnblogs.com/ermei/p/9778021.html
