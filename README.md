# taint_for_php7.0
1、sprintf、vsprintf这两个函数在使用%d时，存在强制转换为int型，但是，taint无法识别 针对此问题，我对sprintf和vsprintf的逻辑判断进行更改， 2、使用针对XSS的过滤函数时，sql注入的漏洞无法检测 在php_taint.h中新加了多个污染位置 3、使用base64_decode、json_decode、urldecode进行处理后的参数，无法检测漏洞 对这三个函数的返回结果分别进行hook
