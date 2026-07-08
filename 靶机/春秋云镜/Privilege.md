![](assets/file-20260708224730815.png)
主页
![](assets/file-20260708224710372.png)
# flag01

## 1. fscan
```
fscan -h 39.99.133.67
[1.5s]     扫描完成, 发现 233 个开放端口
[1.5s]     存活端口数量: 233
[1.5s]     开始漏洞扫描
[1.6s]     POC加载完成: 总共387个，成功387个，失败0个
[5.2s] [*] 网站标题 http://39.99.133.67:8080  状态码:403 长度:548    标题:无标题
[14.5s] [+] 检测到漏洞 http://39.99.133.67:80/www.zip poc-yaml-backup-file
```

下载zip
```
curl -s -o zip http://39.99.133.67:80/www.zip
```

解压缩tools/content-log.php
```php
<?php
$logfile = rawurldecode( $_GET['logfile'] );
// Make sure the file is exist.
if ( file_exists( $logfile ) ) {
  // Get the content and echo it.
  $text = file_get_contents( $logfile );
  echo( $text );
}
exit;
```