## 0x00背景
### case 1：shell终端for循环
2017年8月8号，SecuriTeam在官方博客上公布了D-Link 850L的多个高危漏洞和PoC，这些漏洞是Hack2Win比赛的成果。其中包括：
- **WAN和LAN远程代码执行**
- **WAN和LAN未授权信息泄露**
- **LAN的root远程命令执行**

##0x01 漏洞分析
>####WAN和LAN远程代码执行

基于WAN和LAN的远程代码执行漏洞是组合拳漏洞，包括一个（未授权敏感信息泄漏）和另一个命令注入漏洞，（未授权敏感信息泄漏）用于获取web管理账户和密码，创建授权用户凭证（cookie）。命令注入漏洞是利用ntp server字符串未被检查过滤，向该参数注入恶意命令最终被路由器执行。

（未授权敏感信息泄漏）本质缺陷在于hedwig.cgi缺乏鉴权，导致未经授权的用户发送的请求也会被响应，如果请求获取web管理账户和密码，hedwig.cgi同样会将口令信息回传给不可信用户，造成严重的信息泄漏。

首先，我们要弄清hedwig.cgi处理请求的流程：

hedwig.cgi其实是一个链接文件，指向/htdocs/cgibin文件，接收到用户请求的xml数据请求后先封装成xml文件，发送read xml的请求到xmldb server，然后发送execute php的请求到xmldb server。

- **序列图**

```sequence
hedwig.cgi->xmldb: 1. read xml file "/var/tmp/temp.xml"
Note right of xmldb: parse and save
hedwig.cgi->xmldb: 2. execute php file ""/htdocs/webinc/fatlady.php"
Note right of xmldb: parse and execute
```

- **代码**
``` c
void hedwigcgi_main(...)
{
    char *resp_fomat = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<hedwig><result>FAILED</result><message>%s</message></hedwig>";
    char post_stream[0x400], img_stream[0x80], rt_stream[0x11];
    char *method, *message;
    struct option_ref *option;
    FILE *fimg, *fxml;
    unsigned int fd, idx, uid;
    char *ptoken, post_xml, post_ephp;
    char *token_streams[4];

    memset(post_stream, 0x400, 0);
    memset(img_stream, 0x80, 0);
    memset(rt_stream, 0x11, 0);
    memcpy(rt_stream, "/runtime/session", 0x11);
    method = getenv("REQUEST_METHOD");
    if (!method)
        message = "no REQUEST";
    else if (!strcasecmp(method, "post"))
        message = "unsupported HTTP request";
    else
    {
        cgibin_parse_request(sobj_strdup_, 0, 2);
        fimg = fopen("/etc/config/image_sign", "Other");
        if (!fgets(img_stream, 0x80, fimg))
            message = "unable to read signature!";
        else
        {
            cgibin_reatwhite(img_stream);
            option = sobj_new();
            if (!option)
                message = "unable to allocate string object";
            else
            {
                sess_get_uid(option);
                snprintf(post_stream, 0x400, "%s/%s/postxml", "/runtime/session", sobj_get_string(option));
                fxml = fopen("/var/tmp/temp.xml", "w");
                if (!fxml)
                    message = "unable to open temp file.";
                else
                {
                    if (!g_xml_stream)
                        message = "no xml data.";
                    else
                    {
                        fd = fileno(ftmp);
                        if (!lockf(fd, F_TEST, 0))
                        {
                            message = NULL;
                            resp_fomat = "HTTP/1.1 200 OK\r\n\
                                         Content-Type: text/xml\r\n\
                                         \r\n\
                                         <hedwig><result>BUSY</result><message>%s</message></hedwig>";
                        }
                        else
                        {
                            char **tmp_token = token_streams;
                            fd = fileno(ftmp);
                            lockf(fd, F_LOCK, 0);
                            *tmp_token = img_stream;
                            tmp_token += 4;
                            ptoken = strtok("/runtime/session", "/");
                            *tmp_token = ptoken;
                            tmp_token += 4;
                            unsigned int curcles = 2;
                            do
                            {
                                ptoken = strtok(NULL, "/");
                                curcles = curcles + 1;
                                tmp_token += 4;
                                *tmp_token = ptoken;
                            } while (ptoken);

                            sobj_get_string(option);
                            fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", fxml);
                            do{
                                fprintf(fxml, "<%s>\n", *tmp_token);
                                tmp_token += 4;
                            } while (idx < curcles);

                            post_xml = strstr(g_xml_stream, "<postxml>");
                            fprintf(ftmp, "</%s>\n", post_xml);
                            do{
                                fprintf(fxml, "</%s>\n", *tmp_token);
                                tmp_token += 4;
                            } while (idx < curcles);

                            fflush(ftmp);
                            xmldbc_read(0, 2, "/var/tmp/temp.xml");
                            snprintf(post_stream, 0x400, "/htdocs/webinc/fatlady.php\nprefix=%s/%s", "/runtime/session", sobj_get_string(option));
                            xmldbc_ephp(0, 0, post_stream, stdout);
                            message = NULL;
                        }
                    }
                }
            }
        }
    }

    printf(resp_fomat, message);
    if (g_xml_stream)
        free(g_xml_stream);

    sobj_del(option);
}
```
对处理流程清晰化之后回归漏洞，PoC公布的攻击代码中显示，攻击者发送了一个相对路径的xml文件（../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml）请求到hedwig.cgi，然后从响应的数据中就包含web管理账户和密码。
