# Jeesns 1.3 XSS Filter could be bypassed

## Analysis

I found there was a xss vulnerablity about Jeesns have been reported from [CVE-2018-12429](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12429).

Developer has fixed *CVE-2018-12429* through blacklisting mechanism in [`XssHttpServletRequestWrapper.java`](https://github.com/zchuanzhao/jeesns/blob/master/jeesns-core/src/main/java/com/lxinet/jeesns/core/utils/XssHttpServletRequestWrapper.java).

com.lxinet.jeesns.core.utils.XssHttpServletRequestWrapper : line 40

```java
private String cleanXSS(String value) {
        //first checkpoint
        //(?i)忽略大小写
        value = value.replaceAll("(?i)<style>", "&lt;style&gt;").replaceAll("(?i)</style>", "&lt;&#47;style&gt;");
        value = value.replaceAll("(?i)<script>", "&lt;script&gt;").replaceAll("(?i)</script>", "&lt;&#47;script&gt;");
        value = value.replaceAll("(?i)<script", "&lt;script");
        value = value.replaceAll("(?i)eval\\((.*)\\)", "");
        value = value.replaceAll("[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']", "\"\"");

        //second checkpoint
        // 需要过滤的脚本事件关键字
        String[] eventKeywords = { "onmouseover", "onmouseout", "onmousedown",
                "onmouseup", "onmousemove", "onclick", "ondblclick",
                "onkeypress", "onkeydown", "onkeyup", "ondragstart",
                "onerrorupdate", "onhelp", "onreadystatechange", "onrowenter",
                "onrowexit", "onselectstart", "onload", "onunload",
                "onbeforeunload", "onblur", "onerror", "onfocus", "onresize",
                "onscroll", "oncontextmenu", "alert" };
        // 滤除脚本事件代码
        for (int i = 0; i < eventKeywords.length; i++) {
            // 添加一个"_", 使事件代码无效
            value = value.replaceAll(eventKeywords[i],"_" + eventKeywords[i]);
        }
        return value;
    }
```

It just replace a little tags and events. It is easy to bypass.

We can use `svg` 、 `img` tag to bypass the first checkpoint and use differend spell to bypass the sencond checkpoint.

such as：

```<svg/onLoad=confirm(document.cookie)>```

---

## Test

### Step 1

We need register a account and sign in.

![step1](https://github.com/Jayl1n/CVE/blob/master/jeesns/image/jeesns-1.3-xss-filter-bypass-test-1.png)

### Step 2

Then we post a new article and use our payload `<svg/onLoad=confirm(document.cookie)>`.

![step2](https://github.com/Jayl1n/CVE/blob/master/jeesns/image/jeesns-1.3-xss-filter-bypass-test-2.png)

You can see the evil script will be execute when administrator or other visit the article list.

### Step 3

![step3](https://github.com/Jayl1n/CVE/blob/master/jeesns/image/jeesns-1.3-xss-filter-bypass-test-3.png)