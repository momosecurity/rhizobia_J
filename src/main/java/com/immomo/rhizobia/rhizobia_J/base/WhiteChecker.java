/**
 * MOMOSEC Security SDK(MSS)
 *
 * This file is part of the Open MSS Project
 *
 * Copyright (c) 2019 - V0ld1ron
 *
 * The MSS is published by V0ld1ron under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author V0ld1ron (projectone .at. immomo.com)
 * @created 2019
 */
package com.immomo.rhizobia.rhizobia_J.base;

import org.apache.log4j.Logger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 * @program: java安全编码实践
 *
 * @description: 白名单检验类
 *
 * @author: V0ld1ron
 *
 **/
public class WhiteChecker {
    private String[] evilCharList = {"?", "\\"};
    private List<String> arrayWhiteList = new ArrayList<String>();
    private static Logger logger = Logger.getLogger(WhiteChecker.class);

    public WhiteChecker() {

    }

    public boolean addWhiteList(List<String> whiteList) {
        for (String x : whiteList) {
            if (null == x){
                logger.warn("入参列表有空");
                continue;
            }
            arrayWhiteList.add(x.toLowerCase());
        }
        return true;
    }

    public boolean addWhiteList(String white) {
        if (null == white) {
            logger.warn("white入参为空");
            return false;
        }
        arrayWhiteList.add(white.toLowerCase());
        return true;

    }

    public boolean delWhiteList(String white) {
        if (null == white) {
            logger.warn("white入参为空");
            return false;
        }
        arrayWhiteList.remove(white.toLowerCase());
        return true;

    }

    public List<String> getWhiteList() {
        return this.arrayWhiteList;
    }

    public boolean setWhiteList(List<String> whiteList) {
        arrayWhiteList.clear();
        for (String x : whiteList) {
            if (null == x){
                logger.warn("入参列表有空");
                continue;
            }
            arrayWhiteList.add(x.toLowerCase());
        }
        return true;
    }

    public boolean clearWhiteList(List<String> whiteList) {
        arrayWhiteList.clear();
        return true;

    }

    /**
     * @Description: 校验url是否在白名单内
     * @Param: url 网络地址
     * @return: boolean true 在白名单内；false 不在白名单内
     */
    protected boolean verifyURL(String url) {
        if (null == url){
            logger.warn("传入url参数为空");
            return false;
        }
        URI urlAddress = null;
        try {
            urlAddress = new URI(url);
            //url protocol非http https
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                logger.warn("非http(s)协议");
                return false;
            }
            //验证信息，user:passwd@host 为非法
            String urlWholeHost = urlAddress.getAuthority();
            if (urlWholeHost.contains("@")) {
                logger.warn("包含非法字符@");
                return false;
            }
            for (String j : this.evilCharList) {
                if (true == this.isInvalidUrl(urlWholeHost, j)) {
                    logger.warn("包含非法字符?\\");
                    return false;
                }
            }
            //host 包含 white list内容 符合条件
            String urlHost = urlAddress.getHost().toLowerCase().trim();
            boolean flag = false;
            for (String i : this.arrayWhiteList) {
                int index = urlHost.indexOf(i);
                if ((i.length() + index) == urlHost.length()) {
                    flag = true;
                }
            }
            if (!flag) {
                logger.warn("url不在白名单内");
                return false;
            }

        } catch (URISyntaxException e) {
            logger.warn(e.toString());
            return false;
        }
        return true;

    }

    /**
     * @Description: 校验url是否合法
     * @Param: url 网络地址
     * @Param: evilChar 非法字符
     * @return: boolean true 合法；false 不合法
     */
    private boolean isInvalidUrl(String url, String evilChar) {
        boolean isInvalid = false;
        int evilPos = url.indexOf(evilChar);
        for (String i : this.arrayWhiteList) {
            if (-1 != evilPos && evilPos < url.indexOf(i)) {
                isInvalid = true;
            }
        }
        return isInvalid;
    }

}
