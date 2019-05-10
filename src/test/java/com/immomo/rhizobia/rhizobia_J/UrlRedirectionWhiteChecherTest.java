package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.urlredirection.UrlRedirectionWhiteChecher;
import org.junit.Before;
import org.junit.Test;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class UrlRedirectionWhiteChecherTest {

        public UrlRedirectionWhiteChecher urlChecker;

        @Before
        public void beforeClass() throws Exception {
            List<String> whitelist = new ArrayList<String>();
            String white1 = ".trust1.com";
            String white2 = ".trust2.com";

            //添加的白名单时注意是否需要使用trim()去除多余空字符
            whitelist.add(white1.trim());
            whitelist.add(white2.trim());


            //选择适当的构造函数
            urlChecker = UrlRedirectionWhiteChecher.getInstance();
            urlChecker.setWhiteList(whitelist);

        }

        @Test
        public void verifyURL1() throws MalformedURLException {
            System.out.println("***************************" + 1 + "***************************");

            String url = "https://git.trust2.com/test/../aa";

            //使用白名单检查时，也要注意是否需要使用trim()去除多余空字符
            boolean isWhite = urlChecker.verifyURL(url.trim());
            assertTrue(isWhite);
        }

        @Test
        public void verifyURL2() throws MalformedURLException {
            System.out.println("***************************" + 2 + "***************************");
            String url = "file:///etc/passwd";
            long t1 = System.nanoTime();
            boolean isWhite = urlChecker.verifyURL(url);
            long t2 = System.nanoTime();
            System.out.println(t2 - t1);
            assertFalse(isWhite);
        }

        @Test
        public void verifyURL3() throws MalformedURLException {
            System.out.println("***************************" + 3 + "***************************");
            String url = "http://127.0.0.1:8080/test";
            long t1 = System.nanoTime();
            boolean isWhite = urlChecker.verifyURL(url);
            long t2 = System.nanoTime();
            System.out.println(t2 - t1);
            assertFalse(isWhite);
        }

        @Test
        public void verifyURL4() throws MalformedURLException {
            System.out.println("***************************" + 4 + "***************************");
            String url = "http://a@b:aa.trust1.com@jhhh";
            boolean isWhite = urlChecker.verifyURL(url);
            assertFalse(isWhite);
        }

        @Test
        public void verifyURL5() throws MalformedURLException {
            System.out.println("***************************" + 5 + "***************************");
            String url = "http://www.baidu.trust1.coma.com";
            boolean isWhite = urlChecker.verifyURL(url);
            assertFalse(isWhite);
        }

        @Test
        public void verifyURL6() throws MalformedURLException {
            System.out.println("***************************" + 6 + "***************************");
            String url = "http://www.baidu.com\\trust1.com";
            boolean isWhite = urlChecker.verifyURL(url);
            assertFalse(isWhite);
        }

        @Test
        public void verifyURL7() throws MalformedURLException {
            System.out.println("***************************" + 7 + "***************************");
            String url = "http://www.test.trust1.com";
            boolean isWhite = urlChecker.verifyURL(url);
            assertTrue(isWhite);
        }

        @Test
        public void verifyURL8() throws MalformedURLException {
            System.out.println("***************************" + 8 + "***************************");
            String url = "http://www.baidu.com?trust2.com";
            boolean isWhite = urlChecker.verifyURL(url);
            assertFalse(isWhite);
        }

        @Test
        public void verifyURL9() throws MalformedURLException {
            System.out.println("***************************" + 9 + "***************************");
            String url = "http://www.test.cn/www.trust2.com/hack.html?_aa=21";
            boolean isWhite = urlChecker.verifyURL(url);
            assertFalse(isWhite);
        }

        @Test
        public void verifyURL10() throws MalformedURLException {
            System.out.println("***************************" + 10 + "***************************");
            String url = "https://www.test.net\\@www.trust2.com/fhf.html";
            boolean isWhite = urlChecker.verifyURL(url);
            assertFalse(isWhite);
        }
}