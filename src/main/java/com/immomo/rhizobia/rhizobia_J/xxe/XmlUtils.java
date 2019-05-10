/**
 * MOMOSEC Security SDK(MSS)
 *
 * This file is part of the Open MSS Project
 *
 * Copyright (c) 2019 - The V0ld1ron
 *
 * The MSS is published by V0ld1ron under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author V0ld1ron (projectone .at. immomo.com)
 * @created 2019
 */
package com.immomo.rhizobia.rhizobia_J.xxe;

import com.immomo.rhizobia.rhizobia_J.extra.commons.StringUtilities;
import com.immomo.rhizobia.rhizobia_J.csrf.CSRFTokenUtils;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Source;
import javax.xml.transform.sax.SAXSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;

/**
 * @program: java安全编码实践
 *
 * @description: 避免xxe问题的安全的xml转换工具
 *
 * @author: V0ld1ron
 *
 **/
public class XmlUtils {
    private static String xmlCoding = "UTF-8";

    private static XmlUtils instance = new XmlUtils();
    private static Logger logger = Logger.getLogger(CSRFTokenUtils.class);
    private SAXParserFactory spf = null;
    private DocumentBuilderFactory factory = null;

    public XmlUtils() {
        spf = SAXParserFactory.newInstance();
        factory = DocumentBuilderFactory.newInstance();
    }

    public static XmlUtils getInstance() {
        if (null == instance) {
            instance = new XmlUtils();
        }
        return instance;
    }

    /**
     * @Description: 将xml转换成自定义bean类
     * @Param: xmlContent xml文件内容
     * @Param: Class xml转换的bean类
     * @return: TOCLASS 转换后的bean类
     */
    public <TOCLASS> TOCLASS converyToJavaBean(String xmlContent, Class<TOCLASS> toClass) {
        TOCLASS t = null;
        try {
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            Source xmlSource = null;
            xmlSource = new SAXSource(spf.newSAXParser().getXMLReader(), new InputSource(new StringReader(xmlContent)));
            JAXBContext jc = null;
            jc = JAXBContext.newInstance(toClass);
            Unmarshaller unmarshaller = jc.createUnmarshaller();
            t = (TOCLASS) unmarshaller.unmarshal(xmlSource);
        } catch (ParserConfigurationException| SAXException | JAXBException e) {
            logger.error(e.toString());
            throw new RuntimeException(e);
        }

        return t;
    }

    /**
     * @Description: 将xml转换成document类型
     * @Param: xmlContent xml文件内容
     * @Param: charset 编码方式
     * @return: Document 转换后的Document实例
     */
    public Document newDocument(String xmlContent, String charset) throws ParserConfigurationException, SAXException, IOException {
        return newDocument(xmlContent, charset, false);
    }

    public Document newDocument(String xmlContent, String charset, boolean namespaceAware) throws IOException, SAXException, ParserConfigurationException {
        factory.setNamespaceAware(namespaceAware);
        try {
            String feature = "http://apache.org/xml/features/disallow-doctype-decl";
            factory.setFeature(feature, true);
        } catch (ParserConfigurationException e) {
            logger.error(e.toString());
            throw new RuntimeException(e);
        }
        return buildDocument(factory, xmlContent, charset);
    }

    /**
     * @Description: 将xml转换成document类型实际调用方法
     * @Param: factory xml解析器
     * @Param: xmlContent xml文件内容
     * @Param: charset 编码方式
     * @return: Document 转换后的Document实例
     */
    private Document buildDocument(DocumentBuilderFactory factory, String xmlContent, String charset)
            throws ParserConfigurationException, SAXException, IOException {
        if (StringUtilities.isEmpty(xmlContent)) {
            logger.error("xml内容为空");
            throw new SAXException("xml内容为空");
        }
        DocumentBuilder builder = factory.newDocumentBuilder();

        InputStream is = new ByteArrayInputStream(xmlContent.getBytes(charset));
        Document doc = builder.parse(is);

        return doc;

    }
}