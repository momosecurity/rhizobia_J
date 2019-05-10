package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.xxe.XmlUtils;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.Assert.assertTrue;

public class XmlUtilsTest {

    @Test
    public void testParseXmlNoXxe1() {
        System.out.println("***************************" + 1 + "***************************");
        String xmlFile = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<note>\n" +
                "  <to>Tove</to>\n" +
                "  <from>Jani</from>\n" +
                "  <heading>Reminder</heading>\n" +
                "  <body>Don't forget me this weekend!</body>\n" +
                "</note>";
        long t1 = System.nanoTime();
        XmlUtils xmlParser = XmlUtils.getInstance();
        Document doc = null;
        try {
            doc = xmlParser.newDocument(xmlFile, "utf-8");
            long t2 = System.nanoTime();
            System.out.println(t2 - t1);
            Node notifyNode = doc.getFirstChild();
            NodeList list = notifyNode.getChildNodes();
            for (int i = 0, length = list.getLength(); i < length; i++) {
                Node n = list.item(i);
                String nodeName = n.getNodeName();
                String nodeContent = n.getTextContent();
                System.out.println(nodeName.toString() + "    " + nodeContent.toString());
            }
        } catch (Exception e) {
            assertTrue(false);
        }
        assertTrue(true);

    }

    @Test
    public void testParseXmlXxeError2() {
        System.out.println("***************************" + 2 + "***************************");
        String xmlFile = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<!DOCTYPE a [\n" +
                "    <!ENTITY % name SYSTEM \"file:///etc/passwd\">\n" +
                "    %name;\n" +
                "]>";
        Document doc = null;
        try {
            doc = XmlUtils.getInstance().newDocument(xmlFile, "utf-8");
            Node notifyNode = doc.getFirstChild();
            NodeList list = notifyNode.getChildNodes();
            for (int i = 0, length = list.getLength(); i < length; i++) {
                Node n = list.item(i);
                String nodeName = n.getNodeName();
                String nodeContent = n.getTextContent();
                System.out.println(nodeName.toString() + "    " + nodeContent.toString());
            }
            assertTrue(false);
        } catch (Exception e) {
            assertTrue(true);
        }
    }

    @Test
    public void testConvertXml2BeanNoXxe3() {
        System.out.println("***************************" + 3 + "***************************");
        String xmlFile = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<note>\n" +
                "  <to>Tove</to>\n" +
                "  <from>Jani</from>\n" +
                "  <heading>Reminder</heading>\n" +
                "  <body>Don't forget me this weekend!</body>\n" +
                "</note>";
        XmlUtils xmlParser = XmlUtils.getInstance();
        try {
            long t1 = System.nanoTime();
            TestBean testbean = (TestBean) xmlParser.converyToJavaBean(xmlFile, TestBean.class);
            long t2 = System.nanoTime();
            System.out.println(t2 - t1);
            System.out.println(testbean.getTo());
            System.out.println(testbean.getFrom());
            System.out.println(testbean.getHeading());
            System.out.println(testbean.getBody());
            System.out.println(testbean.getNum());
            assertTrue(true);
        } catch (Exception e) {
            assertTrue(true);
        }
    }

    @Test
    public void testConvertXml2BeanXxeError4() {
        System.out.println("***************************" + 4 + "***************************");
        String xmlFile = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<!DOCTYPE a [\n" +
                "    <!ENTITY % name SYSTEM \"file:///etc/passwd\">\n" +
                "    %name;\n" +
                "]>\n" +
                "<note>\n" +
                "  <to>Tove</to>\n" +
                "  <from>Jani</from>\n" +
                "  <heading>Reminder</heading>\n" +
                "  <body>Don't forget me this weekend!</body>\n" +
                "</note>";
        try {
            TestBean testbean = (TestBean) XmlUtils.getInstance().converyToJavaBean(xmlFile, TestBean.class);
            System.out.println(testbean.getTo());
            System.out.println(testbean.getFrom());
            System.out.println(testbean.getHeading());
            System.out.println(testbean.getBody());
            assertTrue(false);
        } catch (Exception e) {
            assertTrue(true);
        }
    }

}