package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.deserialization.SecureObjectInputStream;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;


public class SecureObjectInputStreamTest {
    @Test
    public void testDeserialization() throws Exception {
        System.out.println("***************************" + 1 + "***************************");
        UnsafeClass Unsafe = new UnsafeClass();
        Unsafe.name = "hacked by ph0rse";

        FileOutputStream fos = new FileOutputStream("object");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        //writeObject()方法将Unsafe对象写入object文件
        os.writeObject(Unsafe);
        os.close();
        //从文件中反序列化obj对象
        FileInputStream fis = new FileInputStream("object");

        /**
         * 使用SecureObjectInputStream 合适的构造函数，增加自定义的白名单
         * SecureObjectInputStream(InputStream in, String[] classlist)
         * SecureObjectInputStream(InputStream in, List<String> classlist)
         */
        // 如想尝试反序列化漏洞，可将如下注释中的一行语句替换接下来的三行代码
        // ObjectInputStream ois = new ObjectInputStream(fis);
        List<String> classlist = new ArrayList<String>();
        classlist.add(SafeClass.class.getName());
        SecureObjectInputStream ois = new SecureObjectInputStream(fis, classlist);

        //使用安全的SecureObjectInputStream恢复对象时会抛出exception
        long t1 = System.nanoTime();
        UnsafeClass objectFromDisk = null;
        try {
            objectFromDisk = (UnsafeClass) ois.readObject();
            long t2 = System.nanoTime();
            System.out.println(objectFromDisk.name);
            System.out.println(t2 - t1);
        } catch (Exception e) {
            assertTrue(true);
        }
        ois.close();
    }

    @Test
    public void testDeserializationNormal() throws Exception {
        System.out.println("***************************" + 2 + "***************************");
        SafeClass safe = new SafeClass();
        safe.name = "nothing";

        FileOutputStream fos = new FileOutputStream("object");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        //writeObject()方法将Unsafe对象写入object文件
        os.writeObject(safe);
        os.close();
        //从文件中反序列化obj对象
        FileInputStream fis = new FileInputStream("object");

        /**
         * 使用SecureObjectInputStream 合适的构造函数，增加自定义的白名单
         * SecureObjectInputStream(InputStream in, String[] classlist)
         * SecureObjectInputStream(InputStream in, List<String> classlist)
         */
        // 如想尝试反序列化漏洞，可将如下注释中的一行语句替换接下来的三行代码
        // ObjectInputStream ois = new ObjectInputStream(fis);
        List<String> classlist = new ArrayList<String>();
        classlist.add(SafeClass.class.getName());
        SecureObjectInputStream ois = new SecureObjectInputStream(fis, classlist);

        //使用安全的SecureObjectInputStream恢复对象时会抛出exception
        long t1 = System.nanoTime();
        SafeClass objectFromDisk = (SafeClass) ois.readObject();
        long t2 = System.nanoTime();
        System.out.println(t2 - t1);
        ois.close();
    }

} 
