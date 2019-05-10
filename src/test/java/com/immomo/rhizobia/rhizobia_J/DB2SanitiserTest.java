package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.sqli.DB2Sanitiser;
import org.junit.Test;

public class DB2SanitiserTest {

    @Test
    public void DB2Sanitise() {
        //确认是连接的是哪种数据库 6ms
        DB2Sanitiser db2Tool = DB2Sanitiser.getInstance();
        //对sql语句进行特殊字符转义
        String id = "1' or '1'='1' #";
        long t1 = System.nanoTime();
        String idEncode = db2Tool.DB2Sanitise(id);
        long t2 = System.nanoTime();
        System.out.println("without column: ");
        System.out.println(t2 - t1);
        String query = "SELECT NAME FROM users WHERE id = '" + idEncode + "'";
        System.out.println(query);
        query = "SELECT NAME FROM users WHERE id = '" + id + "'";
        System.out.println(query);

        String name = "name";
        String nameEncode = db2Tool.DB2Sanitise(name);
        query = "SELECT NAME FROM users order by " + nameEncode;
        System.out.println(query);
        query = "SELECT NAME FROM users order by " + name;
        System.out.println(query);

        name = "user_name";
        nameEncode = db2Tool.DB2Sanitise(name);
        query = "SELECT NAME FROM users order by " + nameEncode;
        System.out.println(query);
        query = "SELECT NAME FROM users order by " + name;
        System.out.println(query);

        name = "user-name";
        nameEncode = db2Tool.DB2Sanitise(name);
        query = "SELECT NAME FROM users order by " + nameEncode;
        System.out.println(query);
        query = "SELECT NAME FROM users order by " + name;
        System.out.println(query);

        name = "user$name";
        nameEncode = db2Tool.DB2Sanitise(name);
        query = "SELECT NAME FROM users order by " + nameEncode;
        System.out.println(query);
        query = "SELECT NAME FROM users order by " + name;
        System.out.println(query);

        System.out.println("\nwith column sign: ");

        name = "name";
        nameEncode = db2Tool.DB2Sanitise(name, true);
        query = "SELECT NAME FROM users order by " + nameEncode;
        System.out.println(query);
        query = "SELECT NAME FROM users order by " + name;
        System.out.println(query);

        name = "user_name";
        nameEncode = db2Tool.DB2Sanitise(name, true);
        query = "SELECT NAME FROM users order by " + nameEncode;
        System.out.println(query);
        query = "SELECT NAME FROM users order by " + name;
        System.out.println(query);

        name = "user-name";
        nameEncode = db2Tool.DB2Sanitise(name, true);
        query = "SELECT NAME FROM users order by " + nameEncode;
        System.out.println(query);
        query = "SELECT NAME FROM users order by " + name;
        System.out.println(query);

        name = "user$name";
        nameEncode = db2Tool.DB2Sanitise(name, true);
        query = "SELECT NAME FROM users order by " + nameEncode;
        System.out.println(query);
        query = "SELECT NAME FROM users order by " + name;
        System.out.println(query);

        name = "1%0A%0Dand%0A%0D1=1";
        nameEncode = db2Tool.DB2Sanitise( name, true);
        System.out.println(nameEncode);
    }
}