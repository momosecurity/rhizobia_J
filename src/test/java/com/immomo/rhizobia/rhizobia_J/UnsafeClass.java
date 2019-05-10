package com.immomo.rhizobia.rhizobia_J;

import java.io.IOException;
import java.io.Serializable;

public class UnsafeClass implements Serializable {
    public String name;

    //重写readObject()方法
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        //执行默认的readObject()方法
        in.defaultReadObject();
        //执行命令
        Runtime.getRuntime().exec("open /Applications/Calculator.app/Contents/MacOS/Calculator");
    }
}
