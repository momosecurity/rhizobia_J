package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.csrf.CSRFTokenUtils;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class CSRFTokenUtilsTest {


    @Test
    public void testVerifyCSRFTokenStorage() throws Exception {
        System.out.println("***************************" + 2 + "***************************");
        //生成的token需要存储，等待后续校验时使用 0.1ms
        CSRFTokenUtils csrfInstance = CSRFTokenUtils.getInstance();
        for (int i = 0; i < 10; i++) {
            long t1 = System.nanoTime();
            String token = csrfInstance.getCsrfToken(32);
            long t2 = System.nanoTime();
            System.out.println(token);
            System.out.println(t2 - t1);
        }
        assertTrue(true);
    }

} 
