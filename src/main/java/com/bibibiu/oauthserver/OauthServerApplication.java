package com.bibibiu.oauthserver;

import ke.co.dynamodigital.commons.annotations.EnablePawaCommons;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnablePawaCommons
@SpringBootApplication
public class OauthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(OauthServerApplication.class, args);
    }

}
