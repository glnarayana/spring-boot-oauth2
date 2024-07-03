package com.assignment.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Lakshminarayana Golla
 * Created on 03-07-2024
 **/
@RequestMapping("/test")
@RestController
public class TestController {

    @GetMapping("/secured")
    public String test() {
        return "Successfully got response";
    }

}
