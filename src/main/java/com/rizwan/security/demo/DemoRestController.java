package com.rizwan.security.demo;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/demo")
public class DemoRestController {
    @GetMapping
    public ResponseEntity<String> sayHello()
    {
        return ResponseEntity.ok( "Hello From Secured End Point!!!" );
    }
}
