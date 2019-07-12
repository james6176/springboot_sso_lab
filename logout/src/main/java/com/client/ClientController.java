package com.client;

import java.security.Principal;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ClientController {

	  @RequestMapping("/")
	  public String home(Principal user) {
	    return "Hello " + user.getName();
	  }
	  
}
