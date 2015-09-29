package com.mydomain;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;

public class Servers extends AbstractVerticle{
	
	public static void main(String[] args) throws Exception {
		System.setProperty("vertx.disableFileCaching", "true");		
		 VertxOptions options = new VertxOptions().setWorkerPoolSize(10);
         Vertx vertx = Vertx.vertx(options);        
          vertx.deployVerticle("com.mydomain.RouterVerticle");
          }
	
	
}
