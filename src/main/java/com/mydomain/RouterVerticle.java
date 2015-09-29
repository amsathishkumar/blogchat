package com.mydomain;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.ServerWebSocket;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.Session;
import io.vertx.ext.web.handler.AuthHandler;
import io.vertx.ext.web.handler.BasicAuthHandler;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.handler.FormLoginHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.handler.StaticHandler;
import io.vertx.ext.web.handler.UserSessionHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bson.types.ObjectId;
import org.mongodb.morphia.Datastore;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Transaction;
import org.neo4j.graphdb.factory.GraphDatabaseFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mydomain.infra.ServicesFactory;
import com.mysocial.model.Blog;
import com.mysocial.model.BlogDTO;
import com.mysocial.model.Comment;
import com.mysocial.model.CommentDTO;
import com.mysocial.model.User;
import com.mysocial.model.UserDTO;

public class RouterVerticle extends AbstractVerticle {
	
	public  static HashMap<String, User> loggedInUsers = new HashMap<String, User>();
	public static  List<ServerWebSocket> allConnectedSockets = new ArrayList<>();
	
	@Override
	public void start(Future<Void> startFuture) throws Exception {
		LocalSessionStore sessionStore = LocalSessionStore.create(vertx);
		HttpServer server = vertx.createHttpServer();
		server.websocketHandler(serverWebSocket -> {
			//Got a new connection
			System.out.println("Connected: "+serverWebSocket.remoteAddress());
			//Store new connection in list
			allConnectedSockets.add(serverWebSocket);
			//Setup handler to receive the data
			serverWebSocket.handler( handler ->{
				String message = new String(handler.getBytes());
				System.out.println("message: "+message);
				//Now broadcast received message to all other clients
				for(ServerWebSocket sock : allConnectedSockets){
					System.out.println("Sending message to client...");
					Buffer buf = Buffer.buffer();
					buf.appendBytes(message.getBytes());
					sock.writeFinalTextFrame(message);
				}
			});
			//Register handler to remove connection from list when connection is closed
			serverWebSocket.closeHandler(handler->{
				allConnectedSockets.remove(serverWebSocket);
			});
			
		});
		
		Router router = Router.router(vertx);

		router.route().handler(CookieHandler.create());
		router.route().handler(
				SessionHandler.create(LocalSessionStore.create(vertx)));		
		router.route().handler(
				SessionHandler.create(sessionStore));
		
		
AuthProvider ap = new MyAuthProvier();

router.route().handler(UserSessionHandler.create(ap));

	//router.route("/Services/rest/user/auth").handler(UserAuth1.create(ap));
		
		
       router.route("/Services/rest/user/auth").handler(new UserAuth());
		router.post("/Services/rest/user/register")
				.handler(new UserPersister());
		router.post("/Services/rest/blogs/:id/comments").handler(
				new CommentPersister());
		router.post("/Services/rest/blogs").handler(new Blogpost());
		router.get("/Services/rest/blogs").handler(new Blogget());	
		router.get("/Services/rest/user").handler(new UserLoader());
		
		
		router.route("/*").handler(StaticHandler.create("webroot"));
		server.requestHandler(router::accept).listen(9091);
		System.out.println("Thread Router Start: "
				+ Thread.currentThread().getId());
		System.out.println("STARTED ROUTER");
		startFuture.complete();
	}
	
	public static void sendNewUserInfo(User u) {
		for(ServerWebSocket sock : RouterVerticle.allConnectedSockets){
			System.out.println("Sending User to client...");
			JsonObject userInfoMsg = new JsonObject();
			JsonObject userInfo = new JsonObject();
			
			userInfo.put("first", u.getFirst());
			userInfo.put("last", u.getLast());
			userInfo.put("username", u.getUserName());
			/*ObjectMapper mapper = new ObjectMapper();
			JsonNode node = mapper.valueToTree(u);*/
			userInfoMsg.put("event", "UserLogin");
			userInfoMsg.put("messageObject", userInfo);
			System.out.println("New User msg: " + userInfoMsg.toString());
			sock.writeFinalTextFrame(userInfoMsg.toString());
			
		}
		}
	
}

class MyAuthProvier implements AuthProvider {

	private String first;
	private String last;
	private ObjectId id;
	private String username;
	
	@Override
	public void authenticate(JsonObject json,
			Handler<AsyncResult<io.vertx.ext.auth.User>> handler) {
		System.out.println("Authenticating users with: " + json);
		AsyncResult<io.vertx.ext.auth.User> result = new AsyncResult<io.vertx.ext.auth.User>() {
			public boolean succeeded() {
				boolean auth = userAuthentication(json.getString("username"),json.getString("password"));
				return auth;
//				return json.getString("username").equals("admin")
//						&& json.getString("password").equals("admin123");
			}

			public io.vertx.ext.auth.User result() {
				return new io.vertx.ext.auth.User() {
					public void setAuthProvider(AuthProvider provider) {
						System.out
								.println("Setting auth provider: " + provider);
					}

					public JsonObject principal() {
						Map<String, Object> dataMap = new HashMap<>();
						dataMap.put("buffer", json.getString("username"));
						JsonObject obj = new JsonObject(dataMap);
						return obj;
					}

					public io.vertx.ext.auth.User isAuthorised(String url,
							Handler<AsyncResult<Boolean>> handler) {
						System.out.println("Is authorized call: " + url);
						return this;
					}

					public io.vertx.ext.auth.User clearCache() {
						return null;
					}
				};
			}

			public boolean failed() {
				return !(json.getString("username").equals("admin") && json
						.getString("password").equals("admin123"));
			}

			public Throwable cause() {
				return null;
			}
		};
		handler.handle(result);
	}
	
public boolean userAuthentication(String uname,String pwd) {
		
		boolean authenticated = false;
		Datastore dataStore = ServicesFactory.getMongoDB();
		List<User> users = dataStore.createQuery(User.class).field("userName")
				.equal(uname).asList();
		if (users.size() == 0) {
			System.out.println("User does not exist");
		}
		else {
			System.out.println("User from database " + users.get(0).getUserName() + 
					           "password " + users.get(0).getPassword());
			if (users.get(0).getPassword().equals(pwd)){
				System.out.println("username-->" +uname + "password-->" + pwd + "matched");
				first = users.get(0).getFirst();
				last = users.get(0).getLast();
				id = users.get(0).getId();
				username = uname;
				authenticated = true;
			}
		}
		
		
		return authenticated;
	}
}

class GraphLoader implements Handler<RoutingContext> {
	@Override
	public void handle(RoutingContext arg0) {
		GraphDatabaseFactory dbFactory = new GraphDatabaseFactory();
		File f = new File("/Users/maruthir/Documents/Training/neo4jdb");
		GraphDatabaseService db = dbFactory.newEmbeddedDatabase(f);
		try (Transaction tx = db.beginTx()) {
			// Perform DB operations
			tx.success();
		}
	}
}

class UserPersister implements Handler<RoutingContext> {
	public void handle(RoutingContext routingContext) {
		System.out.println("Thread UserPersister: "
				+ Thread.currentThread().getId());
		// This handler will be called for every request
		HttpServerResponse response = routingContext.response();
		routingContext.request().bodyHandler(new Handler<Buffer>() {
			public void handle(Buffer buf) {
				String json = buf.toString("UTF-8");
				ObjectMapper mapper = new ObjectMapper();
				UserDTO dto = null;
				try {
					dto = mapper.readValue(json, UserDTO.class);
				} catch (IOException e) {
					e.printStackTrace();
				}
				User u = dto.toModel();
				Datastore dataStore = ServicesFactory.getMongoDB();
				dataStore.save(u);
				response.setStatusCode(204).end("Data saved");
			};
		});
	}
}

class UserLoader implements Handler<RoutingContext> {
	public void handle(RoutingContext routingContext) {
		System.out.println("Thread UserLoader: "
				+ Thread.currentThread().getId());
		// This handler will be called for every request
		HttpServerResponse response = routingContext.response();
		
		MultiMap params = routingContext.request().params();

		response.putHeader("content-type", "application/json");

		if (params.size() > 0) {
			if (params.contains("current")) {
				io.vertx.ext.auth.User user = routingContext.user();
				if (user == null) {
					System.out.println("No user logged in");
					response.setStatusCode(500).end();
				} else {
					System.out.println("One user logged in");
					JsonObject json = user.principal();

					response.setStatusCode(200).end(json.toString());
				}
			} else if (params.contains("signedIn")) {
				ArrayList<User> userList = new ArrayList<User>();
				
				for(Map.Entry<String, User> m: RouterVerticle.loggedInUsers.entrySet()){  
					userList.add(m.getValue());  
				}  
				
				ObjectMapper mapper = new ObjectMapper();
				JsonNode node = mapper.valueToTree(userList);
				System.out.println("User List: " + node.toString());
				String jason = node.toString();
				response.setStatusCode(200).end(jason);
			}
		}
	}
//		String id = routingContext.request().getParam("id");
//
//		response.putHeader("content-type", "application/json");
//		Datastore dataStore = ServicesFactory.getMongoDB();
//		ObjectId oid = null;
//		try {
//			oid = new ObjectId(id);
//		} catch (Exception e) {// Ignore format errors
//		}
//		List<User> users = dataStore.createQuery(User.class).field("id")
//				.equal(oid).asList();
//		if (users.size() != 0) {
//			UserDTO dto = new UserDTO().fillFromModel(users.get(0));
//			ObjectMapper mapper = new ObjectMapper();
//			JsonNode node = mapper.valueToTree(dto);
//			response.end(node.toString());
//		} else {
//			response.setStatusCode(404).end("not found");
//		}
//	}

}

class UserAuth implements Handler<RoutingContext> {

public void handle(RoutingContext routingContext) {
System.out
.println("Thread UserAuth: " + Thread.currentThread().getId());

	HttpServerResponse response = routingContext.response();
		Session session = routingContext.session();

		routingContext.request().bodyHandler(new Handler<Buffer>() {
			public void handle(Buffer buf) {
				Datastore dataStore = ServicesFactory.getMongoDB();
				String json = buf.toString("UTF-8");
				// System.out.println(json);
				JsonObject jsonObj = new JsonObject(json);
				String user = jsonObj.getString("userName");
				String passwd = jsonObj.getString("password");
				System.out.println(user + passwd);
				List<User> users = dataStore.createQuery(User.class)
						.field("userName").equal(user).asList();
				if (users.size() != 0) {
					for (User u : users) {
						if (u.getPassword().equals(passwd)) {
							session.put("user", u.getUserName());
			
				            if (RouterVerticle.loggedInUsers.put(u.getUserName(), u) == null) {
				            	System.out.println("Send New User information to clients");
				            	RouterVerticle.sendNewUserInfo(u);
				            }
							response.setStatusCode(204).end(
									"User Authentication Success !!!");
						break;
						}
					}
				} else {
				response.setStatusCode(404).end("not found");
				}
			}
		});

	}
	
}




class UserAuth1 implements Handler<RoutingContext> {
	private AuthProvider authProvider;
	
	static UserAuth1 create(AuthProvider authProvider) {
		  return new UserAuth1(authProvider);
	  }
	  
	  public UserAuth1(AuthProvider authProvider) {
	    this.authProvider = authProvider;
	  }

	  
	public void handle(RoutingContext context) { 
		 
		HttpServerRequest req = context.request();
	    if (req.method() != HttpMethod.POST) {
	        context.fail(405); // Must be a POST
	    } 
	    req.bodyHandler(new Handler<Buffer>() {
			public void handle(Buffer buf) {
				String json = buf.toString("UTF-8");
				System.out.println("JSON= " + json);
				ObjectMapper mapper = new ObjectMapper();
				UserDTO dto = null;
				try {
					dto = mapper.readValue(json, UserDTO.class);
					System.out.println("DTO Class= " + dto);
				} catch (IOException e) {
					e.printStackTrace();
				}
				User u = dto.toModel();
		        
		        JsonObject authInfo = new JsonObject().put("username", u.getUserName()).put("password", u.getPassword());
		        authProvider.authenticate(authInfo, res -> {
		          if (res.succeeded()) {
		        	Session session = context.session();
					System.out.println("Current Session: " + (new Date()).toString() + session.id());
		           
					io.vertx.ext.auth.User user = res.result();
		            context.setUser(user);
		            
		            System.out.println(user.principal() + " Printing principle");
		            JsonObject jp = user.principal();
		            
		            u.setId((ObjectId)jp.getValue("id"));
		            u.setFirst(jp.getString("first"));
		            u.setLast(jp.getString("last"));
		            u.setUserName(jp.getString("username"));
		            
		            if (RouterVerticle.loggedInUsers.put(u.getUserName(), u) == null) {
		            	System.out.println("Send New User information to clients");
		            	RouterVerticle.sendNewUserInfo(u);
		            }
		            
		            System.out.println("Logging Success");
		            req.response().setStatusCode(204).end("user Login success");
		          } else {
		        	  System.out.println("Login Failed");
		            context.fail(403);  // Failed login
		          }
		        });
		      }
	    });
	    }
}
class Blogpost implements Handler<RoutingContext> {
	public void handle(RoutingContext routingContext) {
		System.out.println("Thread BlogPersister: "
				+ Thread.currentThread().getId());
		HttpServerResponse response = routingContext.response();
		Session session = routingContext.session();
		routingContext.request().bodyHandler(new Handler<Buffer>() {
			public void handle(Buffer buf) {
				String json = buf.toString("UTF-8");
				System.out.println("User:" + json);
				ObjectMapper mapper = new ObjectMapper();
				Datastore dataStore = ServicesFactory.getMongoDB();
				BlogDTO dto = null;
				try {
					dto = mapper.readValue(json, BlogDTO.class);
					String userName = session.get("user");
					if (userName == null || userName.equals(""))
						userName = "test";
					User user = dataStore.createQuery(User.class)
							.field("userName").equal(userName).get();
					System.out.println(user);
					dto.setUserFirst(user.getFirst());
					dto.setUserLast(user.getLast());
					dto.setUserId(user.getId().toString());
					dto.setDate(new Date().getTime());
				} catch (IOException e) {
					e.printStackTrace();
				}
				Blog blog = dto.toModel();
				dataStore.save(blog);
				response.setStatusCode(204).end("Blog saved !!");
			};
		});
	}
}

class Blogget implements Handler<RoutingContext> {
	public void handle(RoutingContext routingContext) {
		System.out
				.println("Thread BlogList: " + Thread.currentThread().getId());
		HttpServerResponse response = routingContext.response();
		response.putHeader("content-type", "application/json");
		Datastore dataStore = ServicesFactory.getMongoDB();

		// For tag search
		String tagParam = routingContext.request().query();
		List<Blog> blogs = null;
		if (tagParam != null) {
			String tagValue = tagParam.split("=")[1];
			blogs = dataStore.createQuery(Blog.class).field("tags")
					.contains(tagValue).asList();
		} else {
			blogs = dataStore.createQuery(Blog.class).asList();
		}
		if (blogs.size() != 0) {
			List<BlogDTO> obj = new ArrayList<BlogDTO>();
			for (Blog b : blogs) {
				BlogDTO dto = new BlogDTO().fillFromModel(b);
				obj.add(dto);
			}

			ObjectMapper mapper = new ObjectMapper();
			try {
				response.end(mapper.writeValueAsString(obj));
			} catch (JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			response.setStatusCode(404).end("not found");
		}
	}
}

class CheckUser implements Handler<RoutingContext> {
	public void handle(RoutingContext routingContext) {
		System.out.println("Thread BlogPersister: "
				+ Thread.currentThread().getId());
		HttpServerResponse response = routingContext.response();
		Session session = routingContext.session();
		routingContext.request().bodyHandler(new Handler<Buffer>() {
			public void handle(Buffer buf) {
				String json = buf.toString("UTF-8");
				System.out.println("User:" + json);
				ObjectMapper mapper = new ObjectMapper();
				Datastore dataStore = ServicesFactory.getMongoDB();
				BlogDTO dto = null;
				try {
					dto = mapper.readValue(json, BlogDTO.class);
					String userName = session.get("user");
					if (userName == null || userName.equals(""))
						userName = "test";
					User user = dataStore.createQuery(User.class)
							.field("userName").equal(userName).get();
					dto.setUserFirst(user.getFirst());
					dto.setUserLast(user.getLast());
					dto.setUserId(user.getId().toString());
					dto.setDate(new Date().getTime());
					} catch (IOException e) {
					e.printStackTrace();
				}
//				Blog blog = dto.toModel();
//				dataStore.save(blog);
//				response.setStatusCode(204).end("Blog saved !!");
			};
		});
	}
}

class CommentPersister implements Handler<RoutingContext> {
	public void handle(RoutingContext routingContext) {
		System.out.println("Thread CommentPersister: "
				+ Thread.currentThread().getId());
		HttpServerResponse response = routingContext.response();
		String blogId = routingContext.request().getParam("id");
		Session session = routingContext.session();
		response.putHeader("content-type", "application/json");
		routingContext.request().bodyHandler(new Handler<Buffer>() {
			public void handle(Buffer buf) {
				String json = buf.toString("UTF-8");
				ObjectMapper mapper = new ObjectMapper();
				Datastore dataStore = ServicesFactory.getMongoDB();
				CommentDTO dto = null;
				try {
					dto = mapper.readValue(json, CommentDTO.class);
					String userName = session.get("user");
					if (userName == null || userName.equals(""))
						userName = "test";
					User user = dataStore.createQuery(User.class)
							.field("userName").equal(userName).get();
					dto.setUserFirst(user.getFirst());
					dto.setUserLast(user.getLast());
					dto.setUserId(user.getId().toString());
					dto.setDate(new Date().getTime());
				} catch (IOException e) {
					e.printStackTrace();
				}
				Comment comment = dto.toModel();

				ObjectId oid = null;
				try {
					oid = new ObjectId(blogId);
				} catch (Exception e) {// Ignore format errors
				}
				Blog blog = dataStore.createQuery(Blog.class).field("id")
						.equal(oid).get();
				List<Comment> comments = blog.getComments();
				comments.add(comment);
				blog.setComments(comments);
				dataStore.save(blog);

				/*
				 * List<Blog> blogs = user.getUserBlogs(); blogs.add(blog);
				 * user.setUserBlogs(blogs); dataStore.save(user);
				 */
				response.setStatusCode(204).end("Comment saved !!");
			};
		});
	}
	
}
