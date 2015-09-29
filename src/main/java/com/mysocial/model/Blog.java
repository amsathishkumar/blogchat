package com.mysocial.model;


import java.util.ArrayList;
import java.util.List;

import org.bson.types.ObjectId;
import org.mongodb.morphia.annotations.Entity;
import org.mongodb.morphia.annotations.Field;
import org.mongodb.morphia.annotations.Id;
import org.mongodb.morphia.annotations.Index;
import org.mongodb.morphia.annotations.Indexes;

@Entity("blogs")
@Indexes(
    @Index(value = "title", fields = @Field("title"))
)
public class Blog {
    @Id
    private ObjectId id;
    private String tags;
    private String content;
    private String title;
    private List<Comment> comments;
    private String userId;
    private String userFirst;
    private String userLast;
    private long date;
    
    @Override
    public String toString()
    {
        return "Blog [id=" + id + ", tags=" + tags + ", content=" + content
                        + ", title=" + title + ", comments=" + comments
                        + ", userId=" + userId + ", userFirst=" + userFirst
                        + ", userLast=" + userLast + ", date=" + date + "]";
    }
    public String getUserId()
    {
        return userId;
    }
    public void setUserId(String userId)
    {
        this.userId = userId;
    }
    public String getUserFirst()
    {
        return userFirst;
    }
    public void setUserFirst(String userFirst)
    {
        this.userFirst = userFirst;
    }
    public String getUserLast()
    {
        return userLast;
    }
    public void setUserLast(String userLast)
    {
        this.userLast = userLast;
    }
    public long getDate()
    {
        return date;
    }
    public void setDate(long date)
    {
        this.date = date;
    }

    public List<Comment> getComments()
    {
        if(comments==null)
            comments = new ArrayList<Comment>();
        return comments;
    }
    public void setComments(List<Comment> userComments)
    {
        this.comments = userComments;
    }
    
    
    public ObjectId getId()
    {
        return id;
    }
    public void setId(ObjectId id)
    {
        this.id = id;
    }
    public String getTitle()
    {
        return title;
    }
    public void setTitle(String title)
    {
        this.title = title;
    }
    public String getTags()
    {
        return tags;
    }
    public void setTags(String tags)
    {
        this.tags = tags;
    }
    public String getContent()
    {
        return content;
    }
    public void setContent(String content)
    {
        this.content = content;
    }  
}
