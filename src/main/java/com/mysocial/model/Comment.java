package com.mysocial.model;

import org.mongodb.morphia.annotations.Embedded;

@Embedded
public class Comment {
    private String userId;
    private String content;
    private String blogId;
    private String userFirst;
    private String userLast;
    private long date;

    public long getDate()
    {
        return date;
    }
    public void setDate(long date)
    {
        this.date = date;
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
    public String getUserId()
    {
        return userId;
    }
    public void setUserId(String userId)
    {
        this.userId = userId;
    }
    public String getBlogId()
    {
        return blogId;
    }
    public void setBlogId(String blogId)
    {
        this.blogId = blogId;
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

