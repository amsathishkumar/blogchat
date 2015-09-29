package com.mysocial.model;

import java.io.Serializable;

public class CommentDTO implements Serializable{
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

    public Comment toModel()
    {
        Comment comment = new Comment();
        comment.setUserId(userId);
        comment.setContent(content);
        comment.setBlogId(blogId);
        comment.setUserFirst(userFirst);
        comment.setUserLast(userLast);
        comment.setDate(date);
        return comment;
    }

    @Override
    public String toString()
    {
        return "CommentDTO [userId=" + userId + ", content=" + content
                        + ", blogId=" + blogId + ", userFirst=" + userFirst
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

    public String getContent()
    {
        return content;
    }

    public void setContent(String content)
    {
        this.content = content;
    }

    public String getBlogId()
    {
        return blogId;
    }

    public void setBlogId(String blogId)
    {
        this.blogId = blogId;
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

    public CommentDTO fillFromModel(Comment com)
    {
        userId = com.getUserId();
        content = com.getContent();
        userFirst = com.getUserFirst();
        userLast = com.getUserLast();
        blogId = com.getBlogId();
        date = com.getDate();
        return this;
    }
    
}

