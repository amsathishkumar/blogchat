package com.mysocial.model;

import java.io.Serializable;
import java.util.List;

import org.bson.types.ObjectId;

public class BlogDTO implements Serializable{
    private String id;
    private String tags;
    private String content;
    private String title;
    private List<Comment> comments;
    private String userId;
    private String userFirst;
    private String userLast;
    private long date;
    
    
    public Blog toModel()
    {
        Blog blog = new Blog();
        if(id!=null)
            blog.setId(new ObjectId(id));
        blog.setTags(tags);
        blog.setContent(content);
        blog.setTitle(title);
        blog.setUserId(userId);
        blog.setUserFirst(userFirst);
        blog.setUserLast(userLast);
        blog.setDate(date);
        blog.setComments(comments);
        return blog;
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

    public String getTitle()
    {
        return title;
    }

    public void setTitle(String title)
    {
        this.title = title;
    }

    public BlogDTO fillFromModel(Blog blog)
    {
        id = blog.getId() != null ? blog.getId().toHexString() : null;
        tags = blog.getTags();
        content = blog.getContent();
        title = blog.getTitle();
        userId = blog.getUserId();
        userFirst = blog.getUserFirst();
        userLast = blog.getUserLast();
        date = blog.getDate();
        comments = blog.getComments();
        return this;
    }
    
    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public List<Comment> getComments()
    {
        return comments;
    }

    public void setComments(List<Comment> comments)
    {
        this.comments = comments;
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

    @Override
    public String toString()
    {
        return "BlogDTO [id=" + id + ", tags=" + tags + ", content=" + content
                        + ", title=" + title + ", userComments=" + comments
                        + ", userId=" + userId + ", userFirst=" + userFirst
                        + ", userLast=" + userLast + ", date=" + date + "]";
    }
    
}

