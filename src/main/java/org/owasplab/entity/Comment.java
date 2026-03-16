package org.owasplab.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "comments")
public class Comment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String author;

    @Lob
    @Column(nullable = false)
    private String content;

    @Column(name = "website")
    private String website;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public Comment() {}

    public Comment(String author, String content, String website, LocalDateTime createdAt) {
        this.author = author;
        this.content = content;
        this.website = website;
        this.createdAt = createdAt;
    }

    public Long getId() { return id; }
    public String getAuthor() { return author; }
    public String getContent() { return content; }
    public String getWebsite() { return website; }
    public LocalDateTime getCreatedAt() { return createdAt; }

    public void setAuthor(String author) { this.author = author; }
    public void setContent(String content) { this.content = content; }
    public void setWebsite(String website) { this.website = website; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}

