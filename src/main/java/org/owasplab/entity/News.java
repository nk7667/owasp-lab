package org.owasplab.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "news")
public class News {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Lob
    @Column(nullable = false)
    private String content;

    @Column(name = "is_public", nullable = false)
    private Boolean isPublic;

    @Column(name = "owner_id")
    private Long ownerId;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public News() {}

    public News(String title, String content, Boolean isPublic, Long ownerId, LocalDateTime createdAt) {
        this.title = title;
        this.content = content;
        this.isPublic = isPublic;
        this.ownerId = ownerId;
        this.createdAt = createdAt;
    }

    public Long getId() { return id; }
    public String getTitle() { return title; }
    public String getContent() { return content; }
    public Boolean getIsPublic() { return isPublic; }
    public Long getOwnerId() { return ownerId; }
    public LocalDateTime getCreatedAt() { return createdAt; }

    public void setTitle(String title) { this.title = title; }
    public void setContent(String content) { this.content = content; }
    public void setIsPublic(Boolean isPublic) { this.isPublic = isPublic; }
    public void setOwnerId(Long ownerId) { this.ownerId = ownerId; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}