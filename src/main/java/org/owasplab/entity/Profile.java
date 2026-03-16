package org.owasplab.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "profiles")
public class Profile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String nickname;

    @Lob
    @Column(nullable = false)
    private String bio;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public Profile() {}

    public Profile(String nickname, String bio, LocalDateTime createdAt) {
        this.nickname = nickname;
        this.bio = bio;
        this.createdAt = createdAt;
    }

    public Long getId() { return id; }
    public String getNickname() { return nickname; }
    public String getBio() { return bio; }
    public LocalDateTime getCreatedAt() { return createdAt; }

    public void setNickname(String nickname) { this.nickname = nickname; }
    public void setBio(String bio) { this.bio = bio; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}

