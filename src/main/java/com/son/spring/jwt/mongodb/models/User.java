package com.son.spring.jwt.mongodb.models;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.son.spring.jwt.mongodb.web.dto.ActivityLog;
import com.son.spring.jwt.mongodb.web.dto.FileInfo;
import com.son.spring.jwt.mongodb.web.dto.HistoryUser;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@Document(collection = "users")
public class User {
  @Id
  private String id;

  @NotBlank
  @Size(max = 20)
  private String username;

  @NotBlank
  @Size(max = 50)
  @Email
  private String email;

  @NotBlank
  @Size(max = 120)
  private String password;

  @DBRef
  private Set<Role> roles = new HashSet<>();

  private List<FileInfo> fileInfos;
  private List<ActivityLog> activityLogs;
  private List<HistoryUser> historyUsers;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;

}
